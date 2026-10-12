
const express = require("express");
const { Pool } = require("pg");
const { createClient } = require("@supabase/supabase-js");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

dotenv.config();

const app = express();

// Allow JSON body requests and requests from the frontend
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || true,
}));

// Connect to the Supabase PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Connect to Supabase Auth
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Test the database connection
pool.query("SELECT NOW()", (error) => {
  if (error) {
    console.error("Database connection failed:", error.message);
  } else {
    console.log("Database connected");
  }
});

// API documentation
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check
app.get("/health", (req, res) => {
  res.json({ message: "Mind Off Run Club API is running" });
});

// Start server
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Mind Off Run Club API running on port ${PORT}`);
});

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email and password are required",
      });
    }

    // Create the account using Supabase Auth
    const { data, error } = await supabase.auth.signUp({
      email: email.trim(),
      password,
    });

    if (error) {
      console.error("Supabase signup error:", error);

      return res.status(400).json({
        error: error.message,
        code: error.code,
        status: error.status,
      });
    }

    // Stop if Supabase did not return a user
    if (!data.user) {
      return res.status(400).json({
        error: "Unable to create your account",
      });
    }

    // Create the user's profile in the profiles table
    const result = await pool.query(
      `
            INSERT INTO public.mindoff_profiles
                (id, username, email)
            VALUES ($1, $2, $3)
            ON CONFLICT (id)
            DO UPDATE SET email = EXCLUDED.email
            RETURNING id, username, email, bio, avatar_url, created_at;
            `,
      [data.user.id, username.trim(), email.trim()]
    );

    res.status(201).json({
      message: data.session
        ? "Account created successfully"
        : "Account created. Please confirm your email before logging in.",
      user: result.rows[0],
      access_token: data.session?.access_token || null,
      needsEmailConfirmation: !data.session,
    });
  } catch (error) {
    console.error("Signup error:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username already exists",
      });
    }

    res.status(500).json({
      error: "Failed to create account",
    });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    // Verify the email and password using Supabase Auth
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password,
    });

    if (error) {
      console.error("Supabase login error:", error.message);

      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Get the user's profile from the profiles table
    const result = await pool.query(
      `
            SELECT id, username, email, bio, avatar_url, created_at
            FROM public.mindoff_profiles
            WHERE id = $1;
            `,
      [data.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User profile not found",
      });
    }

    res.json({
      message: "Login successful",
      access_token: data.session.access_token,
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Failed to login",
    });
  }
});

// Authentication middleware
// Verify the Supabase access token
async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Authentication token is required",
    });
  }

  // Get the token from "Bearer TOKEN"
  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Invalid authentication token",
    });
  }

  try {
    // Ask Supabase Auth to verify the token
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        error: "Invalid or expired authentication token",
      });
    }

    // Store the authenticated user's ID in the request
    req.user = {
      id: data.user.id,
      email: data.user.email,
    };

    next();
  } catch (error) {
    console.error("Token verification error:", error.message);

    res.status(401).json({
      error: "Unable to verify authentication token",
    });
  }
}

// Get the logged-in user's profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
            SELECT id, username, email, bio, avatar_url, created_at
            FROM public.mindoff_profiles
            WHERE id = $1;
            `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Profile not found",
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Get profile error:", error);

    res.status(500).json({
      error: "Failed to get profile",
    });
  }
});

// Update the logged-in user's profile
app.put("/profile", authenticateToken, async (req, res) => {
  try {
    const { username, bio, avatar_url } = req.body;

    if (!username || !username.trim()) {
      return res.status(400).json({
        error: "Username is required",
      });
    }

    const result = await pool.query(
      `
            UPDATE public.mindoff_profiles
            SET username = $1,
                bio = $2,
                avatar_url = $3
            WHERE id = $4
            RETURNING id, username, email, bio, avatar_url, created_at;
            `,
      [
        username.trim(),
        bio ?? "",
        avatar_url ?? null,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Profile not found",
      });
    }

    res.json({
      message: "Profile updated successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Update profile error:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username already exists",
      });
    }

    res.status(500).json({
      error: "Failed to update profile",
    });
  }
});

// Get users except the logged-in user
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
            SELECT
                p.id,
                p.username,
                p.email,
                p.bio,
                p.avatar_url,
                p.created_at,
                f.id AS friendship_id,
                f.status AS friendship_status,
                CASE
                    WHEN f.requester_id = $1 THEN 'outgoing'
                    WHEN f.receiver_id = $1 THEN 'incoming'
                    ELSE NULL
                END AS friendship_direction
            FROM public.mindoff_profiles p
            LEFT JOIN public.mindoff_friendships f
                ON (
                    f.requester_id = $1
                    AND f.receiver_id = p.id
                )
                OR (
                    f.requester_id = p.id
                    AND f.receiver_id = $1
                )
            WHERE p.id <> $1
            ORDER BY p.username;
            `,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get users error:", error);

    res.status(500).json({
      error: "Failed to get users",
    });
  }
});

// Send a friend request
app.post("/friends", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { friend_id } = req.body;

    if (!friend_id) {
      return res.status(400).json({
        error: "Friend ID is required",
      });
    }

    // Prevent users from sending requests to themselves
    if (userId === friend_id) {
      return res.status(400).json({
        error: "You cannot add yourself as a friend",
      });
    }

    // Check whether the selected profile exists
    const friendResult = await pool.query(
      `
            SELECT id
            FROM public.mindoff_profiles
            WHERE id = $1;
            `,
      [friend_id]
    );

    if (friendResult.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    // Check whether a request already exists in either direction
    const existingResult = await pool.query(
      `
            SELECT id, status
            FROM public.mindoff_friendships
            WHERE (requester_id = $1 AND receiver_id = $2)
               OR (requester_id = $2 AND receiver_id = $1);
            `,
      [userId, friend_id]
    );

    if (existingResult.rows.length > 0) {
      return res.status(409).json({
        error: "A friend request or friendship already exists",
      });
    }

    // Create a new pending friend request
    const result = await pool.query(
      `
            INSERT INTO public.mindoff_friendships
                (requester_id, receiver_id, status)
            VALUES ($1, $2, 'pending')
            RETURNING *;
            `,
      [userId, friend_id]
    );

    res.status(201).json({
      message: "Friend request sent",
      friendship: result.rows[0],
    });
  } catch (error) {
    console.error("Send friend request error:", error);

    res.status(500).json({
      error: "Failed to send friend request",
    });
  }
});

// Get the logged-in user's friend requests and friendships
app.get("/friends", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
            SELECT
                f.id AS friendship_id,
                f.requester_id,
                f.receiver_id,
                f.status,
                f.created_at,
                requester.username AS requester_username,
                receiver.username AS receiver_username,
                CASE
                    WHEN f.requester_id = $1 THEN 'outgoing'
                    ELSE 'incoming'
                END AS friendship_direction
            FROM public.mindoff_friendships f
            JOIN public.mindoff_profiles requester
                ON requester.id = f.requester_id
            JOIN public.mindoff_profiles receiver
                ON receiver.id = f.receiver_id
            WHERE f.requester_id = $1
               OR f.receiver_id = $1
            ORDER BY f.created_at DESC;
            `,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get friendships error:", error);

    res.status(500).json({
      error: "Failed to get friendships",
    });
  }
});

// Accept a friend request
app.put("/friends/:id", authenticateToken, async (req, res) => {
  try {
    const friendshipId = req.params.id;
    const userId = req.user.id;

    // Only the receiver can accept a pending request
    const result = await pool.query(
      `
            UPDATE public.mindoff_friendships
            SET status = 'accepted'
            WHERE id = $1
              AND receiver_id = $2
              AND status = 'pending'
            RETURNING *;
            `,
      [friendshipId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Pending friend request not found",
      });
    }

    res.json({
      message: "Friend request accepted",
      friendship: result.rows[0],
    });
  } catch (error) {
    console.error("Accept friend request error:", error);

    res.status(500).json({
      error: "Failed to accept friend request",
    });
  }
});

// Create a post
app.post("/posts", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, content, image_url, visibility } = req.body;

    if (!content || !visibility) {
      return res.status(400).json({
        error: "Content and visibility are required",
      });
    }

    if (!["public", "friends"].includes(visibility)) {
      return res.status(400).json({
        error: "Visibility must be public or friends",
      });
    }

    const result = await pool.query(
      `
            INSERT INTO public.mindoff_posts
                (user_id, title, content, image_url, visibility)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *;
            `,
      [
        userId,
        title ?? "",
        content,
        image_url ?? null,
        visibility,
      ]
    );

    res.status(201).json({
      message: "Post created successfully",
      post: result.rows[0],
    });
  } catch (error) {
    console.error("Create post error:", error);

    res.status(500).json({
      error: "Failed to create post",
    });
  }
});

// Get public posts, own posts, and accepted friends' posts
app.get("/posts", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
            SELECT
                p.id,
                p.user_id,
                p.title,
                p.content,
                p.image_url,
                p.visibility,
                p.created_at,
                profile.username,
                profile.avatar_url
            FROM public.mindoff_posts p
            JOIN public.mindoff_profiles profile
                ON profile.id = p.user_id
            WHERE
                p.visibility = 'public'
                OR p.user_id = $1
                OR (
                    p.visibility = 'friends'
                    AND EXISTS (
                        SELECT 1
                        FROM public.mindoff_friendships f
                        WHERE f.status = 'accepted'
                          AND (
                              (
                                  f.requester_id = $1
                                  AND f.receiver_id = p.user_id
                              )
                              OR (
                                  f.requester_id = p.user_id
                                  AND f.receiver_id = $1
                              )
                          )
                    )
                )
            ORDER BY p.created_at DESC;
            `,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get posts error:", error);

    res.status(500).json({
      error: "Failed to get posts",
    });
  }
});

// Handle unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
  });
});

// Handle unexpected errors
app.use((error, req, res, next) => {
  console.error("Unexpected API error:", error);

  res.status(500).json({
    error: "Internal server error",
  });
});