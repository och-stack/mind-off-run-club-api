require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 4000;

// Connect the React frontend to this API.
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
}));

app.use(express.json());

// Connect to the Supabase PostgreSQL database.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Supabase client for signup, login, and token verification.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

// Check required environment variables before starting.
const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_ANON_KEY",
  "DATABASE_URL",
];

for (const name of requiredEnv) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

// Verify the Supabase access token sent by the logged-in user.
async function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication token is required",
    });
  }

  const token = authorization.split(" ")[1];

  try {
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        error: "Invalid or expired token",
      });
    }

    // Use the Supabase Auth UUID to identify this user.
    req.user = {
      id: data.user.id,
      email: data.user.email,
    };

    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);

    return res.status(401).json({
      error: "Unable to verify token",
    });
  }
}

// Basic API and database health checks.
app.get("/", (req, res) => {
  res.send("Mind Off Run Club API is running!");
});

app.get("/health", async (req, res) => {
  try {
    const result = await pool.query(`
            SELECT
                (SELECT COUNT(*) FROM public.mindoff_profiles) AS profiles,
                (SELECT COUNT(*) FROM public.mindoff_posts) AS posts,
                (SELECT COUNT(*) FROM public.mindoff_friendships) AS friendships
        `);

    res.json({
      message: "Database connected",
      counts: result.rows[0],
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(500).json({
      error: "Database connection failed",
    });
  }
});

// Create a Supabase Auth account.
// The database trigger creates the matching profile.
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (
      !username || !email || !password
    ) {
      return res.status(400).json({
        error: "Username, email, and a password of at least 8 characters are required",
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email: email.trim(),
      password,
      options: {
        data: {
          username: username.trim(),
        },
      },
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.status(201).json({
      message: data.session
        ? "Account created successfully"
        : "Account created. Check your email if confirmation is required.",
      user: data.user
        ? {
          id: data.user.id,
          email: data.user.email,
        }
        : null,
      access_token: data.session?.access_token || null,
    });
  } catch (error) {
    console.error("Signup failed:", error.message);

    res.status(500).json({ error: "Unable to create account" });
  }
});

// Log in and receive a Supabase access token.
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const { data, error } =
      await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

    if (error || !data.session) {
      return res.status(401).json({
        error: "Invalid email or password, or email confirmation is required",
      });
    }

    res.json({
      message: "Login successful",
      access_token: data.session.access_token,
      user: {
        id: data.user.id,
        email: data.user.email,
      },
    });
  } catch (error) {
    console.error("Login failed:", error.message);

    res.status(500).json({ error: "Unable to log in" });
  }
});

// Get the logged-in user's profile.
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, bio, avatar_url, created_at
             FROM public.mindoff_profiles
             WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Profile not found",
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Profile lookup failed:", error.message);

    res.status(500).json({ error: "Unable to load profile" });
  }
});

// Update the logged-in user's profile.
app.put("/profile", authenticateToken, async (req, res) => {
  try {
    const { username, bio, avatar_url } = req.body;

    if (
      username !== undefined &&
      (typeof username !== "string" || !username.trim())
    ) {
      return res.status(400).json({
        error: "Username must not be empty",
      });
    }

    if (bio !== undefined && typeof bio !== "string") {
      return res.status(400).json({
        error: "Bio must be text",
      });
    }

    if (
      avatar_url !== undefined &&
      avatar_url !== null &&
      typeof avatar_url !== "string"
    ) {
      return res.status(400).json({
        error: "Avatar URL must be text or null",
      });
    }

    const result = await pool.query(
      `UPDATE public.mindoff_profiles
             SET username = COALESCE($1, username),
                 bio = COALESCE($2, bio),
                 avatar_url = COALESCE($3, avatar_url)
             WHERE id = $4
             RETURNING id, username, email, bio, avatar_url, created_at`,
      [
        username === undefined ? null : username.trim(),
        bio === undefined ? null : bio,
        avatar_url === undefined ? null : avatar_url,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Profile not found",
      });
    }

    res.json({
      message: "Profile updated",
      profile: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "That username is already taken",
      });
    }

    console.error("Profile update failed:", error.message);

    res.status(500).json({ error: "Unable to update profile" });
  }
});

// List other users and their relationship with the logged-in user.
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
                p.id,
                p.username,
                p.bio,
                p.avatar_url,
                f.id AS friendship_id,
                f.status AS friendship_status,
                CASE
                    WHEN f.requester_id = $1 THEN 'outgoing'
                    WHEN f.receiver_id = $1 THEN 'incoming'
                    ELSE NULL
                END AS request_direction
             FROM public.mindoff_profiles p
             LEFT JOIN public.mindoff_friendships f
                ON (
                    (f.requester_id = $1 AND f.receiver_id = p.id)
                    OR
                    (f.requester_id = p.id AND f.receiver_id = $1)
                )
             WHERE p.id <> $1
             ORDER BY p.username`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("User list failed:", error.message);

    res.status(500).json({ error: "Unable to load users" });
  }
});

// Send a friend request.
app.post("/friends", authenticateToken, async (req, res) => {
  try {
    const { friend_id } = req.body;

    if (
      typeof friend_id !== "string" ||
      friend_id === req.user.id
    ) {
      return res.status(400).json({
        error: "A valid, different user's UUID is required",
      });
    }

    const target = await pool.query(
      `SELECT id FROM public.mindoff_profiles WHERE id = $1`,
      [friend_id]
    );

    if (target.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    const existing = await pool.query(
      `SELECT id, status
             FROM public.mindoff_friendships
             WHERE (requester_id = $1 AND receiver_id = $2)
                OR (requester_id = $2 AND receiver_id = $1)`,
      [req.user.id, friend_id]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "A friend request or friendship already exists",
        friendship: existing.rows[0],
      });
    }

    const result = await pool.query(
      `INSERT INTO public.mindoff_friendships
                (requester_id, receiver_id, status)
             VALUES ($1, $2, 'pending')
             RETURNING *`,
      [req.user.id, friend_id]
    );

    res.status(201).json({
      message: "Friend request sent",
      friendship: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "A friend request or friendship already exists",
      });
    }

    console.error("Friend request failed:", error.message);

    res.status(500).json({
      error: "Unable to send friend request",
    });
  }
});

// List incoming requests and accepted friendships.
app.get("/friends", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
                f.id AS friendship_id,
                f.status,
                f.requester_id,
                f.receiver_id,
                f.created_at,
                p.id AS user_id,
                p.username,
                p.bio,
                p.avatar_url,
                CASE
                    WHEN f.requester_id = $1 THEN 'outgoing'
                    ELSE 'incoming'
                END AS request_direction
             FROM public.mindoff_friendships f
             JOIN public.mindoff_profiles p
                ON p.id = CASE
                    WHEN f.requester_id = $1 THEN f.receiver_id
                    ELSE f.requester_id
                END
             WHERE (f.requester_id = $1 OR f.receiver_id = $1)
             ORDER BY f.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Friend list failed:", error.message);

    res.status(500).json({ error: "Unable to load friends" });
  }
});

// Accept an incoming pending friend request.
app.put("/friends/:id", authenticateToken, async (req, res) => {
  try {
    const friendshipId = Number(req.params.id);

    if (!Number.isSafeInteger(friendshipId) || friendshipId <= 0) {
      return res.status(400).json({
        error: "Invalid friend request ID",
      });
    }

    const result = await pool.query(
      `UPDATE public.mindoff_friendships
             SET status = 'accepted', updated_at = NOW()
             WHERE id = $1
               AND receiver_id = $2
               AND status = 'pending'
             RETURNING *`,
      [friendshipId, req.user.id]
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
    console.error("Accept request failed:", error.message);

    res.status(500).json({
      error: "Unable to accept friend request",
    });
  }
});

// Create a running post.
app.post("/posts", authenticateToken, async (req, res) => {
  try {
    const { title, content, image_url, visibility = "public" } = req.body;

    if (
      typeof title !== "string" ||
      typeof content !== "string" ||
      !title.trim() ||
      !content.trim()
    ) {
      return res.status(400).json({
        error: "Title and content are required",
      });
    }

    if (!["public", "friends"].includes(visibility)) {
      return res.status(400).json({
        error: "Visibility must be public or friends",
      });
    }

    if (
      image_url !== undefined &&
      image_url !== null &&
      typeof image_url !== "string"
    ) {
      return res.status(400).json({
        error: "Image URL must be text or null",
      });
    }

    const result = await pool.query(
      `INSERT INTO public.mindoff_posts
                (user_id, title, content, image_url, visibility)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
      [
        req.user.id,
        title.trim(),
        content.trim(),
        image_url || null,
        visibility,
      ]
    );

    res.status(201).json({
      message: "Post created",
      post: result.rows[0],
    });
  } catch (error) {
    console.error("Post creation failed:", error.message);

    res.status(500).json({ error: "Unable to create post" });
  }
});

// Get public posts, your own posts, and accepted friends' friends-only posts.
app.get("/posts", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
                p.id,
                p.user_id,
                p.title,
                p.content,
                p.image_url,
                p.visibility,
                p.created_at,
                u.username,
                u.avatar_url
             FROM public.mindoff_posts p
             JOIN public.mindoff_profiles u ON u.id = p.user_id
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
                            (f.requester_id = $1 AND f.receiver_id = p.user_id)
                            OR
                            (f.requester_id = p.user_id AND f.receiver_id = $1)
                          )
                    )
                )
             ORDER BY p.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Feed lookup failed:", error.message);

    res.status(500).json({ error: "Unable to load posts" });
  }
});

// Handle unknown API routes.
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Handle unexpected errors without returning private details.
app.use((error, req, res, next) => {
  console.error("Unexpected API error:", error.message);

  res.status(500).json({ error: "Internal server error" });
});

const server = app.listen(PORT, () => {
  console.log(`Mind Off Run Club API running on port ${PORT}`);
});

// Close database connections cleanly when stopping the server.
async function shutdown() {
  server.close();
  await pool.end();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);