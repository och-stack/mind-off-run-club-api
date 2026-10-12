
const express = require("express");
const { Pool } = require("pg");
const { createClient } = require("@supabase/supabase-js");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const { randomUUID } = require("crypto");

dotenv.config();

const app = express();

// Allow JSON requests and requests from the frontend.
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || true,
}));

// Connect to the Supabase PostgreSQL database.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Supabase Auth client.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Server-only Storage client.
// Never expose the service role key in the frontend.
const supabaseStorage = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Receive image files in memory before uploading them to Storage.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (req, file, callback) => {
    if (!file.mimetype.startsWith("image/")) {
      return callback(new Error("Only image files are allowed."));
    }

    callback(null, true);
  },
});

// Test the database connection.
pool.query("SELECT NOW()", (error) => {
  if (error) {
    console.error("Database connection failed:", error.message);
  } else {
    console.log("Database connected");
  }
});

// API documentation.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check.
app.get("/health", (req, res) => {
  res.json({
    message: "Mind Off Run Club API is running",
  });
});

// Signup.
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email and password are required",
      });
    }

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

    if (!data.user) {
      return res.status(400).json({
        error: "Unable to create your account",
      });
    }

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

// Login.
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const { data, error } =
      await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

    if (error) {
      console.error("Supabase login error:", error.message);

      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

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

// Verify the Supabase access token.
async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Authentication token is required",
    });
  }

  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: "Invalid authentication token",
    });
  }

  try {
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        error: "Invalid or expired authentication token",
      });
    }

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

// Get the logged-in user's profile.
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

// Update the logged-in user's profile.
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

// Get users except the logged-in user.
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

// Send a friend request.
app.post("/friends", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { friend_id } = req.body;

    if (!friend_id) {
      return res.status(400).json({
        error: "Friend ID is required",
      });
    }

    if (userId === friend_id) {
      return res.status(400).json({
        error: "You cannot add yourself as a friend",
      });
    }

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

// Get the logged-in user's friend requests and friendships.
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

// Accept a friend request.
app.put("/friends/:id", authenticateToken, async (req, res) => {
  try {
    const friendshipId = req.params.id;
    const userId = req.user.id;

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

// Create a post with an optional image file.
app.post(
  "/posts",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    let imagePath = null;
    let postCreated = false;

    try {
      const userId = req.user.id;
      const { title, content, visibility } = req.body;

      if (!content || !content.trim()) {
        return res.status(400).json({
          error: "Content is required",
        });
      }

      if (!["public", "friends"].includes(visibility)) {
        return res.status(400).json({
          error: "Visibility must be public or friends",
        });
      }

      // Upload the selected file to Supabase Storage.
      if (req.file) {
        const extension = req.file.mimetype
          .split("/")[1]
          .replace(/[^a-zA-Z0-9]/g, "");

        const fileName = `${randomUUID()}.${extension}`;
        imagePath = `${userId}/${fileName}`;

        const { error: uploadError } =
          await supabaseStorage.storage
            .from("post-images")
            .upload(imagePath, req.file.buffer, {
              contentType: req.file.mimetype,
              upsert: false,
            });

        if (uploadError) {
          throw uploadError;
        }
      }

      // Save the storage path with the post.
      const result = await pool.query(
        `
                INSERT INTO public.mindoff_posts
                    (user_id, title, content, image_url, visibility)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *;
                `,
        [
          userId,
          title?.trim() || "",
          content.trim(),
          imagePath,
          visibility,
        ]
      );

      postCreated = true;

      res.status(201).json({
        message: "Post created successfully",
        post: result.rows[0],
      });
    } catch (error) {
      console.error("Create post error:", error);

      // Remove an uploaded image if saving the post failed.
      if (imagePath && !postCreated) {
        const { error: removeError } =
          await supabaseStorage.storage
            .from("post-images")
            .remove([imagePath]);

        if (removeError) {
          console.error(
            "Image cleanup error:",
            removeError.message
          );
        }
      }

      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to create post",
        });
      }
    }
  }
);

// Get public posts, own posts, and accepted friends' posts.
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

    // Convert stored paths into temporary URLs for the feed.
    const postsWithImages = await Promise.all(
      result.rows.map(async (post) => {
        if (!post.image_url) {
          return post;
        }

        const { data, error } =
          await supabaseStorage.storage
            .from("post-images")
            .createSignedUrl(post.image_url, 60 * 60);

        if (error) {
          console.error(
            "Create signed URL error:",
            error.message
          );

          return {
            ...post,
            image_url: null,
          };
        }

        return {
          ...post,
          image_url: data.signedUrl,
        };
      })
    );

    res.json(postsWithImages);
  } catch (error) {
    console.error("Get posts error:", error);

    res.status(500).json({
      error: "Failed to get posts",
    });
  }
});

// Handle unknown routes.
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
  });
});

// Handle upload and unexpected errors.
app.use((error, req, res, next) => {
  console.error("Unexpected API error:", error.message);

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "Image must be 5 MB or smaller",
      });
    }

    return res.status(400).json({
      error: error.message,
    });
  }

  if (error.message === "Only image files are allowed.") {
    return res.status(400).json({
      error: error.message,
    });
  }

  res.status(500).json({
    error: "Internal server error",
  });
});

// Start server after registering routes and middleware.
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Mind Off Run Club API running on port ${PORT}`);
});