import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static(__dirname));

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    password: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ["user", "admin", "owner"],
      default: "user"
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", userSchema);

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      username: user.username,
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Belum login"
    });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Session tidak valid"
    });
  }
}

function ownerOnly(req, res, next) {
  if (req.user.role !== "owner") {
    return res.status(403).json({
      success: false,
      message: "Akses hanya untuk owner"
    });
  }

  next();
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Semua field wajib diisi"
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username minimal 3 karakter"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password minimal 6 karakter"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password tidak cocok"
      });
    }

    const exists = await User.findOne({
      $or: [
        { username },
        { email: email.toLowerCase() }
      ]
    });

    if (exists) {
      return res.status(409).json({
        success: false,
        message: "Username atau email sudah digunakan"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: "user"
    });

    const token = createToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({
      success: true,
      message: "Registrasi berhasil",
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Terjadi kesalahan server"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username dan password wajib diisi"
      });
    }

    const user = await User.findOne({
      username
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Username atau password salah"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Username atau password salah"
      });
    }

    const token = createToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Login berhasil",
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Terjadi kesalahan server"
    });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select(
    "-password"
  );

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User tidak ditemukan"
    });
  }

  res.json({
    success: true,
    user
  });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");

  res.json({
    success: true,
    message: "Logout berhasil"
  });
});

app.get("/api/owner", auth, ownerOnly, async (req, res) => {
  const users = await User.find()
    .select("-password")
    .sort({ createdAt: -1 });

  res.json({
    success: true,
    users
  });
});

app.get("/dashboard", auth, (req, res) => {
  res.sendFile(
    path.join(__dirname, "dashboard", "index.html")
  );
});

app.get("/dashboard/owner", auth, ownerOnly, (req, res) => {
  res.sendFile(
    path.join(__dirname, "dashboard", "owner.html")
  );
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected");

    app.listen(process.env.PORT || 3000, () => {
      console.log(
        `Server running on http://localhost:${process.env.PORT || 3000}`
      );
    });
  })
  .catch(error => {
    console.error("MongoDB connection failed:", error);
    process.exit(1);
  });
