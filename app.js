import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const users = [];
const clicks = [];
const orders = [];
const COMMISSION_LEVELS = [0.10, 0.05, 0.02];

// Test route
app.get("/", (_req, res) => {
  res.send("🚀 MLM Affiliate Backend is LIVE");
});

// Helper functions
function genCode() {
  return nanoid(8);
}

function signJWT(user) {
  return jwt.sign(
    { id: user.id, email: user.email, code: user.code },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Signup
app.post("/auth/signup", async (req, res) => {
  const { name, email, password, ref } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email & password required" });
  if (users.some(u => u.email === email))
    return res.status(409).json({ error: "email exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const code = genCode();

  const user = {
    id: users.length + 1,
    name: name || null,
    email,
    passwordHash,
    code,
    referrerCode: ref || null,
    createdAt: new Date()
  };
  users.push(user);

  const token = signJWT(user);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      code: user.code,
      referrerCode: user.referrerCode
    }
  });
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "invalid creds" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "invalid creds" });

  const token = signJWT(user);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      code: user.code,
      referrerCode: user.referrerCode
    }
  });
});
// Protected route to get current user info
app.get("/me", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "No token provided" });

    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = users.find(u => u.email === decoded.email);
        if (!user) return res.status(404).json({ error: "User not found" });

        res.json({ email: user.email, clicks: user.clicks, referrerCode: user.referrerCode });
    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
});
app.listen(PORT, () => console.log(`API running on :${PORT}`));
