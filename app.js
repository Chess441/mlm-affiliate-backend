import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";

const app = express();
app.use(cors());
app.use(express.json());

/* =======================
   CONFIG
========================= */
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const COMMISSION_LEVELS = [0.10, 0.05, 0.02]; // L1, L2, L3

/* =======================
   IN-MEMORY STORAGE
========================= */
const users = [];        // { id, name, email, passwordHash, code, referrerCode, createdAt }
const clicks = [];       // { code, timestamp, ip }
const orders = [];       // { id, amount, code, buyerEmail, createdAt }
const commissions = [];  // { orderId, earnerUserId, level, percent, amount }

/* =======================
   HELPERS
========================= */
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

function findUserByCode(code) {
  return users.find(u => u.code === code);
}

function buildUpline(refCode, levels) {
  const upline = [];
  let currentCode = refCode;
  for (let i = 0; i < levels; i++) {
    if (!currentCode) break;
    const referrer = findUserByCode(currentCode);
    if (!referrer) break;
    upline.push(referrer);
    currentCode = referrer.referrerCode || null;
  }
  return upline;
}

/* =======================
   TEST ROUTE
========================= */
app.get("/", (_req, res) => {
  res.send("🚀 MLM Affiliate Backend is LIVE");
});

/* =======================
   AUTH
========================= */

// Signup
app.post("/auth/signup", async (req, res) => {
  const { name, email, password, ref } = req.body || {};
  if (!email || !password || !name) {
    return res.status(400).json({ error: "name, email & password required" });
  }
  if (users.some(u => u.email === email)) {
    return res.status(409).json({ error: "email exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const code = genCode();

  const user = {
    id: users.length + 1,
    name,
    email,
    passwordHash,
    code,                    // their referral code
    referrerCode: ref || null, // who referred them (if any)
    createdAt: new Date()
  };
  users.push(user);

  const token = signJWT(user);
  res.json({
    token,
    user: { id: user.id, email: user.email, code: user.code, referrerCode: user.referrerCode }
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
    user: { id: user.id, email: user.email, code: user.code, referrerCode: user.referrerCode }
  });
});

// Who am I
app.get("/me", auth, (req, res) => {
  const me = users.find(u => u.id === req.user.id);
  if (!me) return res.status(404).json({ error: "User not found" });
  res.json({
    id: me.id,
    email: me.email,
    code: me.code,
    referrerCode: me.referrerCode,
    createdAt: me.createdAt
  });
});

/* =======================
   CLICK TRACKING
========================= */

// Record a click for a referral code
app.get("/click/:code", (req, res) => {
  const { code } = req.params;
  const owner = findUserByCode(code);
  if (!owner) {
    return res.status(404).json({ error: "Referral code not found" });
  }

  clicks.push({
    code,
    timestamp: new Date().toISOString(),
    ip: req.ip
  });

  const total = clicks.filter(c => c.code === code).length;
  res.json({ message: `Click recorded for ${code}`, totalClicks: total });
});

// Public stats for a referral code (clicks, orders, commission total)
app.get("/stats/:code", (req, res) => {
  const { code } = req.params;
  const owner = findUserByCode(code);
  if (!owner) return res.status(404).json({ error: "Referral code not found" });

  const totalClicks = clicks.filter(c => c.code === code).length;
  const myOrders = orders.filter(o => o.code === code);
  const orderCount = myOrders.length;
  const revenue = myOrders.reduce((sum, o) => sum + o.amount, 0);

  const myUser = owner;
  const myComms = commissions
    .filter(c => c.earnerUserId === myUser.id)
    .reduce((sum, c) => sum + c.amount, 0);

  res.json({
    code,
    totalClicks,
    orderCount,
    revenue,
    commissions: myComms
  });
});

/* =======================
   ORDERS & COMMISSIONS
========================= */

// Create an order and pay upline commissions
app.post("/order", (req, res) => {
  const { amount, code, buyerEmail } = req.body || {};
  if (!amount || !code) {
    return res.status(400).json({ error: "amount & code required" });
  }
  const owner = findUserByCode(code);
  if (!owner) return res.status(404).json({ error: "Referral code not found" });

  // Record order
  const order = {
    id: orders.length + 1,
    amount: Number(amount),
    code,
    buyerEmail: buyerEmail || null,
    createdAt: new Date()
  };
  orders.push(order);

  // Build upline and allocate commissions
  const upline = buildUpline(owner.referrerCode, COMMISSION_LEVELS.length);
  const payouts = [];

  // Level 0 (the code owner) earns L1 commission
  const l1Percent = COMMISSION_LEVELS[0] ?? 0;
  const l1Amount = order.amount * l1Percent;
  if (l1Amount > 0) {
    commissions.push({
      orderId: order.id,
      earnerUserId: owner.id,
      level: 1,
      percent: l1Percent,
      amount: l1Amount
    });
    payouts.push({ userId: owner.id, level: 1, amount: l1Amount });
  }

  // Higher levels (their referrers)
  upline.forEach((uplineUser, idx) => {
    const level = idx + 2; // starts at level 2
    const percent = COMMISSION_LEVELS[idx + 1] ?? 0;
    const amt = order.amount * percent;
    if (amt > 0) {
      commissions.push({
        orderId: order.id,
        earnerUserId: uplineUser.id,
        level,
        percent,
        amount: amt
      });
      payouts.push({ userId: uplineUser.id, level, amount: amt });
    }
  });

  res.json({
    orderId: order.id,
    amount: order.amount,
    code,
    payouts
  });
});

/* =======================
   PRIVATE STATS FOR A USER
========================= */

// Stats for the logged-in user
app.get("/me/stats", auth, (req, res) => {
  const me = users.find(u => u.id === req.user.id);
  if (!me) return res.status(404).json({ error: "User not found" });

  const myClicks = clicks.filter(c => c.code === me.code).length;
  const myOrders = orders.filter(o => o.code === me.code);
  const myRevenue = myOrders.reduce((sum, o) => sum + o.amount, 0);
  const myComms = commissions.filter(c => c.earnerUserId === me.id);
  const myCommTotal = myComms.reduce((sum, c) => sum + c.amount, 0);

  const myReferrals = users.filter(u => u.referrerCode === me.code).length;

  res.json({
    code: me.code,
    clicks: myClicks,
    referrals: myReferrals,
    orders: myOrders.length,
    revenueDriven: myRevenue,
    commissionsEarned: myCommTotal,
    commissionBreakdown: myComms
  });
});

/* =======================
   START SERVER
========================= */
app.listen(PORT, () => console.log(`API running on :${PORT}`));