const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const DB_PATH = process.env.DB_PATH || "/data/forecast.db";

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// ── Database setup ────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER PRIMARY KEY,
    starting_balance REAL DEFAULT 3000,
    low_balance_threshold REAL DEFAULT 500,
    forecast_days INTEGER DEFAULT 60,
    dark_mode INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    amount REAL NOT NULL,
    type TEXT NOT NULL,
    frequency TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS reconciled (
    user_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    PRIMARY KEY (user_id, key),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

app.use(cors());
app.use(express.json());

// ── Auth middleware ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
  next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────
// Setup: create first admin user (only works if no users exist)
app.post("/api/setup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  const existing = db.prepare("SELECT id FROM users LIMIT 1").get();
  if (existing) return res.status(400).json({ error: "Setup already complete" });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)").run(username, hash);
  db.prepare("INSERT INTO user_data (user_id) VALUES (?)").run(result.lastInsertRowid);
  const token = jwt.sign({ id: result.lastInsertRowid, username, is_admin: true }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username, is_admin: true });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid username or password" });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: !!user.is_admin }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username: user.username, is_admin: !!user.is_admin });
});

// ── User management (admin only) ──────────────────────────────────────────────
app.get("/api/users", authMiddleware, adminMiddleware, (req, res) => {
  const users = db.prepare("SELECT id, username, is_admin, created_at FROM users").all();
  res.json(users);
});

app.post("/api/users", authMiddleware, adminMiddleware, (req, res) => {
  const { username, password, is_admin } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)").run(username, hash, is_admin ? 1 : 0);
    db.prepare("INSERT INTO user_data (user_id) VALUES (?)").run(result.lastInsertRowid);
    res.json({ id: result.lastInsertRowid, username, is_admin: !!is_admin });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(400).json({ error: "Username already exists" });
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/users/:id", authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: "Cannot delete yourself" });
  db.prepare("DELETE FROM reconciled WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM items WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM user_data WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ ok: true });
});

app.post("/api/change-password", authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!bcrypt.compareSync(current_password, user.password))
    return res.status(401).json({ error: "Current password is incorrect" });
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hash, req.user.id);
  res.json({ ok: true });
});

// ── User data (settings) ──────────────────────────────────────────────────────
app.get("/api/settings", authMiddleware, (req, res) => {
  let data = db.prepare("SELECT * FROM user_data WHERE user_id = ?").get(req.user.id);
  if (!data) {
    db.prepare("INSERT INTO user_data (user_id) VALUES (?)").run(req.user.id);
    data = db.prepare("SELECT * FROM user_data WHERE user_id = ?").get(req.user.id);
  }
  res.json(data);
});

app.put("/api/settings", authMiddleware, (req, res) => {
  const { starting_balance, low_balance_threshold, forecast_days, dark_mode } = req.body;
  db.prepare(`UPDATE user_data SET starting_balance=?, low_balance_threshold=?, forecast_days=?, dark_mode=? WHERE user_id=?`)
    .run(starting_balance, low_balance_threshold, forecast_days, dark_mode ? 1 : 0, req.user.id);
  res.json({ ok: true });
});

// ── Items ─────────────────────────────────────────────────────────────────────
app.get("/api/items", authMiddleware, (req, res) => {
  const items = db.prepare("SELECT * FROM items WHERE user_id = ?").all(req.user.id);
  res.json(items.map(i => ({ ...i, endDate: i.end_date, startDate: i.start_date })));
});

app.post("/api/items", authMiddleware, (req, res) => {
  const { name, amount, type, frequency, startDate, endDate } = req.body;
  const result = db.prepare("INSERT INTO items (user_id, name, amount, type, frequency, start_date, end_date) VALUES (?,?,?,?,?,?,?)")
    .run(req.user.id, name, amount, type, frequency, startDate, endDate || "");
  res.json({ id: result.lastInsertRowid, name, amount, type, frequency, startDate, endDate: endDate || "" });
});

app.delete("/api/items/:id", authMiddleware, (req, res) => {
  db.prepare("DELETE FROM items WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  db.prepare("DELETE FROM reconciled WHERE user_id = ? AND key LIKE ?").run(req.user.id, `${req.params.id}_%`);
  res.json({ ok: true });
});

// ── Reconciled ────────────────────────────────────────────────────────────────
app.get("/api/reconciled", authMiddleware, (req, res) => {
  const rows = db.prepare("SELECT key FROM reconciled WHERE user_id = ?").all(req.user.id);
  const obj = {};
  rows.forEach(r => obj[r.key] = true);
  res.json(obj);
});

app.post("/api/reconciled/toggle", authMiddleware, (req, res) => {
  const { key } = req.body;
  const existing = db.prepare("SELECT key FROM reconciled WHERE user_id = ? AND key = ?").get(req.user.id, key);
  if (existing) {
    db.prepare("DELETE FROM reconciled WHERE user_id = ? AND key = ?").run(req.user.id, key);
    res.json({ reconciled: false });
  } else {
    db.prepare("INSERT INTO reconciled (user_id, key) VALUES (?, ?)").run(req.user.id, key);
    res.json({ reconciled: true });
  }
});

app.delete("/api/reconciled", authMiddleware, (req, res) => {
  db.prepare("DELETE FROM reconciled WHERE user_id = ?").run(req.user.id);
  res.json({ ok: true });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", (req, res) => res.json({ ok: true }));

// ── Check if setup needed ─────────────────────────────────────────────────────
app.get("/api/needs-setup", (req, res) => {
  const existing = db.prepare("SELECT id FROM users LIMIT 1").get();
  res.json({ needs_setup: !existing });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
