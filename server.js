/**
 * NagarSeva - Smart City Complaint Portal
 * Fixed Backend Logic
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const path = require('path');

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nagarseva_secret_key';
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'nagarseva.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ─── DB Init ────────────────────────────────────────────────────────
function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'citizen',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      location TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'pending',
      citizen_name TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id),
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
}

// ─── Middleware ──────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

const validate = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { res.status(422).json({ errors: errors.array() }); return false; }
  return true;
};

// ─── Routes ──────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`).run(name, email, hash);
    const user = { id: result.lastInsertRowid, name, email, role: 'citizen' };
    const token = jwt.sign(user, JWT_SECRET);
    res.status(201).json({ token, user });
  } catch { res.status(409).json({ error: 'Email exists' }); }
});

// ✅ FIX: Strict Login (Strict status codes for frontend catch block)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET);
  res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
});

app.get('/api/complaints', authenticate, (req, res) => {
  const rows = db.prepare('SELECT * FROM complaints ORDER BY created_at DESC').all();
  res.json({ complaints: rows });
});

app.get('/api/my-complaints', authenticate, (req, res) => {
  const rows = db.prepare('SELECT * FROM complaints WHERE user_id = ?').all(req.user.id);
  res.json({ complaints: rows });
});

app.post('/api/complaints', authenticate, (req, res) => {
  const { title, category, description, location, priority = 'medium' } = req.body;
  const result = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(title, category, description, location, priority, req.user.name, req.user.id);

  res.status(201).json(db.prepare('SELECT * FROM complaints WHERE id = ?').get(result.lastInsertRowid));
});

app.patch('/api/complaints/:id/status', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.prepare('UPDATE complaints SET status = ?, updated_at = datetime("now") WHERE id = ?').run(req.body.status, req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/stats', authenticate, (req, res) => {
  const stats = db.prepare(`
    SELECT COUNT(*) as total,
    SUM(status = 'pending') as pending,
    SUM(status = 'inProgress') as inProgress,
    SUM(status = 'resolved') as resolved,
    SUM(status = 'rejected') as rejected
    FROM complaints
  `).get();
  res.json(stats);
});

initDB();
app.listen(PORT, () => console.log(`API LIVE: ${PORT}`));
