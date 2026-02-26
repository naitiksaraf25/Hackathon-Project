require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { body, query, validationResult } = require('express-validator');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nagarseva_secret_key';
const DB_PATH = path.join(__dirname, 'nagarseva.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ─── Database Initialization ───
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'citizen'
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
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed Admin & User if not exists
const adminHash = bcrypt.hashSync('admin123', 10);
const userHash = bcrypt.hashSync('citizen123', 10);
db.prepare("INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)").run('Admin', 'admin@nagarseva.in', adminHash, 'admin');
db.prepare("INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)").run('Ramesh', 'ramesh@gmail.com', userHash, 'citizen');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Middleware ───
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid Token' }); }
};

// ─── Routes ───
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
});

app.post('/api/auth/register', (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hash = bcrypt.hashSync(password, 10);
        const result = db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'citizen')").run(name, email, hash);
        const user = { id: result.lastInsertRowid, name, email, role: 'citizen' };
        const token = jwt.sign(user, JWT_SECRET);
        res.json({ token, user });
    } catch (e) { res.status(400).json({ error: "Email already exists" }); }
});

app.get('/api/complaints', authenticate, (req, res) => {
  const complaints = db.prepare('SELECT * FROM complaints ORDER BY id DESC').all();
  res.json(complaints);
});

app.get('/api/my-complaints', authenticate, (req, res) => {
  const complaints = db.prepare('SELECT * FROM complaints WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json(complaints);
});

app.post('/api/complaints', authenticate, (req, res) => {
  const { title, category, description, location, priority } = req.body;
  const result = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(title, category.toLowerCase(), description, location, priority.toLowerCase(), req.user.name, req.user.id);
  
  res.json(db.prepare('SELECT * FROM complaints WHERE id = ?').get(result.lastInsertRowid));
});

app.patch('/api/complaints/:id/status', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  db.prepare('UPDATE complaints SET status = ? WHERE id = ?').run(req.body.status, req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/stats', authenticate, (req, res) => {
  const stats = db.prepare(`
    SELECT COUNT(*) as total, 
    SUM(status='pending') as pending, 
    SUM(status='inProgress') as inProgress, 
    SUM(status='resolved') as resolved 
    FROM complaints`).get();
  res.json(stats);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
