/**
 * NagarSeva - Smart City Complaint Portal
 * Fixed Backend
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
const JWT_SECRET = process.env.JWT_SECRET || 'nagarseva_super_secret_key_change_in_prod';
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'nagarseva.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── DB Init ──────────────────────────────────────────────────────────────────
function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT    NOT NULL,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL DEFAULT 'citizen',
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      title        TEXT NOT NULL,
      category     TEXT NOT NULL,
      description  TEXT NOT NULL,
      location     TEXT NOT NULL,
      priority     TEXT NOT NULL DEFAULT 'medium',
      status       TEXT NOT NULL DEFAULT 'pending',
      citizen_name TEXT NOT NULL,
      user_id      INTEGER REFERENCES users(id),
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER REFERENCES users(id),
      action       TEXT NOT NULL,
      complaint_id INTEGER REFERENCES complaints(id),
      details      TEXT,
      timestamp    TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const count = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (count.c === 0) seedData();
}

function seedData() {
  console.log('[SEED] Seeding users and complaints...');
  const adminHash   = bcrypt.hashSync('admin123', 10);
  const citizenHash = bcrypt.hashSync('citizen123', 10);

  const insertUser = db.prepare(`INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`);
  insertUser.run('Admin NagarSeva', 'admin@nagarseva.in', adminHash,   'admin');
  insertUser.run('Ramesh Kumar',    'ramesh@gmail.com',   citizenHash, 'citizen');

  const citizenId = db.prepare("SELECT id FROM users WHERE email='ramesh@gmail.com'").get().id;

  const insertComplaint = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, status, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seeds = [
    ['Broken Street Light on MG Road',        'electricity',    'Three consecutive street lights near MG Road bus stop have been non-functional for 2 weeks causing safety issues at night.', 'MG Road, Near Bus Stop No. 14, Pune',     'high',     'pending',    'Ramesh Kumar',   citizenId],
    ['Overflowing Garbage Bin near Market',   'sanitation',     'The garbage bin near Laxmi Market has been overflowing for 3 days. Foul smell is spreading to nearby shops and homes.',        'Laxmi Market, Sector 7, Nagpur',          'high',     'inProgress', 'Priya Sharma',   citizenId],
    ['Pothole on NH-48 Causing Accidents',    'roads',          'Large pothole on NH-48 near Zomato office junction. Two bike accidents reported this week. Immediate repair needed.',          'NH-48, Near Zomato Office, Bengaluru',    'critical', 'pending',    'Suresh Nair',    citizenId],
    ['Water Supply Disruption for 5 Days',    'water',          'Our entire colony has not received municipal water supply for 5 days. Residents are forced to buy expensive tankers.',         'Shanti Nagar Colony, Block C, Jaipur',    'critical', 'inProgress', 'Meena Devi',     citizenId],
    ['Unauthorized Construction Blocking Road','infrastructure', 'Builder has placed construction material on the public road without permission, blocking traffic flow completely.',           'Gandhi Nagar Road, Near Park, Ahmedabad', 'medium',   'resolved',   'Ajay Patel',     citizenId],
    ['Sewage Overflow in Residential Area',   'sanitation',     'Sewage is overflowing from the drain on Main Street and entering homes. Health hazard for children and elderly residents.',   'Model Town, Sector 12, Ludhiana',         'critical', 'pending',    'Harpreet Singh', citizenId],
    ['Damaged Park Benches and Broken Swings','parks',          'Most benches in the community park are broken and swing sets are damaged. Children are getting hurt while playing there.',     'Central Park, Anna Nagar, Chennai',       'low',      'pending',    'Kavitha Rao',    citizenId],
    ['Stray Dogs Menace Near School',         'animal control', 'Pack of aggressive stray dogs near St. Mary School gates. Children afraid to walk. Three biting incidents reported.',         'St. Mary School Road, Bhopal',            'high',     'inProgress', 'Father Thomas',  citizenId],
  ];

  for (const s of seeds) insertComplaint.run(...s);
  console.log(`[SEED] Inserted ${seeds.length} complaints.`);
}

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); // Railway proxy fix

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
}));

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error: 'Admin access required' });
  next();
}

function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { res.status(422).json({ errors: errors.array() }); return false; }
  return true;
}

function logActivity(userId, action, complaintId, details) {
  db.prepare(`INSERT INTO activity_logs (user_id, action, complaint_id, details) VALUES (?, ?, ?, ?)`)
    .run(userId, action, complaintId, details);
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'NagarSeva API' });
});

// ── REGISTER ──────────────────────────────────────────────────────────────────
app.post('/api/auth/register',
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  (req, res) => {
    if (!validate(req, res)) return;
    const { name, email, password } = req.body;

    // FIX: Self-registered users are ALWAYS citizens — never trust email for role
    const role = 'citizen';

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered. Please sign in.', code: 'EMAIL_EXISTS' });

    const password_hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`)
      .run(name, email, password_hash, role);

    const user = { id: result.lastInsertRowid, name, email, role };
    logActivity(user.id, 'USER_REGISTER', null, `New user registered: ${email}`);
    console.log(`[AUTH] Registered: ${email} (${role})`);
    res.status(201).json({ token: generateToken(user), user });
  }
);

// ── LOGIN — FIXED: No demo bypass, strict error codes ─────────────────────────
app.post('/api/auth/login',
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password is required'),
  (req, res) => {
    if (!validate(req, res)) return;
    const { email, password } = req.body;

    // Step 1: Does user exist?
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({
        error: 'No account found with this email. Please register first.',
        code: 'USER_NOT_FOUND'
      });
    }

    // Step 2: Is password correct?
    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({
        error: 'Incorrect password. Please try again.',
        code: 'WRONG_PASSWORD'
      });
    }

    const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
    logActivity(user.id, 'USER_LOGIN', null, `Login from ${req.ip}`);
    console.log(`[AUTH] Login: ${email} (${user.role})`);
    res.json({ token: generateToken(safeUser), user: safeUser });
  }
);

// ── GET ALL COMPLAINTS (admin) ────────────────────────────────────────────────
app.get('/api/complaints',
  authenticate,
  query('category').optional().trim(),
  query('status').optional().trim(),
  (req, res) => {
    if (!validate(req, res)) return;
    const { category, status } = req.query;
    let sql = 'SELECT * FROM complaints WHERE 1=1';
    const params = [];
    if (category) { sql += ' AND category = ?'; params.push(category); }
    if (status)   { sql += ' AND status = ?';   params.push(status); }
    sql += ' ORDER BY created_at DESC';
    const complaints = db.prepare(sql).all(...params);
    res.json({ count: complaints.length, complaints });
  }
);

// ── GET MY COMPLAINTS (citizen) — NEW ENDPOINT ───────────────────────────────
app.get('/api/my-complaints',
  authenticate,
  (req, res) => {
    const complaints = db.prepare(
      'SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.user.id);
    res.json({ count: complaints.length, complaints });
  }
);

// ── POST COMPLAINT ────────────────────────────────────────────────────────────
// FIX: Reduced min description to 10 chars (frontend sends shorter sometimes)
app.post('/api/complaints',
  authenticate,
  body('title').trim().notEmpty().withMessage('Title is required'),
  body('category').trim().notEmpty().withMessage('Category is required'),
  body('description').trim().isLength({ min: 10 }).withMessage('Description must be at least 10 characters'),
  body('location').trim().notEmpty().withMessage('Location is required'),
  body('priority').optional().isIn(['low','medium','high','critical']).withMessage('Invalid priority'),
  (req, res) => {
    if (!validate(req, res)) return;

    const { title, category, description, location, priority = 'medium' } = req.body;
    const citizen_name = req.user.name;
    const user_id      = req.user.id;

    const result = db.prepare(`
      INSERT INTO complaints (title, category, description, location, priority, citizen_name, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(title, category, description, location, priority, citizen_name, user_id);

    const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(result.lastInsertRowid);
    logActivity(user_id, 'COMPLAINT_CREATED', complaint.id, `New complaint: "${title}"`);
    console.log(`[COMPLAINT] Created #${complaint.id}: "${title}" by ${citizen_name}`);
    res.status(201).json(complaint);
  }
);

// ── UPDATE STATUS (admin only) ────────────────────────────────────────────────
app.patch('/api/complaints/:id/status',
  authenticate,
  requireAdmin,
  body('status').isIn(['pending','inProgress','resolved','rejected']).withMessage('Invalid status'),
  (req, res) => {
    if (!validate(req, res)) return;
    const { id } = req.params;
    const { status, note } = req.body;

    const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

    db.prepare(`UPDATE complaints SET status = ?, updated_at = datetime('now') WHERE id = ?`).run(status, id);

    const details = `Status: ${complaint.status} → ${status}${note ? ' | Note: ' + note : ''}`;
    logActivity(req.user.id, 'STATUS_UPDATED', parseInt(id), details);
    console.log(`[ADMIN] #${id}: ${complaint.status} → ${status} by ${req.user.email}`);

    const updated = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
    res.json({ message: 'Status updated', complaint: updated });
  }
);

// ── ADMIN STATS ───────────────────────────────────────────────────────────────
app.get('/api/admin/stats',
  authenticate,
  requireAdmin,
  (_req, res) => {
    const row = db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'pending'    THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'inProgress' THEN 1 ELSE 0 END) AS inProgress,
        SUM(CASE WHEN status = 'resolved'   THEN 1 ELSE 0 END) AS resolved,
        SUM(CASE WHEN status = 'rejected'   THEN 1 ELSE 0 END) AS rejected,
        SUM(CASE WHEN priority = 'critical' AND status != 'resolved' THEN 1 ELSE 0 END) AS criticalOpen
      FROM complaints
    `).get();

    const byCategory = db.prepare(
      `SELECT category, COUNT(*) as count FROM complaints GROUP BY category ORDER BY count DESC`
    ).all();

    const recentActivity = db.prepare(`
      SELECT al.*, u.name as user_name FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.timestamp DESC LIMIT 10
    `).all();

    res.json({
      total:        row.total        || 0,
      pending:      row.pending      || 0,
      inProgress:   row.inProgress   || 0,
      resolved:     row.resolved     || 0,
      rejected:     row.rejected     || 0,
      criticalOpen: row.criticalOpen || 0,
      byCategory,
      recentActivity
    });
  }
);

// ─── 404 / Error ──────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found` }));
app.use((err, _req, res, _next) => { console.error('[ERROR]', err); res.status(500).json({ error: 'Internal server error' }); });

// ─── Start ────────────────────────────────────────────────────────────────────
initDB();
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║   🏙️  NagarSeva API  —  Port ${PORT}          ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
  console.log('[INFO] Admin   → admin@nagarseva.in / admin123');
  console.log('[INFO] Citizen → ramesh@gmail.com   / citizen123\n');
});
