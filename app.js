const express = require('express');
const cors = require('cors');
const argon2 = require('@node-rs/argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const con = require('./db_config');

const app = express();
app.use(cors());
app.use(express.json());

// FIXME: ย้ายไปไฟล์ .env เมื่อขึ้นใช้งานจริง
const JWT_KEY = process.env.JWT_KEY || 'sdf1216werxfw@dsjfrewi';

const PROJECT_ROLES = [
  'PC', 'FRONTEND_DEV', 'BACKEND_DEV', 'UI_UX_DESIGNER',
  'DATA_ANALYST', 'TESTER', 'MEMBER',
];

/* ============================ Helpers ============================ */

// Express 4 ไม่จับ error ของ async เอง จึงต้องครอบไว้
const h = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* =========================== Middleware =========================== */

// ตรวจ JWT -> req.user.student_id
const authJWT = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_KEY);
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// ต้องเป็นสมาชิกโปรเจคนี้ (เก็บ role ไว้ที่ req.projectRole)
const requireProjectMember = h(async (req, res, next) => {
  const [rows] = await con.query(
    'SELECT project_role FROM project_members WHERE project_id = ? AND student_id = ?',
    [req.params.id, req.user.student_id]
  );
  if (!rows.length) return res.status(403).json({ message: 'Not a member of this project' });
  req.projectRole = rows[0].project_role;
  next();
});

// ต้องเป็น PC ของโปรเจคนี้
const requirePC = [
  requireProjectMember,
  (req, res, next) => {
    if (req.projectRole !== 'PC') return res.status(403).json({ message: 'PC only' });
    next();
  },
];

/* ============================== Auth ============================== */

// POST /api/auth/register
app.post('/api/auth/register', h(async (req, res) => {
  const { student_id, full_name, email, password } = req.body;
  if (!student_id || !full_name || !email || !password)
    return res.status(400).json({ message: 'student_id, full_name, email, password are required' });
  if (password.length < 8)
    return res.status(400).json({ message: 'Password must be at least 8 characters' });

  const hash = await argon2.hash(password);
  try {
    await con.query(
      'INSERT INTO users (student_id, full_name, email, password_hash) VALUES (?,?,?,?)',
      [student_id, full_name, email, hash]
    );
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ message: 'Student ID or email already exists' });
    throw e;
  }
  res.status(201).json({ message: 'Registered' });
}));

// POST /api/auth/login  (username = student_id)
app.post('/api/auth/login', h(async (req, res) => {
  const { student_id, password } = req.body;
  if (!student_id || !password)
    return res.status(400).json({ message: 'student_id and password are required' });

  const [rows] = await con.query('SELECT * FROM users WHERE student_id = ?', [student_id]);
  const user = rows[0];
  // ข้อความเดียวกันทั้งสองกรณี ไม่บอกว่าผิดที่ id หรือรหัสผ่าน
  if (!user || !(await argon2.verify(user.password_hash, password)))
    return res.status(401).json({ message: 'Invalid student ID or password' });

  const token = jwt.sign({ student_id: user.student_id }, JWT_KEY, { expiresIn: '1d' });
  res.json({
    token,
    user: {
      student_id: user.student_id,
      full_name: user.full_name,
      email: user.email,
      avatar_url: user.avatar_url,
    },
  });
}));

// POST /api/auth/logout  (JWT เป็น stateless: ฝั่ง client ลบ token ทิ้ง)
app.post('/api/auth/logout', authJWT, (req, res) => {
  res.json({ message: 'Logged out' });
});

/* ============================== Users ============================== */

// GET /api/users/me
app.get('/api/users/me', authJWT, h(async (req, res) => {
  const [rows] = await con.query(
    'SELECT student_id, full_name, email, avatar_url, created_at, updated_at FROM users WHERE student_id = ?',
    [req.user.student_id]
  );
  if (!rows.length) return res.status(404).json({ message: 'User not found' });
  res.json(rows[0]);
}));

// PUT /api/users/me  (แก้ชื่อ/รูป และเปลี่ยนรหัสผ่านได้)
app.put('/api/users/me', authJWT, h(async (req, res) => {
  const { full_name, avatar_url, current_password, new_password } = req.body;
  const sets = [];
  const vals = [];

  if (full_name !== undefined) {
    if (!full_name.trim()) return res.status(400).json({ message: 'full_name cannot be empty' });
    sets.push('full_name = ?'); vals.push(full_name);
  }
  if (avatar_url !== undefined) { sets.push('avatar_url = ?'); vals.push(avatar_url); }

  if (new_password !== undefined) {
    if (new_password.length < 8)
      return res.status(400).json({ message: 'New password must be at least 8 characters' });
    const [rows] = await con.query('SELECT password_hash FROM users WHERE student_id = ?', [req.user.student_id]);
    if (!current_password || !(await argon2.verify(rows[0].password_hash, current_password)))
      return res.status(400).json({ message: 'Current password is incorrect' });
    sets.push('password_hash = ?'); vals.push(await argon2.hash(new_password));
  }

  if (!sets.length) return res.status(400).json({ message: 'Nothing to update' });
  await con.query(`UPDATE users SET ${sets.join(', ')} WHERE student_id = ?`, [...vals, req.user.student_id]);
  res.json({ message: 'Profile updated' });
}));

/* ============================= Projects ============================= */

// POST /api/projects  -> สร้างโปรเจค + ใส่ผู้สร้างเป็น PC (transaction เดียวกัน ตามกฎข้อ 1)
app.post('/api/projects', authJWT, h(async (req, res) => {
  const { title, course_code, description, deadline } = req.body;
  if (!title) return res.status(400).json({ message: 'title is required' });

  const id = crypto.randomUUID();
  const conn = await con.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      'INSERT INTO projects (id, title, course_code, description, deadline, created_by) VALUES (?,?,?,?,?,?)',
      [id, title, course_code || null, description || null, deadline || null, req.user.student_id]
    );
    await conn.query(
      "INSERT INTO project_members (project_id, student_id, project_role) VALUES (?,?,'PC')",
      [id, req.user.student_id]
    );
    await conn.commit();
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
  res.status(201).json({ id, message: 'Project created' });
}));

// GET /api/projects  -> โปรเจคที่ฉันเป็นสมาชิก
app.get('/api/projects', authJWT, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT p.id, p.title, p.course_code, p.description, p.deadline, p.created_by,
            p.created_at, pm.project_role AS my_role
     FROM projects p
     JOIN project_members pm ON pm.project_id = p.id
     WHERE pm.student_id = ?
     ORDER BY p.created_at DESC`,
    [req.user.student_id]
  );
  res.json(rows);
}));

// GET /api/projects/:id  -> รายละเอียด + สมาชิก
app.get('/api/projects/:id', authJWT, requireProjectMember, h(async (req, res) => {
  const [projects] = await con.query('SELECT * FROM projects WHERE id = ?', [req.params.id]);
  const [members] = await con.query(
    `SELECT u.student_id, u.full_name, u.avatar_url, pm.project_role, pm.joined_at
     FROM project_members pm
     JOIN users u ON u.student_id = pm.student_id
     WHERE pm.project_id = ?
     ORDER BY pm.joined_at`,
    [req.params.id]
  );
  res.json({ ...projects[0], my_role: req.projectRole, members });
}));

/* ============================== Members ============================== */

// POST /api/projects/:id/members  (PC เท่านั้น)
app.post('/api/projects/:id/members', authJWT, requirePC, h(async (req, res) => {
  const { student_id, project_role = 'MEMBER' } = req.body;
  if (!student_id) return res.status(400).json({ message: 'student_id is required' });
  if (!PROJECT_ROLES.includes(project_role))
    return res.status(400).json({ message: `project_role must be one of ${PROJECT_ROLES.join(', ')}` });
  if (project_role === 'PC')
    return res.status(400).json({ message: 'A project has exactly one PC' });

  const [users] = await con.query('SELECT student_id FROM users WHERE student_id = ?', [student_id]);
  if (!users.length) return res.status(404).json({ message: 'User not found' });

  try {
    await con.query(
      'INSERT INTO project_members (project_id, student_id, project_role) VALUES (?,?,?)',
      [req.params.id, student_id, project_role]
    );
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Already a member' });
    throw e;
  }

  // แจ้งเตือนสมาชิกใหม่
  const [[project]] = await con.query('SELECT title FROM projects WHERE id = ?', [req.params.id]);
  await con.query(
    `INSERT INTO notifications (recipient_id, sender_id, project_id, title, message)
     VALUES (?,?,?,?,?)`,
    [student_id, req.user.student_id, req.params.id,
     'Added to a project', `You have been added to project "${project.title}"`]
  );

  res.status(201).json({ message: 'Member added' });
}));

// GET /api/projects/:id/members
app.get('/api/projects/:id/members', authJWT, requireProjectMember, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT u.student_id, u.full_name, u.email, u.avatar_url, pm.project_role, pm.joined_at
     FROM project_members pm
     JOIN users u ON u.student_id = pm.student_id
     WHERE pm.project_id = ?
     ORDER BY pm.joined_at`,
    [req.params.id]
  );
  res.json(rows);
}));

/* ========================== Error handler ========================== */

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
