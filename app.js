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

/* =====================================================================
 * poom 4/11/69
 * ===================================================================== */

const TASK_STATUS = ['TODO', 'IN_PROGRESS', 'DONE'];

/* ============================ Helpers ============================ */

// สร้างแจ้งเตือน (ไม่แจ้งตัวเอง) รับ db ได้ทั้ง con และ connection ใน transaction
const notify = async (db, { recipient_id, sender_id, project_id, title, message }) => {
  if (!recipient_id || recipient_id === sender_id) return;
  await db.query(
    `INSERT INTO notifications (id, recipient_id, sender_id, project_id, title, message)
     VALUES (?,?,?,?,?,?)`,
    [crypto.randomUUID(), recipient_id, sender_id || null, project_id || null, title, message]
  );
};

// โหลด task จาก :taskId แล้วเช็กว่าเป็นสมาชิกโปรเจคของ task นั้น
// -> req.task, req.projectRole
const loadTask = h(async (req, res, next) => {
  const [tasks] = await con.query('SELECT * FROM tasks WHERE id = ?', [req.params.taskId]);
  if (!tasks.length) return res.status(404).json({ message: 'Task not found' });

  const [m] = await con.query(
    'SELECT project_role FROM project_members WHERE project_id = ? AND student_id = ?',
    [tasks[0].project_id, req.user.student_id]
  );
  if (!m.length) return res.status(403).json({ message: 'Not a member of this project' });

  req.task = tasks[0];
  req.projectRole = m[0].project_role;
  next();
});

const isMember = async (project_id, student_id) => {
  const [rows] = await con.query(
    'SELECT 1 FROM project_members WHERE project_id = ? AND student_id = ?',
    [project_id, student_id]
  );
  return rows.length > 0;
};

const validDate = (v) => v === null || /^\d{4}-\d{2}-\d{2}$/.test(v);

/* ============================== Tasks ============================== */

// POST /api/projects/:id/tasks  (PC เท่านั้น)
app.post('/api/projects/:id/tasks', authJWT, requirePC, h(async (req, res) => {
  const { title, description, assigned_to, due_date } = req.body;
  if (!title || !title.trim()) return res.status(400).json({ message: 'title is required' });
  if (due_date && !validDate(due_date))
    return res.status(400).json({ message: 'due_date must be YYYY-MM-DD' });
  if (assigned_to && !(await isMember(req.params.id, assigned_to)))
    return res.status(400).json({ message: 'assigned_to must be a member of this project' });

  const id = crypto.randomUUID();
  await con.query(
    `INSERT INTO tasks (id, project_id, title, description, assigned_to, due_date)
     VALUES (?,?,?,?,?,?)`,
    [id, req.params.id, title.trim(), description || null, assigned_to || null, due_date || null]
  );

  await notify(con, {
    recipient_id: assigned_to,
    sender_id: req.user.student_id,
    project_id: req.params.id,
    title: 'New task assigned',
    message: `You have been assigned a task: "${title.trim()}"`,
  });

  res.status(201).json({ id, message: 'Task created' });
}));

// GET /api/projects/:id/tasks?status=TODO&assigned_to=6531501001
app.get('/api/projects/:id/tasks', authJWT, requireProjectMember, h(async (req, res) => {
  const where = ['t.project_id = ?'];
  const vals = [req.params.id];

  if (req.query.status) {
    if (!TASK_STATUS.includes(req.query.status))
      return res.status(400).json({ message: `status must be one of ${TASK_STATUS.join(', ')}` });
    where.push('t.status = ?'); vals.push(req.query.status);
  }
  if (req.query.assigned_to) {
    where.push('t.assigned_to = ?'); vals.push(req.query.assigned_to);
  }

  const [rows] = await con.query(
    `SELECT t.id, t.title, t.description, t.assigned_to, u.full_name AS assignee_name,
            t.due_date, t.status, t.submission_url, t.created_at, t.updated_at
     FROM tasks t
     LEFT JOIN users u ON u.student_id = t.assigned_to
     WHERE ${where.join(' AND ')}
     ORDER BY t.due_date IS NULL, t.due_date, t.created_at DESC`,
    vals
  );
  res.json(rows);
}));

// GET /api/tasks/mine  -> งานที่มอบหมายให้ฉัน (ทุกโปรเจค)
app.get('/api/tasks/mine', authJWT, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT t.id, t.project_id, p.title AS project_title, t.title, t.due_date,
            t.status, t.submission_url
     FROM tasks t
     JOIN projects p ON p.id = t.project_id
     WHERE t.assigned_to = ?
     ORDER BY t.status = 'DONE', t.due_date IS NULL, t.due_date`,
    [req.user.student_id]
  );
  res.json(rows);
}));

// GET /api/tasks/:taskId
app.get('/api/tasks/:taskId', authJWT, loadTask, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT t.*, u.full_name AS assignee_name
     FROM tasks t
     LEFT JOIN users u ON u.student_id = t.assigned_to
     WHERE t.id = ?`,
    [req.params.taskId]
  );
  res.json({ ...rows[0], my_role: req.projectRole });
}));

// PUT /api/tasks/:taskId
//  - PC: แก้ได้ทุกช่อง (title, description, assigned_to, due_date, status, submission_url)
//  - ผู้ที่ได้รับมอบหมาย: แก้ได้เฉพาะ status กับ submission_url
app.put('/api/tasks/:taskId', authJWT, loadTask, h(async (req, res) => {
  const task = req.task;
  const me = req.user.student_id;
  const isPC = req.projectRole === 'PC';
  const isAssignee = task.assigned_to === me;
  if (!isPC && !isAssignee)
    return res.status(403).json({ message: 'Only PC or the assignee can update this task' });

  const memberFields = ['status', 'submission_url'];
  const pcFields = ['title', 'description', 'assigned_to', 'due_date'];
  const allowed = isPC ? [...pcFields, ...memberFields] : memberFields;

  const given = Object.keys(req.body).filter((k) => [...pcFields, ...memberFields].includes(k));
  if (!given.length) return res.status(400).json({ message: 'Nothing to update' });
  if (given.some((k) => !allowed.includes(k)))
    return res.status(403).json({ message: 'Assignee can only update status and submission_url' });

  const b = req.body;
  if ('title' in b && (!b.title || !b.title.trim()))
    return res.status(400).json({ message: 'title cannot be empty' });
  if ('status' in b && !TASK_STATUS.includes(b.status))
    return res.status(400).json({ message: `status must be one of ${TASK_STATUS.join(', ')}` });
  if ('due_date' in b && b.due_date !== null && !validDate(b.due_date))
    return res.status(400).json({ message: 'due_date must be YYYY-MM-DD or null' });
  if ('assigned_to' in b && b.assigned_to && !(await isMember(task.project_id, b.assigned_to)))
    return res.status(400).json({ message: 'assigned_to must be a member of this project' });

  const sets = given.map((k) => `${k} = ?`);
  const vals = given.map((k) => (k === 'title' ? b[k].trim() : b[k] === '' ? null : b[k]));
  await con.query(`UPDATE tasks SET ${sets.join(', ')} WHERE id = ?`, [...vals, task.id]);

  // --- แจ้งเตือน ---
  if ('assigned_to' in b && b.assigned_to !== task.assigned_to) {
    await notify(con, {
      recipient_id: b.assigned_to, sender_id: me, project_id: task.project_id,
      title: 'New task assigned', message: `You have been assigned a task: "${task.title}"`,
    });
  }
  if ('status' in b && b.status !== task.status) {
    // แจ้ง PC ของโปรเจค (กรณีผู้รับงานเปลี่ยนสถานะ) และแจ้งผู้รับงาน (กรณี PC เปลี่ยน)
    const [[pc]] = await con.query(
      "SELECT student_id FROM project_members WHERE project_id = ? AND project_role = 'PC'",
      [task.project_id]
    );
    const msg = `Task "${task.title}" status changed: ${task.status} -> ${b.status}`;
    await notify(con, { recipient_id: pc?.student_id, sender_id: me, project_id: task.project_id, title: 'Task status updated', message: msg });
    await notify(con, { recipient_id: task.assigned_to, sender_id: me, project_id: task.project_id, title: 'Task status updated', message: msg });
  }

  res.json({ message: 'Task updated' });
}));

// DELETE /api/tasks/:taskId  (PC เท่านั้น)
app.delete('/api/tasks/:taskId', authJWT, loadTask, h(async (req, res) => {
  if (req.projectRole !== 'PC') return res.status(403).json({ message: 'PC only' });

  const conn = await con.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('DELETE FROM task_comments WHERE task_id = ?', [req.task.id]);
    await conn.query('DELETE FROM tasks WHERE id = ?', [req.task.id]);
    await conn.commit();
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
  res.json({ message: 'Task deleted' });
}));

/* =========================== Task comments =========================== */

// POST /api/tasks/:taskId/comments  (สมาชิกโปรเจคทุกคน)
app.post('/api/tasks/:taskId/comments', authJWT, loadTask, h(async (req, res) => {
  const { comment_text } = req.body;
  if (!comment_text || !comment_text.trim())
    return res.status(400).json({ message: 'comment_text is required' });

  const [result] = await con.query(
    'INSERT INTO task_comments (task_id, author_id, comment_text) VALUES (?,?,?)',
    [req.task.id, req.user.student_id, comment_text.trim()]
  );

  await notify(con, {
    recipient_id: req.task.assigned_to,
    sender_id: req.user.student_id,
    project_id: req.task.project_id,
    title: 'New comment',
    message: `New comment on task "${req.task.title}"`,
  });

  res.status(201).json({ id: result.insertId, message: 'Comment added' });
}));

// GET /api/tasks/:taskId/comments
app.get('/api/tasks/:taskId/comments', authJWT, loadTask, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT c.id, c.author_id, u.full_name AS author_name, u.avatar_url,
            c.comment_text, c.created_at
     FROM task_comments c
     JOIN users u ON u.student_id = c.author_id
     WHERE c.task_id = ?
     ORDER BY c.created_at`,
    [req.params.taskId]
  );
  res.json(rows);
}));

// DELETE /api/comments/:commentId  (เจ้าของคอมเมนต์ หรือ PC)
app.delete('/api/comments/:commentId', authJWT, h(async (req, res) => {
  const [rows] = await con.query(
    `SELECT c.id, c.author_id, t.project_id
     FROM task_comments c JOIN tasks t ON t.id = c.task_id
     WHERE c.id = ?`,
    [req.params.commentId]
  );
  if (!rows.length) return res.status(404).json({ message: 'Comment not found' });
  const c = rows[0];

  const [m] = await con.query(
    'SELECT project_role FROM project_members WHERE project_id = ? AND student_id = ?',
    [c.project_id, req.user.student_id]
  );
  if (!m.length) return res.status(403).json({ message: 'Not a member of this project' });
  if (c.author_id !== req.user.student_id && m[0].project_role !== 'PC')
    return res.status(403).json({ message: 'Only the author or PC can delete this comment' });

  await con.query('DELETE FROM task_comments WHERE id = ?', [c.id]);
  res.json({ message: 'Comment deleted' });
}));

/* =========================== Notifications =========================== */
// หมายเหตุ: ต้องประกาศ /unread-count และ /read-all ก่อน /:id

// GET /api/notifications?unread=true&limit=50&offset=0
app.get('/api/notifications', authJWT, h(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const where = ['n.recipient_id = ?'];
  const vals = [req.user.student_id];
  if (req.query.unread === 'true') where.push('n.is_read = 0');

  const [rows] = await con.query(
    `SELECT n.id, n.sender_id, s.full_name AS sender_name, n.project_id,
            n.title, n.message, n.is_read, n.created_at
     FROM notifications n
     LEFT JOIN users s ON s.student_id = n.sender_id
     WHERE ${where.join(' AND ')}
     ORDER BY n.created_at DESC
     LIMIT ? OFFSET ?`,
    [...vals, limit, offset]
  );
  res.json(rows);
}));

// GET /api/notifications/unread-count
app.get('/api/notifications/unread-count', authJWT, h(async (req, res) => {
  const [[row]] = await con.query(
    'SELECT COUNT(*) AS unread FROM notifications WHERE recipient_id = ? AND is_read = 0',
    [req.user.student_id]
  );
  res.json({ unread: row.unread });
}));

// PUT /api/notifications/read-all
app.put('/api/notifications/read-all', authJWT, h(async (req, res) => {
  const [r] = await con.query(
    'UPDATE notifications SET is_read = 1 WHERE recipient_id = ? AND is_read = 0',
    [req.user.student_id]
  );
  res.json({ message: 'All notifications marked as read', updated: r.affectedRows });
}));

// PUT /api/notifications/:id/read
app.put('/api/notifications/:id/read', authJWT, h(async (req, res) => {
  const [r] = await con.query(
    'UPDATE notifications SET is_read = 1 WHERE id = ? AND recipient_id = ?',
    [req.params.id, req.user.student_id]
  );
  if (!r.affectedRows) return res.status(404).json({ message: 'Notification not found' });
  res.json({ message: 'Marked as read' });
}));

// DELETE /api/notifications/:id
app.delete('/api/notifications/:id', authJWT, h(async (req, res) => {
  const [r] = await con.query(
    'DELETE FROM notifications WHERE id = ? AND recipient_id = ?',
    [req.params.id, req.user.student_id]
  );
  if (!r.affectedRows) return res.status(404).json({ message: 'Notification not found' });
  res.json({ message: 'Notification deleted' });
}));

/* ========================== Error handler ========================== */

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
