// server.js
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import fs from 'fs';
import nodemailer from 'nodemailer';
import { Parser } from 'json2csv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sql = neon(process.env.DATABASE_URL);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: '/tmp' });

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const generateToken = (user) =>
  jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      track: user.track
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing auth token' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid auth token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path, { folder: 'guru_it' });
  fs.unlinkSync(file.path);
  return result.secure_url;
};

app.get('/', (req, res) => {
  res.send('Welcome to Guru IT API');
});


// --- AUTH ROUTES ---

app.post('/register', upload.single('image'), async (req, res) => {
  const { email, password, name, reg_no, level, school, department, track, role = 'user' } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'All fields are required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const imageUrl = req.file ? await uploadImage(req.file) : null;

    const [existing] = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (existing) return res.status(400).json({ error: 'Email already in use' });


    const [user] = await sql`
      INSERT INTO users (email, password, name, profile_image_url, reg_no, level, school, department, track, role)
      VALUES (${email}, ${hashedPassword}, ${name}, ${imageUrl}, ${reg_no}, ${level}, ${school}, ${department}, ${track}, ${role})
      RETURNING *;
    `;
    const token = generateToken(user);
    res.status(201).json({ message: 'User registered successfully',token, user});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [user] = await sql`SELECT * FROM users WHERE email = ${email} LIMIT 1`;
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

    const token = generateToken(user);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/auth/profile', authenticateToken, async (req, res) => {
  try {
    const [user] = await sql`SELECT * FROM users WHERE id = ${req.user.id}`;
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/auth/profile', authenticateToken, upload.single('image'), async (req, res) => {
  const { email, name, reg_no, level, school, department } = req.body;

  try {
    const updates = { email, name, reg_no, level, school, department };
    if (req.file) updates.profile_image_url = await uploadImage(req.file);

    const fields = Object.keys(updates).filter((k) => updates[k] !== undefined);
    const values = fields.map((k) => updates[k]);
    const setClause = fields.map((k, i) => `${k} = $${i + 1}`).join(', ');
    const query = `UPDATE users SET ${setClause} WHERE id = $${fields.length + 1} RETURNING *`;

    const [updatedUser] = await sql.unsafe(query, [...values, req.user.id]);

    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const [user] = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetUrl = `http://localhost:5173/reset-password?token=${token}`;

    await transporter.sendMail({
      from: `"GURU IT" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Click to reset your password:</p><a href="${resetUrl}">${resetUrl}</a><p>Expires in 15 minutes.</p>`,
    });

    res.json({ message: 'Reset email sent if account exists.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send reset email' });
  }
});

app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and password required' });

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    const [user] = await sql`SELECT * FROM users WHERE id = ${userId}`;
    if (!user) return res.status(400).json({ error: 'User not found' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await sql`UPDATE users SET password = ${hashed} WHERE id = ${userId}`;

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// --- ASSIGNMENT ROUTES ---

// Get current assignment for logged-in user
app.get('/current-assignment', authenticateToken, async (req, res) => {
  try {
    //  Get the latest active assignment for this user
    const [assignment] = await sql`
      SELECT *
      FROM assignments
      WHERE (
        (track = ${req.user.track})
        OR (
          is_group = true
          AND group_members::jsonb @> ${JSON.stringify([req.user.id])}::jsonb
        )
      )
      AND (deadline IS NULL OR deadline >= CURRENT_DATE)
      ORDER BY date DESC, time DESC
      LIMIT 1;
    `;

    if (!assignment) {
      return res.status(404).json({ error: 'No active assignment found' });
    }

    //  Check if user already submitted
    const [submission] = await sql`
      SELECT *
      FROM submissions
      WHERE assignment_id = ${assignment.id}
        AND user_id = ${req.user.id}
      LIMIT 1;
    `;

    if (submission) {
      return res.status(200).json({
        message: 'No current assignment',
        assignment: null
      });
    }

    res.json({
      assignment,
      submitted: false,
      submission: null
    });
  } catch (err) {
    console.error('Get current assignment error:', err);
    res.status(500).json({ error: 'Failed to fetch assignment' });
  }
});


// User submits assignment
app.post('/assignment', authenticateToken, upload.single('file'), async (req, res) => {
  const { topic, is_group, group_members, email, link } = req.body;

  if (!topic || !email || (!req.file && !link))
    return res.status(400).json({ error: 'Required fields missing' });

  try {
    // ✅ Get the latest assignment for the user’s track & topic
    const [assignment] = await sql`
      SELECT * FROM assignments
      WHERE track = ${req.user.track} AND topic = ${topic}
      ORDER BY date DESC, time DESC
      LIMIT 1;
    `;
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    // ✅ Check deadline
    if (assignment.deadline && new Date() > new Date(assignment.deadline)) {
      return res.status(400).json({ error: 'Deadline has passed. Submission not allowed.' });
    }

    // ✅ Validate submission type
    let allowedTypes = assignment.allowed_submission_types;
    if (typeof allowedTypes === 'string') {
      try { allowedTypes = JSON.parse(allowedTypes); } catch { allowedTypes = [allowedTypes]; }
    }
    if (!Array.isArray(allowedTypes)) allowedTypes = [];

    if (req.file && !allowedTypes.includes('file')) {
      return res.status(400).json({ error: 'File submission not allowed for this assignment' });
    }
    if (link && !allowedTypes.includes('link')) {
      return res.status(400).json({ error: 'Link submission not allowed for this assignment' });
    }

    // ✅ Handle submission
    let submission = null;
    if (req.file) submission = await uploadImage(req.file);
    else if (link) submission = link;

    // ✅ Insert into submissions (not assignments)
    const [submitted] = await sql`
      INSERT INTO submissions (
        assignment_id, user_id, track, topic, date, time, is_group, group_members, email, submission
      ) VALUES (
        ${assignment.id}, ${req.user.id}, ${req.user.track}, ${topic}, CURRENT_DATE, CURRENT_TIME,
        ${is_group || false}, ${group_members || []}, ${email}, ${submission}
      )
      RETURNING *;
    `;

    res.status(201).json({ submission: submitted });
  } catch (err) {
    console.error('Submit assignment error:', err);
    res.status(500).json({ error: 'Assignment submission failed' });
  }
});

// GET /user/submissions – user sees their own submission history with assignment question
app.get('/user/submissions', authenticateToken, async (req, res) => {
  try {
    const { track, startDate, endDate, limit = 20, offset = 0 } = req.query;
    const userId = req.user.id;

    let baseQuery = sql`
      FROM submissions s
      JOIN assignments a ON s.assignment_id = a.id
      WHERE s.user_id = ${userId}
    `;

    if (track) baseQuery = sql`${baseQuery} AND LOWER(a.track) = LOWER(${track})`;
    if (startDate && endDate) baseQuery = sql`${baseQuery} AND s.date BETWEEN ${startDate} AND ${endDate}`;
    else if (startDate) baseQuery = sql`${baseQuery} AND s.date >= ${startDate}`;
    else if (endDate) baseQuery = sql`${baseQuery} AND s.date <= ${endDate}`;

    // Get paginated data including question
    const dataQuery = sql`
      SELECT 
        s.*, 
        a.topic, 
        a.track, 
        a.deadline, 
        a.question
      ${baseQuery}
      ORDER BY s.date DESC, s.time DESC
      LIMIT ${limit} OFFSET ${offset};
    `;

    // Get total count
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [submissions, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ submissions, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    console.error('Get user submission history error:', err);
    res.status(500).json({ error: 'Failed to fetch submission history' });
  }
});



// --- CHECK-IN / OUT ---
app.post('/checkin', authenticateToken, async (req, res) => {
  try {
    // Remove daily check: allow multiple check-ins per day
    const [checkin] = await sql`
      INSERT INTO checkins (
        user_id, name, track, date, checkin_time, status
      ) VALUES (
        ${req.user.id}, ${req.user.name}, ${req.user.track}, CURRENT_DATE, CURRENT_TIME, 'pending'
      )
      RETURNING *;
    `;

    res.status(201).json({ checkin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Check-in failed' });
  }
});

app.post('/checkout', authenticateToken, async (req, res) => {
  try {
    // Find the latest check-in without a checkout_time for this user
    const [checkin] = await sql`
      SELECT * FROM checkins
      WHERE user_id = ${req.user.id} AND checkout_time IS NULL
      ORDER BY date DESC, checkin_time DESC
      LIMIT 1;
    `;

    if (!checkin) {
      return res.status(400).json({ error: 'No active check-in found' });
    }

    // Only allow checkout if status is 'approved'
    if (checkin.status !== 'approved') {
      return res.status(400).json({ error: 'You cannot check out unless your check-in is approved.' });
    }

    const now = new Date();

    // Parse today's check-in time into a Date object
    const [hours, minutes] = checkin.checkin_time.split(':').map(Number);
    const checkinDate = new Date();
    checkinDate.setUTCHours(hours, minutes, 0, 0); // assuming checkin_time is in UTC

    const durationMs = now - checkinDate;
    const durationMinutes = Math.floor(durationMs / 60000);

    const [checkout] = await sql`
      UPDATE checkins
      SET checkout_time = CURRENT_TIME,
          duration = ${durationMinutes},
          status = 'checked-out'
      WHERE id = ${checkin.id}
      RETURNING *;
    `;

    const readableDuration = `${Math.floor(durationMinutes / 60)}h ${durationMinutes % 60}m`;

    res.json({ checkout, readableDuration });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});


app.get('/checkin/history', authenticateToken, async (req, res) => {
  try {
    const history = await sql`
      SELECT * FROM checkins
      WHERE user_id = ${req.user.id}
      ORDER BY date DESC, checkin_time DESC;
    `;

    const formattedHistory = history.map((entry) => {
      let durationFormatted = null;

      if (entry.duration && typeof entry.duration === 'number') {
        const hours = Math.floor(entry.duration / 60);
        const mins = entry.duration % 60;
        durationFormatted = `${hours}h ${mins}m`;
      } else if (typeof entry.duration === 'string') {
        durationFormatted = entry.duration; // Fallback if duration is already formatted as string
      }

      return { ...entry, durationFormatted };
    });

    res.json({ history: formattedHistory });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});




// --- ADMIN ---

// GET ALL USERS 
app.get('/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const { track, name, limit = 20, offset = 0 } = req.query;

    let baseQuery = sql`FROM users WHERE 1=1`;

    if (track) baseQuery = sql`${baseQuery} AND LOWER(track) = LOWER(${track})`;
    if (name) baseQuery = sql`${baseQuery} AND LOWER(name) LIKE LOWER(${`%${name}%`})`;

    // Get data
    const dataQuery = sql`
      SELECT * ${baseQuery}
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${offset};
    `;

    // Get total count
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [users, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ users, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});



// Admin creates assignment
app.post('/admin/assignments', authenticateToken, upload.single('question_file'), async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  const {
    track,
    is_group,
    group_members,  // array of user IDs from the form
    date,
    time,
    topic,
    question_text,
    question_link,
    allowed_submission_types,
    deadline
  } = req.body;

  if (!track || !topic) {
    return res.status(400).json({ error: 'Track and topic are required' });
  }

  try {
    // Handle question
    let question = null;
    if (req.file) {
      question = await uploadImage(req.file);
    } else if (question_link) {
      question = question_link;
    } else if (question_text) {
      question = question_text;
    }

    // Parse allowed types
    let allowedTypes = allowed_submission_types;
    if (typeof allowedTypes === 'string') {
      allowedTypes = allowedTypes.split(',').map(t => t.trim());
    }

    // Insert assignment
    const [assignment] = await sql`
      INSERT INTO assignments (
        track, date, is_group, group_members, time,
        topic, question, allowed_submission_types, deadline
      )
      VALUES (
        ${track},
        ${date || new Date().toISOString().slice(0, 10)},
        ${is_group || false},
        ${is_group && group_members ? JSON.stringify(group_members) : null},
        ${time || new Date().toISOString().slice(11, 19)},
        ${topic},
        ${question},
        ${JSON.stringify(allowedTypes)},
        ${deadline || null}
      )
      RETURNING *;
    `;

    res.status(201).json({ assignment });
  } catch (err) {
    console.error('Admin create assignment error:', err);
    res.status(500).json({ error: 'Failed to create assignment' });
  }
});



// Admin extends assignment deadline
app.put('/admin/assignments/:id/deadline', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { id } = req.params;
  const { new_deadline } = req.body;

  if (!new_deadline) return res.status(400).json({ error: 'New deadline required' });

  try {
    const [updated] = await sql`
      UPDATE assignments
      SET deadline = ${new_deadline}
      WHERE id = ${id}
      RETURNING *;
    `;
    if (!updated) return res.status(404).json({ error: 'Assignment not found' });

    res.json({ assignment: updated });
  } catch (err) {
    console.error('Extend deadline error:', err);
    res.status(500).json({ error: 'Failed to extend deadline' });
  }
});


// GET ALL ASSIGNMENTS – Admin sees all assignments
app.get('/admin/assignments', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const { track, startDate, endDate, limit = 20, offset = 0 } = req.query;

    let baseQuery = sql`FROM assignments WHERE 1=1`;

    if (track) baseQuery = sql`${baseQuery} AND LOWER(track) = LOWER(${track})`;
    if (startDate && endDate) baseQuery = sql`${baseQuery} AND date BETWEEN ${startDate} AND ${endDate}`;
    else if (startDate) baseQuery = sql`${baseQuery} AND date >= ${startDate}`;
    else if (endDate) baseQuery = sql`${baseQuery} AND date <= ${endDate}`;

    const dataQuery = sql`
      SELECT * ${baseQuery}
      ORDER BY date DESC, time DESC
      LIMIT ${limit} OFFSET ${offset};
    `;
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [assignments, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ assignments, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    console.error('Get all assignments error:', err);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});


// GET /admin/assignments/:id – Admin sees assignment + all submissions under it
app.get('/admin/assignments/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const { track, startDate, endDate, limit = 20, offset = 0 } = req.query;
    const { id } = req.params;

    const [assignment] = await sql`SELECT * FROM assignments WHERE id = ${id}`;
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    let baseQuery = sql`
      FROM submissions s
      JOIN users u ON s.user_id = u.id
      WHERE s.assignment_id = ${id}
    `;

    if (track) baseQuery = sql`${baseQuery} AND LOWER(u.track) = LOWER(${track})`;
    if (startDate && endDate) baseQuery = sql`${baseQuery} AND s.date BETWEEN ${startDate} AND ${endDate}`;
    else if (startDate) baseQuery = sql`${baseQuery} AND s.date >= ${startDate}`;
    else if (endDate) baseQuery = sql`${baseQuery} AND s.date <= ${endDate}`;

    const dataQuery = sql`
      SELECT s.*, u.name, u.email, u.track ${baseQuery}
      ORDER BY s.date DESC, s.time DESC
      LIMIT ${limit} OFFSET ${offset};
    `;
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [submissions, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ assignment, submissions, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    console.error('Get assignment by ID error:', err);
    res.status(500).json({ error: 'Failed to fetch assignment and submissions' });
  }
});



// GET /admin/submissions – Admin sees all submissions across all assignments
app.get('/admin/submissions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const { track, startDate, endDate, assignmentId, limit = 20, offset = 0 } = req.query;

    let baseQuery = sql`
      FROM submissions s
      JOIN assignments a ON s.assignment_id = a.id
      JOIN users u ON s.user_id = u.id
      WHERE 1=1
    `;

    if (assignmentId) baseQuery = sql`${baseQuery} AND s.assignment_id = ${assignmentId}`;
    if (track) baseQuery = sql`${baseQuery} AND LOWER(u.track) = LOWER(${track})`;
    if (startDate && endDate) baseQuery = sql`${baseQuery} AND s.date BETWEEN ${startDate} AND ${endDate}`;
    else if (startDate) baseQuery = sql`${baseQuery} AND s.date >= ${startDate}`;
    else if (endDate) baseQuery = sql`${baseQuery} AND s.date <= ${endDate}`;

    const dataQuery = sql`
      SELECT s.*, a.topic, a.track, a.deadline, u.name, u.email, u.track AS user_track
      ${baseQuery}
      ORDER BY s.date DESC, s.time DESC
      LIMIT ${limit} OFFSET ${offset};
    `;
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [submissions, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ submissions, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    console.error('Get all submissions error:', err);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});


// get all check-ins for admin with optional filters
app.get('/admin/checkins', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied. Admins only.' });

  try {
    const { status, name, limit = 20, offset = 0 } = req.query;
    const validStatuses = ['pending', 'approved', 'rejected'];

    let baseQuery = sql`FROM checkins WHERE 1=1`;

    if (status) {
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status filter' });
      }
      baseQuery = sql`${baseQuery} AND status = ${status}`;
    }
    if (name) baseQuery = sql`${baseQuery} AND LOWER(name) LIKE LOWER(${`%${name}%`})`;

    const dataQuery = sql`
      SELECT * ${baseQuery}
      ORDER BY date DESC, checkin_time DESC
      LIMIT ${limit} OFFSET ${offset};
    `;
    const countQuery = sql`SELECT COUNT(*) ${baseQuery};`;

    const [checkins, [countResult]] = await Promise.all([dataQuery, countQuery]);
    const totalCount = Number(countResult.count);

    res.json({ checkins, totalCount, limit: Number(limit), offset: Number(offset) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch check-ins' });
  }
});


// Admin updates check-in status + logs attendance
app.put('/admin/checkin/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admins only.' });
    }

    const { status } = req.body;
    const validStatuses = ['pending', 'approved', 'rejected'];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const [checkin] = await sql`
      SELECT * FROM checkins WHERE id = ${req.params.id}
    `;

    if (!checkin) {
      return res.status(404).json({ error: 'Check-in record not found' });
    }

    // === If rejected → clear checkin & related attendance ===
    if (status === 'rejected') {
      await sql`
        DELETE FROM checkins
        WHERE id = ${req.params.id};
      `;

      await sql`
        DELETE FROM attendance
        WHERE user_id = ${checkin.user_id} AND date = ${checkin.date};
      `;

      return res.json({ message: 'Check-in rejected and records cleared' });
    }

    // === If approved → update and log attendance ===
    const [updated] = await sql`
      UPDATE checkins
      SET status = ${status}
      WHERE id = ${req.params.id}
      RETURNING *;
    `;

    if (status === 'approved') {
      const [user] = await sql`SELECT * FROM users WHERE id = ${updated.user_id}`;
      if (user) {
        await sql`
          INSERT INTO attendance (user_id, name, email, track, date)
          VALUES (${user.id}, ${user.name}, ${user.email}, ${user.track}, ${updated.date})
          ON CONFLICT (user_id, date) DO NOTHING;
        `;
      }
    }

    res.json({ message: 'Status updated', checkin: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});


// GET /admin/attendance/csv
app.get('/admin/attendance/csv', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admins only.' });
  }

  try {
    const { date } = req.query;
    const attendance = await sql`
      SELECT * FROM attendance
      WHERE date = ${date || new Date().toISOString().slice(0, 10)}
      ORDER BY track, name;
    `;

    if (!attendance.length) {
      return res.status(404).json({ error: 'No attendance records found' });
    }

    const fields = ['id', 'user_id', 'name', 'email', 'track', 'date'];
    const parser = new Parser({ fields });
    const csv = parser.parse(attendance);

    res.header('Content-Type', 'text/csv');
    res.attachment(`attendance_${date || 'today'}.csv`);
    res.send(csv);
  } catch (err) {
    console.error('Download attendance error:', err);
    res.status(500).json({ error: 'Failed to generate attendance CSV' });
  }
});

// GET /admin/attendance – view attendance list in JSON
app.get('/admin/attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admins only.' });
  }

  try {
    const { date, track } = req.query;

    let query = sql`
      SELECT * FROM attendance
      WHERE 1=1
    `;

    if (date) {
      query = sql`${query} AND date = ${date}`;
    } else {
      // default to today
      query = sql`${query} AND date = ${new Date().toISOString().slice(0, 10)}`;
    }

    if (track) {
      query = sql`${query} AND LOWER(track) = LOWER(${track})`;
    }

    query = sql`${query} ORDER BY track, name`;

    const records = await query;

    res.json({ attendance: records });
  } catch (err) {
    console.error('Get attendance error:', err);
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});


// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
