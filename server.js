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
  res.send('Welcome to Guru IT Website');
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

// Get current assignment for user based on track
app.get('/current-assignment', authenticateToken, async (req, res) => {
  try {
    console.log("User track:", req.user.track); // debug

    const [assignment] = await sql`
      SELECT * FROM assignments
      WHERE LOWER(track) = LOWER(${req.user.track})
      ORDER BY created_at DESC
      LIMIT 1;
    `;

    if (!assignment) {
      return res.status(200).json({ message: 'No assignments found for your track' });
    }

    res.json({ assignment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get assignment' });
  }
});


// User submits assignment, validate allowed submission type
app.post('/assignment', authenticateToken, upload.single('file'), async (req, res) => {
  const { topic, is_group, group_members, email, link } = req.body;

  if (!topic || !email || (!req.file && !link))
    return res.status(400).json({ error: 'Required fields missing' });

  try {
    // Get the latest assignment for the user's track and topic
    const [assignment] = await sql`
      SELECT * FROM assignments WHERE track = ${req.user.track} AND topic = ${topic} ORDER BY date DESC, time DESC LIMIT 1;
    `;
    if (!assignment) return res.status(404).json({ error: 'Assignment not found for your track and topic' });

    let allowedTypes = assignment.allowed_submission_types;
    if (typeof allowedTypes === 'string') {
      try { allowedTypes = JSON.parse(allowedTypes); } catch { allowedTypes = [allowedTypes]; }
    }
    if (!Array.isArray(allowedTypes)) allowedTypes = [];

    // Validate submission type
    if (req.file && !allowedTypes.includes('file')) {
      return res.status(400).json({ error: 'File submission not allowed for this assignment' });
    }
    if (link && !allowedTypes.includes('link')) {
      return res.status(400).json({ error: 'Link submission not allowed for this assignment' });
    }
    if (!req.file && !link) {
      return res.status(400).json({ error: 'No submission provided' });
    }

    let submission = null;
    if (req.file) {
      submission = await uploadImage(req.file);
    } else if (link) {
      submission = link;
    }

    const [submitted] = await sql`
      INSERT INTO assignments (
        user_id, track, topic, date, time, is_group, group_members, email, submission
      ) VALUES (
        ${req.user.id}, ${req.user.track}, ${topic}, CURRENT_DATE, CURRENT_TIME,
        ${is_group || false}, ${group_members || []}, ${email}, ${submission}
      )
      RETURNING *;
    `;

    res.status(201).json({ assignment: submitted });
  } catch (err) {
    res.status(500).json({ error: 'Assignment submission failed' });
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

// get all users
app.get('/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const { track } = req.query;
    let users;

    if (track) {
      users = await sql`SELECT * FROM users WHERE LOWER(track) = LOWER(${track}) ORDER BY created_at DESC;`;
    } else {
      users = await sql`SELECT * FROM users ORDER BY created_at DESC;`;
    }

    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin gives assignment to a track (not individual user)
app.post('/admin/assignments', authenticateToken, upload.single('question_file'), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { track, date, is_group, time, topic, question_text, question_link, allowed_submission_types, emails } = req.body;
  if (!track || !topic) return res.status(400).json({ error: 'Required fields missing' });

  try {
    // Accept all: question_text, question_link, file (image/pdf)
    let question = {};

    if (question_text) question.text = question_text || null;
    if (question_link) question.link = question_link || null;
    if (req.file) question.file = await uploadImage(req.file) || null;

    // If nothing provided, error
    if (!question.text && !question.link && !question.file) {
      return res.status(400).json({ error: 'Provide at least one of question_text, question_link, or file' });
    }

    // allowed_submission_types should be an array or comma-separated string
    let allowedTypes = allowed_submission_types;
    if (typeof allowedTypes === 'string') {
      allowedTypes = allowedTypes.split(',').map(t => t.trim());
    }

    // If emails provided, assign to specific users in the track
    if (emails) {
      let emailList = emails;
      if (typeof emails === 'string') {
        emailList = emails.split(',').map(e => e.trim());
      }
      // Get users in track with those emails
      const users = await sql`
        SELECT id FROM users WHERE LOWER(track) = LOWER(${track}) AND email = ANY(${emailList})
      `;
      if (!users.length) {
        return res.status(400).json({ error: 'No users found for provided emails in this track' });
      }
      // Insert assignment for each user
      const inserted = [];
      for (const user of users) {
        const [result] = await sql`
          INSERT INTO assignments (track, date, is_group, time, topic, question, allowed_submission_types, user_id)
          VALUES (
            ${track},
            ${date || new Date().toISOString().slice(0, 10)},
            ${is_group || false},
            ${time || new Date().toISOString().slice(11, 19)},
            ${topic},
            ${JSON.stringify(question)},
            ${JSON.stringify(allowedTypes)},
            ${user.id}
          )
          RETURNING *;
        `;
        inserted.push(result);
      }
      return res.status(201).json({ assignments: inserted });
    } else {
      // Assign to all users in the track (no user_id, or user_id = null)
      const result = await sql`
        INSERT INTO assignments (track, date, is_group, time, topic, question, allowed_submission_types)
        VALUES (
          ${track},
          ${date || new Date().toISOString().slice(0, 10)},
          ${is_group || false},
          ${time || new Date().toISOString().slice(11, 19)},
          ${topic},
          ${JSON.stringify(question)},
          ${JSON.stringify(allowedTypes)}
        )
        RETURNING *;
      `;
      return res.status(201).json({ assignment: result[0] });
    }
  } catch (err) {
    console.error('Admin create assignment error:', err);   
    res.status(500).json({ error: 'Failed to create assignment' });
  }
});

// GET /admin/assignments – Admin sees all assignments
app.get('/admin/assignments', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const result = await sql`
      SELECT * FROM assignments ORDER BY date DESC, time DESC;
    `;
    res.json({ assignments: result });
  } catch (err) {
    console.error('Get all assignments error:', err);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

//  Admin updates check-in status
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

    const [updated] = await sql`
      UPDATE checkins
      SET status = ${status}
      WHERE id = ${req.params.id}
      RETURNING *;
    `;

    if (!updated) {
      return res.status(404).json({ error: 'Check-in record not found' });
    }

    res.json({ message: 'Status updated', checkin: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// get assignments by id
app.get('/admin/assignments/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const [assignment] = await sql`
      SELECT * FROM assignments WHERE id = ${req.params.id};
    `;

    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    res.json({ assignment });
  } catch (err) {
    console.error('Get assignment by ID error:', err);
    res.status(500).json({ error: 'Failed to fetch assignment' });
  }
});

// get all check-ins for admin
app.get('/admin/checkins', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admins only.' });
    }

    const { status } = req.query;
    const validStatuses = ['pending', 'approved', 'rejected'];

    let checkins;

    if (status) {
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status filter' });
      }

      checkins = await sql`
        SELECT * FROM checkins
        WHERE status = ${status}
        ORDER BY date DESC, checkin_time DESC;
      `;
    } else {
      checkins = await sql`
        SELECT * FROM checkins
        ORDER BY date DESC, checkin_time DESC;
      `;
    }

    res.json({ checkins });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch check-ins' });
  }
});

// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
