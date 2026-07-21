const express = require('express');
const { z } = require('zod');

const { pool } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { encryptField, decryptField } = require('../utils/encryption');
const { logAction } = require('../middleware/auditLog');

const router = express.Router();

// Everything in this file operates ONLY on req.user.id (taken from the verified
// JWT), never on an :id param from the URL or body. That's deliberate: it's what
// makes mass-assignment / IDOR attacks impossible here — there is no "whose
// profile am I editing?" decision to get wrong, because it's always "mine".

// ---- View own profile ------------------------------------------------------
router.get('/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, full_name, contact_encrypted, role, mfa_enabled, created_at
     FROM users WHERE id = $1`,
    [req.user.id]
  );
  if (rows.length === 0) {
    return res.status(404).json({ error: 'User not found.' });
  }

  const user = rows[0];
  return res.json({
    id: user.id,
    email: user.email,
    fullName: user.full_name,
    // Decrypt only at the point of returning it to its own owner — never log or
    // pass the decrypted value anywhere else.
    phone: decryptField(user.contact_encrypted),
    role: user.role,
    mfaEnabled: user.mfa_enabled,
    createdAt: user.created_at,
  });
});

// ---- Edit own profile -------------------------------------------------------
// Explicit allow-list of editable fields via zod .strict() — any extra field in
// the request body (e.g. "role": "admin") is REJECTED outright rather than
// silently ignored, which is what stops a classic mass-assignment attack where
// someone stuffs privileged fields into a profile-update payload.
const profileUpdateSchema = z
  .object({
    fullName: z.string().min(1).max(200).optional(),
    phone: z.string().max(30).nullable().optional(),
  })
  .strict();

router.patch('/me', requireAuth, async (req, res) => {
  const parsed = profileUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input.', details: parsed.error.issues });
  }
  const { fullName, phone } = parsed.data;

  if (fullName === undefined && phone === undefined) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }

  const fields = [];
  const values = [];
  let i = 1;

  if (fullName !== undefined) {
    fields.push(`full_name = $${i++}`);
    values.push(fullName);
  }
  if (phone !== undefined) {
    fields.push(`contact_encrypted = $${i++}`);
    values.push(phone === null ? null : encryptField(phone));
  }
  values.push(req.user.id);

  await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${i}`, values);
  await logAction({ userId: req.user.id, action: 'profile_updated', ip: req.ip });

  return res.json({ message: 'Profile updated.' });
});

// ---- Export own data (privacy / data portability) ---------------------------
// Returns the user's own data as a downloadable JSON file. Deliberately excludes
// password_hash, mfa_secret, and any other users' data — this is a self-service
// export of exactly what this account owns, nothing more.
router.get('/export', requireAuth, async (req, res) => {
  const userResult = await pool.query(
    `SELECT id, email, full_name, contact_encrypted, role, created_at FROM users WHERE id = $1`,
    [req.user.id]
  );
  const bookingsResult = await pool.query(
    `SELECT b.id, b.check_in, b.check_out, b.status, b.total_price, r.room_number, r.room_type
     FROM bookings b JOIN rooms r ON r.id = b.room_id WHERE b.guest_id = $1`,
    [req.user.id]
  );

  const user = userResult.rows[0];
  const exportData = {
    profile: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      phone: decryptField(user.contact_encrypted),
      role: user.role,
      createdAt: user.created_at,
    },
    bookings: bookingsResult.rows,
    exportedAt: new Date().toISOString(),
  };

  await logAction({ userId: req.user.id, action: 'data_exported', ip: req.ip });

  res.setHeader('Content-Disposition', 'attachment; filename="securestay-data-export.json"');
  return res.json(exportData);
});

// ---- Import profile data -----------------------------------------------------
// Only re-imports the same safe, allow-listed fields as PATCH /me — this is
// intentionally NOT a generic "restore my account" endpoint. Accepting a full
// user object back in (including role, id, password_hash) would reopen the exact
// mass-assignment hole the edit endpoint above closes.
const profileImportSchema = z
  .object({
    profile: z
      .object({
        fullName: z.string().min(1).max(200).optional(),
        phone: z.string().max(30).nullable().optional(),
      })
      .strict(),
  })
  .strict();

router.post('/import', requireAuth, async (req, res) => {
  const parsed = profileImportSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid import file.', details: parsed.error.issues });
  }
  const { fullName, phone } = parsed.data.profile;

  const fields = [];
  const values = [];
  let i = 1;
  if (fullName !== undefined) {
    fields.push(`full_name = $${i++}`);
    values.push(fullName);
  }
  if (phone !== undefined) {
    fields.push(`contact_encrypted = $${i++}`);
    values.push(phone === null ? null : encryptField(phone));
  }
  if (fields.length === 0) {
    return res.status(400).json({ error: 'Import file contained no recognized fields.' });
  }
  values.push(req.user.id);

  await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${i}`, values);
  await logAction({ userId: req.user.id, action: 'profile_imported', ip: req.ip });

  return res.json({ message: 'Profile data imported.' });
});

module.exports = router;