const { safeRouter } = require('../utils/safeRouter');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const { z } = require('zod');

const { pool } = require('../config/db');
const { checkPasswordPolicy } = require('../utils/passwordPolicy');
const { encryptField } = require('../utils/encryption');
const { generateToken, hashToken } = require('../utils/tokens');
const { sendMail } = require('../utils/mailer');
const { authLimiter } = require('../middleware/rateLimiter');
const { requireAuth } = require('../middleware/auth');
const { logAction } = require('../middleware/auditLog');

const router = safeRouter();

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '7d';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1), // real strength check runs via checkPasswordPolicy below
  fullName: z.string().min(1).max(200),
  phone: z.string().optional(),
});

function issueTokens(user) {
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role, hotelId: user.hotel_id },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
  const refreshToken = jwt.sign(
    { sub: user.id, tokenType: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  );
  return { accessToken, refreshToken };
}

function setAuthCookies(res, { accessToken, refreshToken }) {
  const cookieBase = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  };
  res.cookie('accessToken', accessToken, { ...cookieBase, maxAge: 15 * 60 * 1000 });
  res.cookie('refreshToken', refreshToken, { ...cookieBase, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/auth/refresh' });
}

// ---- Register ----------------------------------------------------------
router.post('/register', authLimiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input.', details: parsed.error.issues });
  }
  const { email, password, fullName, phone } = parsed.data;

  const policy = checkPasswordPolicy(password);
  if (!policy.valid) {
    return res.status(400).json({ error: 'Password does not meet policy.', problems: policy.problems });
  }

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (existing.rows.length > 0) {
    // Generic message — don't confirm/deny which emails are registered.
    return res.status(400).json({ error: 'Unable to register with these details.' });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const contactEncrypted = phone ? encryptField(phone) : null;

  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash, full_name, contact_encrypted, role)
     VALUES ($1, $2, $3, $4, 'guest')
     RETURNING id, email, role, hotel_id`,
    [email.toLowerCase(), passwordHash, fullName, contactEncrypted]
  );

  await logAction({ userId: rows[0].id, action: 'user_registered', ip: req.ip });

  return res.status(201).json({ message: 'Registered. Please log in.' });
});

// ---- Login (step 1: password) ------------------------------------------
router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required.' });
  }

  const { rows } = await pool.query(
    `SELECT id, email, password_hash, role, hotel_id, mfa_enabled,
            failed_login_count, locked_until
     FROM users WHERE email = $1`,
    [email.toLowerCase()]
  );

  // Constant-shape response whether or not the user exists, to avoid user enumeration.
  const genericFail = () => res.status(401).json({ error: 'Invalid email or password.' });

  if (rows.length === 0) {
    await bcrypt.hash(password, BCRYPT_ROUNDS); // keep timing consistent
    return genericFail();
  }

  const user = rows[0];

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    await logAction({ userId: user.id, action: 'login_blocked_locked', ip: req.ip });
    return res.status(423).json({ error: 'Account temporarily locked due to repeated failed attempts.' });
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    const newCount = user.failed_login_count + 1;
    const lockedUntil = newCount >= MAX_FAILED_ATTEMPTS
      ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000)
      : null;

    await pool.query(
      `UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,
      [lockedUntil ? 0 : newCount, lockedUntil, user.id]
    );
    await logAction({ userId: user.id, action: 'login_failed', ip: req.ip, metadata: { attempt: newCount } });
    return genericFail();
  }

  // Correct password — reset failure counter.
  await pool.query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1', [user.id]);

  if (user.mfa_enabled) {
    // Issue a short-lived, single-purpose "MFA pending" token instead of a full
    // session — the caller must hit /auth/mfa/verify next.
    const mfaToken = jwt.sign({ sub: user.id, purpose: 'mfa_pending' }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: '5m',
    });
    await logAction({ userId: user.id, action: 'login_password_ok_awaiting_mfa', ip: req.ip });
    return res.json({ mfaRequired: true, mfaToken });
  }

  const tokens = issueTokens(user);
  setAuthCookies(res, tokens);
  await logAction({ userId: user.id, action: 'login_success', ip: req.ip });
  return res.json({ mfaRequired: false, role: user.role });
});

// ---- Login (step 2: TOTP verify) ---------------------------------------
router.post('/mfa/verify', authLimiter, async (req, res) => {
  const { mfaToken, code } = req.body || {};
  if (!mfaToken || !code) {
    return res.status(400).json({ error: 'mfaToken and code are required.' });
  }

  let payload;
  try {
    payload = jwt.verify(mfaToken, process.env.JWT_ACCESS_SECRET);
  } catch {
    return res.status(401).json({ error: 'MFA session expired. Please log in again.' });
  }
  if (payload.purpose !== 'mfa_pending') {
    return res.status(401).json({ error: 'Invalid MFA session.' });
  }

  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [payload.sub]);
  const user = rows[0];
  if (!user || !user.mfa_secret) {
    return res.status(400).json({ error: 'MFA not configured for this account.' });
  }

  const validCode = authenticator.check(code, user.mfa_secret);
  if (!validCode) {
    await logAction({ userId: user.id, action: 'mfa_failed', ip: req.ip });
    return res.status(401).json({ error: 'Invalid verification code.' });
  }

  const tokens = issueTokens(user);
  setAuthCookies(res, tokens);
  await logAction({ userId: user.id, action: 'mfa_success_login', ip: req.ip });
  return res.json({ role: user.role });
});

// ---- MFA setup (must already be logged in) ------------------------------
router.post('/mfa/setup', requireAuth, async (req, res) => {
  const secret = authenticator.generateSecret();
  await pool.query('UPDATE users SET mfa_secret = $1, mfa_enabled = FALSE WHERE id = $2', [
    secret,
    req.user.id,
  ]);

  const { rows } = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
  const otpauth = authenticator.keyuri(rows[0].email, 'SecureStay', secret);
  const qrDataUrl = await qrcode.toDataURL(otpauth);

  // mfa_enabled stays FALSE until the user confirms with a real code via /mfa/enable,
  // so a half-finished setup can't lock someone out.
  return res.json({ qrDataUrl, secret });
});

router.post('/mfa/enable', requireAuth, async (req, res) => {
  const { code } = req.body || {};
  const { rows } = await pool.query('SELECT mfa_secret FROM users WHERE id = $1', [req.user.id]);
  const secret = rows[0]?.mfa_secret;
  if (!secret || !authenticator.check(code, secret)) {
    return res.status(400).json({ error: 'Invalid code. MFA not enabled.' });
  }
  await pool.query('UPDATE users SET mfa_enabled = TRUE WHERE id = $1', [req.user.id]);
  await logAction({ userId: req.user.id, action: 'mfa_enabled', ip: req.ip });
  return res.json({ message: 'MFA enabled.' });
});

// ---- Refresh / logout ----------------------------------------------------
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token.' });

  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [payload.sub]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid session.' });

    const tokens = issueTokens(rows[0]);
    setAuthCookies(res, tokens);
    return res.json({ message: 'Refreshed.' });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token.' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken', { path: '/auth/refresh' });
  await logAction({ userId: req.user.id, action: 'logout', ip: req.ip });
  return res.json({ message: 'Logged out.' });
});

// ---- Forgot / reset password ----------------------------------------------
const RESET_TOKEN_TTL_MINUTES = 30;

router.post('/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  // Always return the same generic response whether or not the email exists —
  // this prevents an attacker from using this endpoint to enumerate registered
  // accounts.
  const genericResponse = () =>
    res.json({ message: 'If that email is registered, a reset link has been sent.' });

  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (rows.length === 0) return genericResponse();

  const userId = rows[0].id;
  const { raw, hash } = generateToken();

  await pool.query(
    `INSERT INTO auth_tokens (user_id, token_hash, purpose, expires_at)
     VALUES ($1, $2, 'password_reset', now() + interval '${RESET_TOKEN_TTL_MINUTES} minutes')`,
    [userId, hash]
  );

  const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${raw}`;
  await sendMail({
    to: email,
    subject: 'Reset your SecureStay password',
    text: `Click here to reset your password (expires in ${RESET_TOKEN_TTL_MINUTES} minutes): ${resetLink}`,
  });

  await logAction({ userId, action: 'password_reset_requested', ip: req.ip });
  return genericResponse();
});

router.post('/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and newPassword are required.' });
  }

  const policy = checkPasswordPolicy(newPassword);
  if (!policy.valid) {
    return res.status(400).json({ error: 'Password does not meet policy.', problems: policy.problems });
  }

  const tokenHash = hashToken(token);
  const { rows } = await pool.query(
    `SELECT id, user_id FROM auth_tokens
     WHERE token_hash = $1 AND purpose = 'password_reset' AND used_at IS NULL AND expires_at > now()`,
    [tokenHash]
  );
  if (rows.length === 0) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
  }

  const { id: tokenId, user_id: userId } = rows[0];
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

  await pool.query(
    `UPDATE users SET password_hash = $1, password_changed_at = now(),
            failed_login_count = 0, locked_until = NULL
     WHERE id = $2`,
    [passwordHash, userId]
  );
  await pool.query('UPDATE auth_tokens SET used_at = now() WHERE id = $1', [tokenId]);
  // Invalidate any other outstanding reset tokens for this user, in case several
  // were requested — only the one just used should ever be effective.
  await pool.query(
    `UPDATE auth_tokens SET used_at = now()
     WHERE user_id = $1 AND purpose = 'password_reset' AND used_at IS NULL`,
    [userId]
  );

  await logAction({ userId, action: 'password_reset_completed', ip: req.ip });
  return res.json({ message: 'Password has been reset. Please log in.' });
});

// ---- Passwordless "magic link" login (advanced/bonus feature) --------------
const MAGIC_LINK_TTL_MINUTES = 15;

router.post('/magic-link/request', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  const genericResponse = () =>
    res.json({ message: 'If that email is registered, a login link has been sent.' });

  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (rows.length === 0) return genericResponse();

  const userId = rows[0].id;
  const { raw, hash } = generateToken();

  await pool.query(
    `INSERT INTO auth_tokens (user_id, token_hash, purpose, expires_at)
     VALUES ($1, $2, 'magic_link', now() + interval '${MAGIC_LINK_TTL_MINUTES} minutes')`,
    [userId, hash]
  );

  const loginLink = `${process.env.APP_URL || 'http://localhost:3000'}/magic-login?token=${raw}`;
  await sendMail({
    to: email,
    subject: 'Your SecureStay login link',
    text: `Click here to log in (expires in ${MAGIC_LINK_TTL_MINUTES} minutes): ${loginLink}`,
  });

  await logAction({ userId, action: 'magic_link_requested', ip: req.ip });
  return genericResponse();
});

router.post('/magic-link/verify', authLimiter, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token is required.' });

  const tokenHash = hashToken(token);
  const { rows } = await pool.query(
    `SELECT id, user_id FROM auth_tokens
     WHERE token_hash = $1 AND purpose = 'magic_link' AND used_at IS NULL AND expires_at > now()`,
    [tokenHash]
  );
  if (rows.length === 0) {
    return res.status(400).json({ error: 'This login link is invalid or has expired.' });
  }

  const { id: tokenId, user_id: userId } = rows[0];
  await pool.query('UPDATE auth_tokens SET used_at = now() WHERE id = $1', [tokenId]);

  const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  const user = userResult.rows[0];

  // Proving email ownership via the link is treated as equivalent to a correct
  // password — but if the account has MFA enabled, that second factor is still
  // required, same as normal login. A magic link alone never bypasses MFA.
  if (user.mfa_enabled) {
    const mfaToken = jwt.sign({ sub: user.id, purpose: 'mfa_pending' }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: '5m',
    });
    await logAction({ userId: user.id, action: 'magic_link_used_awaiting_mfa', ip: req.ip });
    return res.json({ mfaRequired: true, mfaToken });
  }

  const tokens = issueTokens(user);
  setAuthCookies(res, tokens);
  await logAction({ userId: user.id, action: 'magic_link_login_success', ip: req.ip });
  return res.json({ mfaRequired: false, role: user.role });
});

module.exports = router;
