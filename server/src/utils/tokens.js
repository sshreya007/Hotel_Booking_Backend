const crypto = require('crypto');

/**
 * Generates a random token for one-time-use links (password reset, magic link
 * login). Returns both the RAW token (put this in the emailed URL, never store
 * it) and its SHA-256 HASH (store only this in the database).
 *
 * This mirrors how you should treat passwords: if the auth_tokens table ever
 * leaked, an attacker would have hashes, not usable tokens.
 */
function generateToken() {
  const raw = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

module.exports = { generateToken, hashToken };
