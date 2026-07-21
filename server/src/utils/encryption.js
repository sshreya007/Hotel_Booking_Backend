const crypto = require('crypto');

// AES-256-GCM chosen because it's authenticated encryption: it protects confidentiality
// AND integrity (tampered ciphertext fails to decrypt rather than silently returning
// garbage). Key comes from FIELD_ENCRYPTION_KEY env var (32 bytes / 64 hex chars) —
// in production this should come from a real KMS (AWS KMS / Vault) rather than a
// plain env var; document that tradeoff in your report.
const ALGO = 'aes-256-gcm';

function getKey() {
  const hex = process.env.FIELD_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('FIELD_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypt a plaintext string. Returns a JSON string safe to store in a TEXT column.
 */
function encryptField(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return JSON.stringify({
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
  });
}

/**
 * Decrypt a value previously produced by encryptField.
 */
function decryptField(payload) {
  if (!payload) return null;
  const { iv, tag, data } = JSON.parse(payload);
  const decipher = crypto.createDecipheriv(ALGO, getKey(), Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(data, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

module.exports = { encryptField, decryptField };
