const { pool } = require('../config/db');


async function logAction({ userId, action, resource, ip, metadata }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, resource, ip_address, metadata)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId || null, action, resource || null, ip || null, metadata ? JSON.stringify(metadata) : null]
    );
  } catch (err) {
    // Audit logging must never crash the request it's observing, but a failure here
    // is itself worth knowing about in real operation (e.g. ship to stderr/monitoring).
    // eslint-disable-next-line no-console
    console.error('Failed to write audit log', err);
  }
}

module.exports = { logAction };
