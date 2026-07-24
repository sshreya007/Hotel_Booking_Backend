const { safeRouter } = require('../utils/safeRouter');
const { z } = require('zod');

const { pool } = require('../config/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { logAction } = require('../middleware/auditLog');

const router = safeRouter();

// Everything in this file requires an authenticated admin. Applied per-route (not
// with router.use) so it's explicit and easy to point to in the pentest write-up.

router.get('/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, role, hotel_id, mfa_enabled, created_at FROM users ORDER BY created_at DESC`
  );
  return res.json(rows);
});

const roleChangeSchema = z.object({
  role: z.enum(['guest', 'staff', 'admin']),
  hotelId: z.string().uuid().nullable().optional(),
});

// Privilege escalation guard: only an authenticated admin can reach this route at
// all (requireRole above), and we log every change with who made it and the before
// state, so any misuse is auditable after the fact.
router.patch('/users/:id/role', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = roleChangeSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input.', details: parsed.error.issues });
  }
  const { role, hotelId } = parsed.data;

  if (role === 'staff' && !hotelId) {
    return res.status(400).json({ error: 'hotelId is required when assigning the staff role.' });
  }

  const before = await pool.query('SELECT role, hotel_id FROM users WHERE id = $1', [req.params.id]);
  if (before.rows.length === 0) {
    return res.status(404).json({ error: 'User not found.' });
  }

  await pool.query('UPDATE users SET role = $1, hotel_id = $2 WHERE id = $3', [
    role,
    role === 'staff' ? hotelId : null,
    req.params.id,
  ]);

  await logAction({
    userId: req.user.id,
    action: 'role_changed',
    resource: `user:${req.params.id}`,
    ip: req.ip,
    metadata: { before: before.rows[0], after: { role, hotelId } },
  });

  return res.json({ message: 'Role updated.' });
});

router.get('/audit-logs', requireAuth, requireRole('admin'), async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const { rows } = await pool.query(
    `SELECT id, user_id, action, resource, ip_address, metadata, created_at
     FROM audit_logs ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
  return res.json(rows);
});

module.exports = router;
