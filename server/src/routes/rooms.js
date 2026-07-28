const { safeRouter } = require('../utils/safeRouter');
const { z } = require('zod');

const { pool } = require('../config/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { logAction } = require('../middleware/auditLog');

const router = safeRouter();

// Public search — no auth required, but strictly read-only and parameterized.
router.get('/search', async (req, res) => {
  const checkIn = req.query.checkIn;
  const checkOut = req.query.checkOut;
  if (!checkIn || !checkOut) {
    return res.status(400).json({ error: 'checkIn and checkOut are required.' });
  }

  const { rows } = await pool.query(
    `SELECT r.id, r.room_number, r.room_type, r.price_per_night, r.max_guests,
            h.id AS hotel_id, h.name AS hotel_name, h.address, h.description AS hotel_description
     FROM rooms r
     JOIN hotels h ON h.id = r.hotel_id
     WHERE r.id NOT IN (
       SELECT room_id FROM bookings
       WHERE status IN ('held', 'confirmed')
         AND daterange(check_in, check_out, '[)') && daterange($1::date, $2::date, '[)')
         AND (status != 'held' OR hold_expires_at > now())
     )`,
    [checkIn, checkOut]
  );
  return res.json(rows);
});

const roomSchema = z.object({
  roomNumber: z.string().min(1).max(20),
  roomType: z.string().min(1).max(50),
  pricePerNight: z.number().positive(),
  maxGuests: z.number().int().positive().max(20),
});

// Staff can only create/edit rooms for THEIR OWN hotel — req.user.hotelId comes from

router.post('/', requireAuth, requireRole('staff', 'admin'), async (req, res) => {
  const parsed = roomSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input.', details: parsed.error.issues });
  }
  if (req.user.role === 'staff' && !req.user.hotelId) {
    return res.status(403).json({ error: 'Staff account is not assigned to a hotel.' });
  }

  const hotelId = req.user.role === 'admin' ? req.body.hotelId : req.user.hotelId;
  if (!hotelId) {
    return res.status(400).json({ error: 'hotelId is required for admin-created rooms.' });
  }

  const { roomNumber, roomType, pricePerNight, maxGuests } = parsed.data;
  const { rows } = await pool.query(
    `INSERT INTO rooms (hotel_id, room_number, room_type, price_per_night, max_guests)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [hotelId, roomNumber, roomType, pricePerNight, maxGuests]
  );

  await logAction({ userId: req.user.id, action: 'room_created', resource: `room:${rows[0].id}`, ip: req.ip });
  return res.status(201).json(rows[0]);
});

// List bookings for the caller's own hotel only — this is the multi-tenant IDOR

router.get('/my-hotel/bookings', requireAuth, requireRole('staff', 'admin'), async (req, res) => {
  const hotelId = req.user.role === 'admin' ? req.query.hotelId : req.user.hotelId;
  if (!hotelId) return res.status(400).json({ error: 'hotelId required.' });

  const { rows } = await pool.query(
    `SELECT b.id, b.check_in, b.check_out, b.status, b.total_price, r.room_number
     FROM bookings b
     JOIN rooms r ON r.id = b.room_id
     WHERE r.hotel_id = $1
     ORDER BY b.check_in DESC`,
    [hotelId]
  );
  return res.json(rows);
});

module.exports = router;
