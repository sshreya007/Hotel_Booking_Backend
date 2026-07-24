const { safeRouter } = require('../utils/safeRouter');
const Stripe = require('stripe');
const { z } = require('zod');

const { pool } = require('../config/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { requireBookingOwnership } = require('../middleware/ownership');
const { apiLimiter } = require('../middleware/rateLimiter');
const { logAction } = require('../middleware/auditLog');

const router = safeRouter();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const HOLD_MINUTES = 10;

const holdSchema = z.object({
  roomId: z.string().uuid(),
  checkIn: z.string(), // ISO date
  checkOut: z.string(),
  guests: z.number().int().positive().max(20),
});

// ---- Step 1: hold a room --------------------------------------------------
// Runs inside a single DB transaction so the availability check and the insert
// happen atomically — this is what prevents two guests both "winning" the same
// room in a race condition (classic TOCTOU bug if done as two separate queries).
router.post('/hold', apiLimiter, requireAuth, requireRole('guest'), async (req, res) => {
  const parsed = holdSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input.', details: parsed.error.issues });
  }
  const { roomId, checkIn, checkOut, guests } = parsed.data;

  if (new Date(checkOut) <= new Date(checkIn)) {
    return res.status(400).json({ error: 'Check-out must be after check-in.' });
  }
  if (new Date(checkIn) < new Date(new Date().toDateString())) {
    return res.status(400).json({ error: 'Check-in cannot be in the past.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const roomResult = await client.query(
      'SELECT id, price_per_night, max_guests FROM rooms WHERE id = $1 FOR UPDATE',
      [roomId]
    );
    if (roomResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Room not found.' });
    }
    const room = roomResult.rows[0];
    if (guests > room.max_guests) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `This room allows a maximum of ${room.max_guests} guests.` });
    }

    // Overlap check against any currently held or confirmed booking for this room.
    // The GIST index in schema.sql backs this and also enforces it at the DB level.
    const overlap = await client.query(
      `SELECT id FROM bookings
       WHERE room_id = $1
         AND status IN ('held', 'confirmed')
         AND daterange(check_in, check_out, '[)') && daterange($2::date, $3::date, '[)')
         AND (status != 'held' OR hold_expires_at > now())`,
      [roomId, checkIn, checkOut]
    );
    if (overlap.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Room is not available for these dates.' });
    }

    const nights = Math.round(
      (new Date(checkOut) - new Date(checkIn)) / (1000 * 60 * 60 * 24)
    );
    // Total price is ALWAYS computed server-side from the room's stored price —
    // never accept a client-supplied price. This is the main defense against
    // price-tampering / mass-assignment style attacks on this endpoint.
    const totalPrice = (Number(room.price_per_night) * nights).toFixed(2);

    const { rows } = await client.query(
      `INSERT INTO bookings (room_id, guest_id, check_in, check_out, status, total_price, hold_expires_at)
       VALUES ($1, $2, $3, $4, 'held', $5, now() + interval '${HOLD_MINUTES} minutes')
       RETURNING id, total_price, hold_expires_at`,
      [roomId, req.user.id, checkIn, checkOut, totalPrice]
    );

    await client.query('COMMIT');
    await logAction({ userId: req.user.id, action: 'booking_held', resource: `booking:${rows[0].id}`, ip: req.ip });

    return res.status(201).json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(500).json({ error: 'Could not hold room. Please try again.' });
  } finally {
    client.release();
  }
});

// ---- Step 2: create a Stripe PaymentIntent for a held booking ------------
router.post('/:id/pay', apiLimiter, requireAuth, requireRole('guest'), requireBookingOwnership(), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, total_price, status, hold_expires_at FROM bookings WHERE id = $1`,
    [req.params.id]
  );
  const booking = rows[0];

  if (booking.status !== 'held' || new Date(booking.hold_expires_at) < new Date()) {
    return res.status(410).json({ error: 'Hold has expired. Please search again.' });
  }

  let paymentIntent;
  try {
    paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(Number(booking.total_price) * 100), // Stripe uses smallest currency unit
      currency: 'usd',
      metadata: { bookingId: booking.id },
    });
  } catch (err) {
    // Most commonly this means STRIPE_SECRET_KEY is missing, a placeholder,
    // or invalid — surface that clearly rather than a generic 500, since it's
    // a setup problem, not something the caller did wrong.
    // eslint-disable-next-line no-console
    console.error('Stripe paymentIntents.create failed:', err.message);
    return res.status(502).json({
      error: 'Payment could not be initiated. The payment provider is not configured correctly.',
    });
  }

  await pool.query(
    `INSERT INTO payments (booking_id, stripe_payment_id, amount, status)
     VALUES ($1, $2, $3, 'pending')`,
    [booking.id, paymentIntent.id, booking.total_price]
  );

  return res.json({ clientSecret: paymentIntent.client_secret });
});

// ---- Step 3: Stripe webhook confirms/fails payment ------------------------
// Mounted separately in index.js with express.raw() BEFORE the json() body parser,
// because Stripe signature verification needs the raw request body bytes.
async function stripeWebhookHandler(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    // Verifying the signature is critical: without this, anyone who finds the
    // webhook URL could POST a fake "payment_intent.succeeded" event and get a
    // free confirmed booking.
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
  }

  const client = await pool.connect();
  try {
    if (event.type === 'payment_intent.succeeded') {
      const intent = event.data.object;
      const bookingId = intent.metadata.bookingId;

      await client.query('BEGIN');
      await client.query(`UPDATE payments SET status = 'succeeded' WHERE stripe_payment_id = $1`, [intent.id]);
      await client.query(
        `UPDATE bookings SET status = 'confirmed', hold_expires_at = NULL, updated_at = now()
         WHERE id = $1 AND status = 'held'`,
        [bookingId]
      );
      await client.query('COMMIT');
      await logAction({ action: 'booking_confirmed', resource: `booking:${bookingId}` });
    } else if (event.type === 'payment_intent.payment_failed') {
      const intent = event.data.object;
      await client.query('BEGIN');
      await client.query(`UPDATE payments SET status = 'failed' WHERE stripe_payment_id = $1`, [intent.id]);
      // Release the hold immediately so someone else can book the room rather than
      // waiting out the full 10-minute hold window.
      await client.query(
        `UPDATE bookings SET status = 'expired', hold_expires_at = NULL WHERE id = $1 AND status = 'held'`,
        [intent.metadata.bookingId]
      );
      await client.query('COMMIT');
      await logAction({ action: 'booking_payment_failed', resource: `booking:${intent.metadata.bookingId}` });
    }
    return res.json({ received: true });
  } catch (err) {
    await client.query('ROLLBACK');
    // eslint-disable-next-line no-console
    console.error('Webhook processing error', err);
    return res.status(500).json({ error: 'Webhook processing failed.' });
  } finally {
    client.release();
  }
}

// ---- List my own bookings --------------------------------------------------
// No :id param here at all — it's always scoped to req.user.id from the verified
// JWT, so there's no ID for an attacker to tamper with in the first place.
router.get('/mine', requireAuth, requireRole('guest'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.id, b.check_in, b.check_out, b.status, b.total_price,
            r.room_number, r.room_type, h.name AS hotel_name
     FROM bookings b
     JOIN rooms r ON r.id = b.room_id
     JOIN hotels h ON h.id = r.hotel_id
     WHERE b.guest_id = $1
     ORDER BY b.check_in DESC`,
    [req.user.id]
  );
  return res.json(rows);
});

// ---- Cancel / view --------------------------------------------------------
router.get('/:id', requireAuth, requireBookingOwnership(), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.id, b.check_in, b.check_out, b.status, b.total_price, r.room_number, r.room_type
     FROM bookings b JOIN rooms r ON r.id = b.room_id WHERE b.id = $1`,
    [req.params.id]
  );
  return res.json(rows[0]);
});

router.post('/:id/cancel', apiLimiter, requireAuth, requireBookingOwnership(), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, status FROM bookings WHERE id = $1 FOR UPDATE`,
      [req.params.id]
    );
    if (rows[0].status !== 'confirmed') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Only confirmed bookings can be cancelled.' });
    }

    await client.query(`UPDATE bookings SET status = 'cancelled', updated_at = now() WHERE id = $1`, [req.params.id]);

    const payment = await client.query(
      `SELECT stripe_payment_id, amount FROM payments WHERE booking_id = $1 AND status = 'succeeded'`,
      [req.params.id]
    );
    if (payment.rows.length > 0) {
      await stripe.refunds.create({ payment_intent: payment.rows[0].stripe_payment_id });
      await client.query(`UPDATE payments SET status = 'refunded' WHERE booking_id = $1`, [req.params.id]);
    }

    await client.query('COMMIT');
    await logAction({ userId: req.user.id, action: 'booking_cancelled', resource: `booking:${req.params.id}`, ip: req.ip });
    return res.json({ message: 'Booking cancelled and refunded if applicable.' });
  } catch (err) {
    await client.query('ROLLBACK');
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(500).json({ error: 'Cancellation failed. No changes were made.' });
  } finally {
    client.release();
  }
});

module.exports = { router, stripeWebhookHandler };
