const { pool } = require('../config/db');

/**
 * IDOR defense: given a route like GET /bookings/:id, this confirms the booking
 * actually belongs to the calling guest (or, for staff, belongs to their hotel)
 * BEFORE the route handler runs — never rely on "the frontend only shows your own
 * bookings" as a control, since the API itself must enforce it.
 *
 * This is deliberately its own middleware (rather than inline in each route) so it's
 * applied consistently and is easy to point to during the pentest write-up as your
 * IDOR mitigation.
 */
function requireBookingOwnership() {
  return async (req, res, next) => {
    const bookingId = req.params.id;
    const { rows } = await pool.query(
      `SELECT b.id, b.guest_id, r.hotel_id
       FROM bookings b
       JOIN rooms r ON r.id = b.room_id
       WHERE b.id = $1`,
      [bookingId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found.' });
    }

    const booking = rows[0];
    const { role, id: userId, hotelId } = req.user;

    const isOwnerGuest = role === 'guest' && booking.guest_id === userId;
    const isOwnerStaff = role === 'staff' && booking.hotel_id === hotelId;
    const isAdmin = role === 'admin';

    if (!isOwnerGuest && !isOwnerStaff && !isAdmin) {
      // Return 404 rather than 403 here so we don't leak "this booking exists but
      // isn't yours" to an attacker enumerating IDs.
      return res.status(404).json({ error: 'Booking not found.' });
    }

    req.booking = booking;
    return next();
  };
}

module.exports = { requireBookingOwnership };
