/**
 * Wraps an async Express route handler so a rejected promise (a thrown error,
 * a failed await) is forwarded to next(err) instead of becoming an unhandled
 * promise rejection.
 *
 * This matters more than it might look: Express 4 does NOT catch errors
 * thrown inside async handlers automatically, and modern Node.js terminates
 * the entire process on an unhandled rejection by default. Without this
 * wrapper, a single failed database query or a failed call to a third-party
 * API (Stripe, for example) can crash the whole server for every user — not
 * just return an error for the one request that failed. That turns an
 * ordinary error (bad input, a down dependency) into an accidental
 * denial-of-service.
 *
 * Usage: router.get('/x', asyncHandler(async (req, res) => { ... }))
 */
function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = { asyncHandler };
