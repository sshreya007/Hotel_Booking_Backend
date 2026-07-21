const rateLimit = require('express-rate-limit');

// Applied per-IP. Tune windowMs/max in your writeup based on what you observe during
// testing — these are reasonable starting points, not final numbers.

// Tight limit on auth endpoints specifically (login, register, MFA verify) since
// these are the highest-value brute-force targets.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
});

// Looser, general limiter for the rest of the API so a single client can't hammer
// any endpoint (booking creation, search, etc).
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { authLimiter, apiLimiter };
