const rateLimit = require('express-rate-limit');


const skipInTest = () => process.env.NODE_ENV === 'test';

// Tight limit on auth endpoints specifically (login, register, MFA verify) since
// these are the highest-value brute-force targets.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
  message: { error: 'Too many attempts. Try again later.' },
});

// Looser, general limiter for the rest of the API so a single client can't hammer
// any endpoint (booking creation, search, etc).
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipInTest,
});

module.exports = { authLimiter, apiLimiter };
