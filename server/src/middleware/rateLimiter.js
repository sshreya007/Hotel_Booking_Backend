const rateLimit = require('express-rate-limit');

// Applied per-IP. Tune windowMs/max in your writeup based on what you observe during
// testing — these are reasonable starting points, not final numbers.

// The test suite deliberately calls auth endpoints many times in a row (many
// separate test cases), which would otherwise trip these limits and produce
// unrelated 429 failures. Real brute-force protection still applies in dev/
// production; only NODE_ENV=test disables it, and that's driven by your own
// test runner env, never by anything a client can influence.
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
