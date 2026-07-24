require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth');
const profileRoutes = require('./routes/profile');
const roomRoutes = require('./routes/rooms');
const adminRoutes = require('./routes/admin');
const { router: bookingRoutes, stripeWebhookHandler } = require('./routes/bookings');
const { apiLimiter } = require('./middleware/rateLimiter');
const { ipFilter } = require('./middleware/ipFilter');

const app = express();

// Needed so req.ip reflects the real client address (not the Docker/reverse-proxy
// hop) — both the rate limiter and the IP allow/block list below depend on this
// being correct.
app.set('trust proxy', 1);

// IP allow/block list — see middleware/ipFilter.js for how IP_BLOCKLIST /
// IP_ALLOWLIST are read from environment variables. Runs before everything else.
app.use(ipFilter);

// Security headers (sets sensible CSP/HSTS/etc defaults) — tune the CSP directives
// once the real frontend is built, since the default is fairly locked down.
app.use(helmet());

app.use(
  cors({
    origin: (process.env.CORS_ORIGIN || '').split(',').filter(Boolean),
    credentials: true,
  })
);

// IMPORTANT: the Stripe webhook route needs the raw request body to verify the
// signature, so it's mounted BEFORE express.json() and given its own raw parser.
// If you move this below express.json(), signature verification will always fail
// (or worse, someone disables verification to "fix" it — don't do that).
app.post('/bookings/webhook', express.raw({ type: 'application/json' }), stripeWebhookHandler);

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(apiLimiter);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authRoutes);
app.use('/profile', profileRoutes);
app.use('/rooms', roomRoutes);
app.use('/admin', adminRoutes);
app.use('/bookings', bookingRoutes);

// Generic error handler — never leak stack traces or internal error details to
// the client in production.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  const isProd = process.env.NODE_ENV === 'production';
  res.status(500).json({ error: 'Internal server error.', detail: isProd ? undefined : err.message });
});

// Last-resort safety net. safeRouter() (see utils/safeRouter.js) already
// catches rejected promises inside every route handler and forwards them to
// the error handler below, so this should rarely fire — but if something
// outside the request/response cycle throws (e.g. inside a library's own
// background callback), log it instead of letting Node kill the whole
// process and take down every other user's in-flight request with it.
process.on('unhandledRejection', (reason) => {
  // eslint-disable-next-line no-console
  console.error('Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  // eslint-disable-next-line no-console
  console.error('Uncaught exception:', err);
});

const port = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`SecureStay API listening on port ${port}`);
  });
}

module.exports = app;
