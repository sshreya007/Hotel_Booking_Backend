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


app.set('trust proxy', 1);


app.use(ipFilter);


app.use(helmet());

app.use(
  cors({
    origin: (process.env.CORS_ORIGIN || '').split(',').filter(Boolean),
    credentials: true,
  })
);


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


app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  const isProd = process.env.NODE_ENV === 'production';
  res.status(500).json({ error: 'Internal server error.', detail: isProd ? undefined : err.message });
});


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
