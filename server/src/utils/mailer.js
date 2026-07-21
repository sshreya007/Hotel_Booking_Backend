/**
 * Minimal mail stub. In development this just logs the message so you can see
 * reset/magic links in your terminal without needing a real mail provider.
 *
 * For a real deployment, swap the body of sendMail() for an actual provider,
 * e.g. Nodemailer with SMTP, or an API-based service like SendGrid/Postmark/SES.
 * Keep the function signature the same so nothing else in the app needs to change.
 */
async function sendMail({ to, subject, text }) {
  if (process.env.NODE_ENV === 'production') {
    // eslint-disable-next-line no-console
    console.warn('sendMail() is still using the console stub in production — wire up a real provider.');
  }
  // eslint-disable-next-line no-console
  console.log(`\n--- EMAIL (dev stub) ---\nTo: ${to}\nSubject: ${subject}\n\n${text}\n------------------------\n`);
}

module.exports = { sendMail };
