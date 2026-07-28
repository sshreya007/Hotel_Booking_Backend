
async function sendMail({ to, subject, text }) {
  if (process.env.NODE_ENV === 'production') {
    // eslint-disable-next-line no-console
    console.warn('sendMail() is still using the console stub in production — wire up a real provider.');
  }
  // eslint-disable-next-line no-console
  console.log(`\n--- EMAIL (dev stub) ---\nTo: ${to}\nSubject: ${subject}\n\n${text}\n------------------------\n`);
}

module.exports = { sendMail };
