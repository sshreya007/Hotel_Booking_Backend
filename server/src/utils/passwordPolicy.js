// Password policy: length, complexity, and basic strength feedback.
// For a stronger real-world check, call the HaveIBeenPwned "Pwned Passwords" API
// (k-anonymity range search — you send a SHA-1 prefix, never the full password)
// to reject breached passwords. Left as a documented extension point.

const MIN_LENGTH = 12;

function checkPasswordPolicy(password) {
  const problems = [];

  if (!password || password.length < MIN_LENGTH) {
    problems.push(`Password must be at least ${MIN_LENGTH} characters long.`);
  }
  if (!/[a-z]/.test(password)) problems.push('Include at least one lowercase letter.');
  if (!/[A-Z]/.test(password)) problems.push('Include at least one uppercase letter.');
  if (!/[0-9]/.test(password)) problems.push('Include at least one number.');
  if (!/[^A-Za-z0-9]/.test(password)) problems.push('Include at least one symbol.');

  // Reject a short list of trivially guessable passwords as a placeholder for a
  // real breached-password check.
  const commonPasswords = ['password123!', 'qwertyuiop123', 'admin12345678'];
  if (commonPasswords.includes((password || '').toLowerCase())) {
    problems.push('This password is too common. Choose something more unique.');
  }

  return {
    valid: problems.length === 0,
    problems,
    // crude strength score 0-4 for UI feedback, not cryptographically meaningful
    score: [
      password && password.length >= MIN_LENGTH,
      /[a-z]/.test(password) && /[A-Z]/.test(password),
      /[0-9]/.test(password),
      /[^A-Za-z0-9]/.test(password),
    ].filter(Boolean).length,
  };
}

module.exports = { checkPasswordPolicy, MIN_LENGTH };
