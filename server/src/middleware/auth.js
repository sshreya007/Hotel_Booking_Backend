const jwt = require('jsonwebtoken');

/**
 * Verifies the access token cookie/header and attaches { id, role, hotelId } to req.user.
 * Access tokens are short-lived (15 min) — see routes/auth.js for issuance and the
 * refresh-token rotation flow that keeps users logged in without a long-lived JWT
 * sitting in the browser.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.cookies?.accessToken;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = { id: payload.sub, role: payload.role, hotelId: payload.hotelId || null };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

/**
 * Least-privilege role gate. Usage: requireRole('admin') or requireRole('admin', 'staff').
 * Must run after requireAuth.
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      // Zero-trust: don't reveal WHY it failed beyond "forbidden" — no hints about
      // valid roles or resource existence.
      return res.status(403).json({ error: 'Forbidden.' });
    }
    return next();
  };
}

/**
 * Optionally binds the session to a hash of the User-Agent header. If the header
 * changes mid-session, force re-authentication. This is a defense-in-depth measure
 * against session token theft/replay from a different device — not foolproof
 * (UA can be spoofed) but raises the bar. Document this tradeoff in your report.
 */
function requireMatchingUserAgent(req, res, next) {
  const currentUAHash = require('crypto')
    .createHash('sha256')
    .update(req.headers['user-agent'] || '')
    .digest('hex');

  if (req.user?.uaHash && req.user.uaHash !== currentUAHash) {
    return res.status(401).json({ error: 'Session invalid for this device. Please log in again.' });
  }
  return next();
}

module.exports = { requireAuth, requireRole, requireMatchingUserAgent };
