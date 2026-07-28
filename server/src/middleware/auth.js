const jwt = require('jsonwebtoken');


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
