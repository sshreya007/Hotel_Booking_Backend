/**
 * IP-based access control, applied globally (see index.js).
 *
 * - IP_BLOCKLIST: comma-separated IPs that are always rejected — use this to
 *   cut off an address you've identified as abusive during testing/monitoring.
 * - IP_ALLOWLIST: if set to a non-empty list, ONLY those IPs may reach the API
 *   at all. Leave empty/unset for normal public operation; this is mainly
 *   useful for locking the admin-facing parts of a deployment down to office/VPN
 *   IPs, or for a fully private internal instance during testing.
 *
 * This is a coarse, defense-in-depth layer on top of (not a replacement for)
 * the rate limiting and RBAC already in place.
 */
function parseList(envVar) {
  return (envVar || '')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean);
}

function ipFilter(req, res, next) {
  const blocklist = parseList(process.env.IP_BLOCKLIST);
  const allowlist = parseList(process.env.IP_ALLOWLIST);

  const clientIp = req.ip;

  if (blocklist.includes(clientIp)) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  if (allowlist.length > 0 && !allowlist.includes(clientIp)) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  return next();
}

module.exports = { ipFilter };
