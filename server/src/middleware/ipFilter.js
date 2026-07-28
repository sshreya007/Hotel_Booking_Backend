
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
