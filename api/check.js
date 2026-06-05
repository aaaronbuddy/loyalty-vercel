// api/check.js - Vercel Serverless Function to check authentication
const crypto = require('crypto');

const SECRET = process.env.AUTH_SECRET || 'loyalty-2026-ctf-secret-key-change-this';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}

function verifyToken(token) {
  if (!token) return false;
  try {
    const parts = token.split('|');
    const signature = parts.pop();
    const data = parts.join('|');
    const expectedSig = sign(data);
    if (signature !== expectedSig) return false;
    const [auth, timestamp] = data.split('|');
    if (auth !== 'auth=1') return false;
    const age = Date.now() - parseInt(timestamp);
    if (age > 120 * 24 * 60 * 60 * 1000) return false;
    return true;
  } catch(e) {
    return false;
  }
}

module.exports = async (req, res) => {
  // CORS headers
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization');
    return res.status(200).end();
  }

  // Read token from Authorization header (Bear <token>) or query parameter
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }
  // Fallback: check query param
  if (!token && req.query && req.query.token) {
    token = req.query.token;
  }

  if (verifyToken(token)) {
    return res.status(200).json({ authenticated: true });
  } else {
    return res.status(401).json({ authenticated: false });
  }
};
