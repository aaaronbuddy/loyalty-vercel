// api/check.js - Vercel Serverless Function to check authentication
const crypto = require('crypto');

const SECRET = 'loyalty-2026-ctf-secret-key-change-this';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}

function verifyToken(cookie) {
  if (!cookie) return false;
  try {
    const [data, signature] = cookie.split('|');
    const expectedSig = sign(data);
    if (signature !== expectedSig) return false;
    const [auth, timestamp] = data.split('|');
    if (auth !== 'auth=1') return false;
    const age = Date.now() - parseInt(timestamp);
    if (age > 30 * 24 * 60 * 60 * 1000) return false;
    return true;
  } catch(e) {
    return false;
  }
}

module.exports = async (req, res) => {
  // CORS headers - mirror origin for credentials support
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    return res.status(200).end();
  }

  const cookie = req.headers.cookie || '';
  const match = cookie.match(/loyalty_auth=([^;]+)/);
  const token = match ? match[1] : null;
  
  if (verifyToken(token)) {
    return res.status(200).json({ authenticated: true });
  } else {
    return res.status(401).json({ authenticated: false });
  }
};
