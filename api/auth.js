// api/auth.js - Vercel Serverless Function for authentication
const crypto = require('crypto');

// Secret key for signing cookies (in production, use environment variable)
const SECRET = 'loyalty-2026-ctf-secret-key-change-this';
const PASSWORD_HASH = '249b43985f89a2055f9cd29cad7d293df8e767bb1fc1b5aec8de6873fadf1f6e'; // SHA-256 of 'ctf2026'

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
    // Check if token is not too old (30 days)
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
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  // Hash the provided password
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  
  if (hash !== PASSWORD_HASH) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Create signed token
  const timestamp = Date.now().toString();
  const data = `auth=1|${timestamp}`;
  const signature = sign(data);
  const token = `${data}|${signature}`;

  // Set HttpOnly cookie
  res.setHeader('Set-Cookie', `loyalty_auth=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}; Path=/`);
  
  return res.status(200).json({ success: true });
};
