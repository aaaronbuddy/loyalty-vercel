// api/auth.js - Vercel Serverless Function for authentication
const crypto = require('crypto');

const SECRET = process.env.AUTH_SECRET || 'loyalty-2026-ctf-secret-key-change-this';
const PASSWORD = process.env.PASSWORD || 'ctf2026';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}

module.exports = async (req, res) => {
  // CORS headers
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  if (password !== PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Create signed token (120 days expiry)
  const timestamp = Date.now().toString();
  const data = `auth=1|${timestamp}`;
  const signature = sign(data);
  const token = `${data}|${signature}`;

  // Return token in JSON response (client saves to localStorage)
  return res.status(200).json({
    success: true,
    token: token,
    expiresAt: Date.now() + 120 * 24 * 60 * 60 * 1000
  });
};
