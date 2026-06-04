// api/debug.js - Debug endpoint to check env vars (remove after debugging)
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  // Only show if PASSWORD env var is set (not the value itself)
  const hasPassword = !!process.env.PASSWORD;
  const hasAuthSecret = !!process.env.AUTH_SECRET;
  const passwordLength = process.env.PASSWORD ? process.env.PASSWORD.length : 0;
  
  res.status(200).json({
    hasPassword,
    hasAuthSecret,
    passwordLength,
    nodeVersion: process.version,
    env: Object.keys(process.env).filter(k => !k.includes('SECRET') && !k.includes('KEY') && !k.includes('TOKEN')).slice(0, 20)
  });
};
