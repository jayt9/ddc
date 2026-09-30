const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

const TO_EMAIL = 'info@data-dc.com';
const FROM_EMAIL = 'Data Driven Consulting <hello@data-dc.com>';

// Basic in-memory rate limiting (per serverless instance). Good enough to
// blunt casual abuse; for stronger guarantees use Vercel Edge Config/KV.
const submissions = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 5;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = submissions.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  submissions.set(ip, entry);
  return entry.count > RATE_LIMIT_MAX;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function sanitize(str, maxLen) {
  return String(str || '').trim().slice(0, maxLen).replace(/[\r\n]+/g, ' ');
}

async function verifyTurnstile(token, ip) {
  if (!token) return false;

  const params = new URLSearchParams();
  params.append('secret', process.env.TURNSTILE_SECRET_KEY);
  params.append('response', token);
  if (ip) params.append('remoteip', ip);

  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: params,
  });
  const data = await res.json();
  return data.success === true;
}

module.exports = async function handler(req, res) {
  // Same-origin form submissions don't need CORS at all; this just guards
  // against the endpoint being called cross-site from another domain.
  const allowedOrigin = process.env.ALLOWED_ORIGIN || `https://${req.headers.host}`;
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(ip)) {
    res.status(429).json({ error: 'Too many requests. Please try again in a minute.' });
    return;
  }

  const { name, email, company, service, message, turnstileToken } = req.body || {};

  const cleanName = sanitize(name, 100);
  const cleanEmail = sanitize(email, 200);
  const cleanCompany = sanitize(company, 150);
  const cleanService = sanitize(service, 100);
  const cleanMessage = sanitize(message, 3000);

  if (!cleanName || !cleanEmail || !cleanMessage) {
    res.status(400).json({ error: 'Name, email, and message are required.' });
    return;
  }

  if (!EMAIL_RE.test(cleanEmail)) {
    res.status(400).json({ error: 'Please provide a valid email address.' });
    return;
  }

  const isHuman = await verifyTurnstile(turnstileToken, ip);
  if (!isHuman) {
    res.status(403).json({ error: 'Verification failed. Please try again.' });
    return;
  }

  try {
    await resend.emails.send({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: cleanEmail,
      subject: `New inquiry from ${cleanName}${cleanCompany ? ` (${cleanCompany})` : ''}`,
      text: [
        `Name: ${cleanName}`,
        `Email: ${cleanEmail}`,
        `Company: ${cleanCompany || '—'}`,
        `Project type: ${cleanService || '—'}`,
        '',
        'Message:',
        cleanMessage,
      ].join('\n'),
    });

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Failed to send contact email:', err);
    res.status(502).json({ error: 'Failed to send message. Please try again later.' });
  }
};
