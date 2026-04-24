/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: magic-link.js
 *
 * Handles returning investor re-access. When a recognized investor
 * enters their email at the gate, this function looks up their profile
 * and — if their NDA is signed — emails them a secure one-click re-access link.
 *
 * POST /.netlify/functions/magic-link
 * Body: { email }
 *
 * Returns:
 *   { sent: true }          — re-access email sent
 *   { pending: true }       — NDA not yet completed, no email sent
 *   { notFound: true }      — no profile found for this email
 *
 * Environment variables:
 *   GMAIL_USER              = chad@healthcred.com
 *   GMAIL_APP_PASSWORD      = (16-char Google App Password)
 *   ACCESS_TOKEN_SECRET     = (same secret as docusign-webhook.js)
 *   PORTAL_URL              = https://bridge.healthcred.com
 */

'use strict';

const crypto = require('crypto');
const tls    = require('tls');
const { getStore: _getStore } = require('@netlify/blobs');

// Wrapper: uses explicit siteID+token from env when available (bypasses auto-inject).
function getStore(opts) {
  const siteID = process.env.NETLIFY_SITE_ID;
  const token  = process.env.NETLIFY_AUTH_TOKEN || process.env.NETLIFY_ACCESS_TOKEN;
  if (siteID && token) return _getStore({ ...opts, siteID, token });
  return _getStore(opts);
}

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function emailKey(email) {
  return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
}

function generateAccessToken(envelopeId, email) {
  const secret = process.env.ACCESS_TOKEN_SECRET || 'hc-bridge-secret-2024';
  return crypto
    .createHmac('sha256', secret)
    .update(`${envelopeId}:${email.toLowerCase().trim()}`)
    .digest('hex')
    .substring(0, 40);
}

function formatDate(isoString) {
  if (!isoString) return 'recently';
  const d = new Date(isoString);
  return d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
}

// ── Gmail SMTP (raw TLS — no external dependencies) ──────────────────────────
function sendGmailSMTP({ user, pass, to, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' },
      () => {}
    );

    socket.setTimeout(20000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
    socket.on('error', reject);

    let buf  = '';
    let step = 0;

    const boundary = `hc_ml_${Date.now()}`;
    const headers  = [
      `From: HealthCred Investor Portal <${user}>`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ].join('\r\n');

    let body = headers + '\r\n\r\n';
    body += `--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n`;
    body += `--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${html}\r\n`;
    body += `--${boundary}--\r\n`;

    const escapedBody = body.split('\r\n').map(l => l === '.' ? '..' : l).join('\r\n');
    const w = (cmd) => socket.write(cmd + '\r\n');

    socket.on('data', chunk => {
      buf += chunk.toString();
      let pos;
      while ((pos = buf.indexOf('\r\n')) !== -1) {
        const line   = buf.slice(0, pos);
        buf          = buf.slice(pos + 2);
        const code   = parseInt(line.slice(0, 3), 10);
        const isLast = line[3] === ' ';
        if (!isLast) continue;
        if (code >= 500) { socket.destroy(); return reject(new Error(`SMTP ${code}: ${line.slice(4)}`)); }
        if      (step === 0 && code === 220) { step = 1; w('EHLO bridge.healthcred.com'); }
        else if (step === 1 && code === 250) {
          step = 2;
          const cred = Buffer.from(`\x00${user}\x00${pass}`).toString('base64');
          w(`AUTH PLAIN ${cred}`);
        }
        else if (step === 2 && code === 235) { step = 3; w(`MAIL FROM:<${user}>`); }
        else if (step === 3 && code === 250) { step = 4; w(`RCPT TO:<${to}>`); }
        else if (step === 4 && code === 250) { step = 5; w('DATA'); }
        else if (step === 5 && code === 354) {
          step = 6;
          socket.write(escapedBody + '\r\n.\r\n');
        }
        else if (step === 6 && code === 250) { step = 7; w('QUIT'); }
        else if (step === 7 && code === 221) { socket.destroy(); resolve({ sent: true }); }
        else if (code >= 400) { socket.destroy(); reject(new Error(`SMTP ${code} at step ${step}: ${line.slice(4)}`)); }
      }
    });
  });
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS, body: '' };
  }

  const json = (statusCode, body) => ({
    statusCode,
    headers: { ...CORS, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (event.httpMethod !== 'POST') {
    return json(405, { error: 'Method not allowed' });
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { error: 'Invalid JSON' });
  }

  const { email } = body;
  if (!email) return json(400, { error: 'email is required' });

  const cfg = {
    GMAIL_USER:   process.env.GMAIL_USER         || 'chad@healthcred.com',
    GMAIL_PASS:   process.env.GMAIL_APP_PASSWORD,
    PORTAL_URL:   (process.env.PORTAL_URL        || 'https://bridge.healthcred.com').replace(/\/$/, ''),
  };

  try {
    const store   = getStore({ name: 'investor-profiles', consistency: 'strong' });
    const key     = emailKey(email);
    const profile = await store.get(key, { type: 'json' });

    if (!profile) {
      return json(200, { notFound: true });
    }

    if (!profile.ndaSigned || !profile.envelopeId) {
      return json(200, { pending: true, envelopeId: profile.envelopeId || null });
    }

    const token     = generateAccessToken(profile.envelopeId, profile.email);
    const accessUrl = `${cfg.PORTAL_URL}/?access=${token}&eid=${profile.envelopeId}`;
    const firstName = (profile.name || 'there').split(' ')[0];
    const signedOn  = formatDate(profile.ndaSignedAt);

    if (!cfg.GMAIL_PASS) {
      console.warn('GMAIL_APP_PASSWORD not set — returning URL without sending email');
      return json(200, { sent: true, debug_url: accessUrl });
    }

    const subject = 'HealthCred — Your Re-Access Link';

    const text = [
      `${firstName},`,
      '',
      'Here is your secure re-access link to the HealthCred investor portal:',
      '',
      `  ${accessUrl}`,
      '',
      `Your NDA was executed on ${signedOn}. This link is unique to you — please do not share it.`,
      '',
      'Chad R. LaBoy | President & Founder | HealthCred',
      'Direct: +1 (949) 866-3839 | chad@healthcred.com',
    ].join('\n');

    const html = `\n<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#1a1a2e;">\n  <div style="background:#0D1B2A;padding:24px 32px;border-radius:10px 10px 0 0;text-align:center;">\n    <div style="font-size:20px;font-weight:900;color:#C9A84C;letter-spacing:2px;">HEALTHCRED</div>\n    <div style="font-size:10px;color:rgba(255,255,255,0.35);letter-spacing:3px;margin-top:4px;">CORRECTIONS INFRASTRUCTURE</div>\n  </div>\n  <div style="background:#f9f8f5;padding:32px;border-radius:0 0 10px 10px;border:1px solid #e8e0d0;border-top:none;">\n    <p style="font-size:15px;color:#0D1B2A;margin-top:0;">Hi ${firstName},</p>\n    <p style="color:#333;line-height:1.6;margin-bottom:28px;">Here is your secure re-access link to the HealthCred investor portal. Your NDA was executed on <strong>${signedOn}</strong>.</p>\n    <div style="text-align:center;margin:0 0 28px;">\n      <a href="${accessUrl}" style="display:inline-block;background:#C9A84C;color:#0D1B2A;padding:15px 34px;border-radius:8px;font-weight:900;font-size:14px;text-decoration:none;letter-spacing:1px;">RE-ENTER THE PORTAL →</a>\n    </div>\n    <p style="font-size:11px;color:#999;text-align:center;margin-bottom:24px;">This link is unique to you. Please do not share it.</p>\n    <div style="border-top:1px solid #e8e0d0;padding-top:18px;font-size:12px;color:#666;line-height:1.8;">\n      <strong>Chad R. LaBoy</strong> | President &amp; Founder | HealthCred<br>\n      Direct: +1 (949) 866-3839 | <a href="mailto:chad@healthcred.com" style="color:#C9A84C;">chad@healthcred.com</a>\n    </div>\n  </div>\n</div>`;

    await sendGmailSMTP({
      user:    cfg.GMAIL_USER,
      pass:    cfg.GMAIL_PASS,
      to:      email,
      subject,
      text,
      html,
    });

    console.log(`Magic link sent to ${email}`);
    return json(200, { sent: true });

  } catch (err) {
    console.error('magic-link error:', err.message);
    return json(500, { error: err.message });
  }
};
