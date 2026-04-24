/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: docusign-webhook.js
 *
 * Receives DocuSign Connect webhooks. When an envelope reaches "completed"
 * status (both investor AND Chad have signed), generates a secure access
 * token and emails it to the investor so they can enter the data room.
 *
 * Environment variables (set in Netlify dashboard):
 *   GMAIL_USER          = chad@healthcred.com
 *   GMAIL_APP_PASSWORD  = (16-char Google App Password — already set)
 *   ACCESS_TOKEN_SECRET = (random 32-char secret — set once)
 *   PORTAL_URL          = https://bridge.healthcred.com
 *   NOTIFICATION_EMAIL  = chad@healthcred.com
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

function generateAccessToken(envelopeId, investorEmail) {
  const secret = process.env.ACCESS_TOKEN_SECRET || 'hc-bridge-secret-2024';
  return crypto.createHmac('sha256', secret).update(`${envelopeId}:${investorEmail.toLowerCase()}`).digest('hex').substring(0, 40);
}

function sendGmailSMTP({ user, pass, to, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' }, () => {});
    socket.setTimeout(20000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
    socket.on('error', reject);
    let buf = '', step = 0;
    const boundary = `hc_${Date.now()}`;
    const headers = [`From: HealthCred Investor Portal <${user}>`, `To: ${to}`, `Subject: ${subject}`, 'MIME-Version: 1.0', html ? `Content-Type: multipart/alternative; boundary="${boundary}"` : 'Content-Type: text/plain; charset=UTF-8'].join('\r\n');
    let body = headers + '\r\n\r\n';
    if (html) { body += `--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n`; body += `--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${html}\r\n`; body += `--${boundary}--\r\n`; } else { body += text + '\r\n'; }
    const escaped = body.split('\r\n').map(l => l === '.' ? '..' : l).join('\r\n');
    const w = (cmd) => socket.write(cmd + '\r\n');
    socket.on('data', chunk => {
      buf += chunk.toString();
      let pos;
      while ((pos = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, pos); buf = buf.slice(pos + 2);
        const code = parseInt(line.slice(0, 3), 10); const isLast = line[3] === ' ';
        if (!isLast) continue;
        if (code >= 500) { socket.destroy(); return reject(new Error(`SMTP ${code}: ${line.slice(4)}`)); }
        if (step === 0 && code === 220) { step = 1; w('EHLO bridge.healthcred.com'); }
        else if (step === 1 && code === 250) { step = 2; w(`AUTH PLAIN ${Buffer.from(`\x00${user}\x00${pass}`).toString('base64')}`); }
        else if (step === 2 && code === 235) { step = 3; w(`MAIL FROM:<${user}>`); }
        else if (step === 3 && code === 250) { step = 4; w(`RCPT TO:<${to}>`); }
        else if (step === 4 && code === 250) { step = 5; w('DATA'); }
        else if (step === 5 && code === 354) { step = 6; socket.write(escaped + '\r\n.\r\n'); }
        else if (step === 6 && code === 250) { step = 7; w('QUIT'); }
        else if (step === 7 && code === 221) { socket.destroy(); resolve({ sent: true }); }
        else if (code >= 400) { socket.destroy(); reject(new Error(`SMTP ${code} at step ${step}: ${line.slice(4)}`)); }
      }
    });
  });
}

async function sendAccessEmail({ investorName, investorEmail, accessUrl, cfg }) {
  const firstName = investorName.split(' ')[0] || investorName;
  const subject = 'HealthCred — Your NDA is Executed. Access the Investor Portal Now.';
  const text = [`${firstName},`, '', 'Your NDA with HealthCred is fully executed. Access the investor portal:', '', `  ${accessUrl}`, '', 'This link is unique to you. Please do not share it.', '', 'Chad R. LaBoy | President & Founder | HealthCred', 'Direct: +1 (949) 866-3839 | chad@healthcred.com'].join('\n');
  const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;"><div style="background:#0D1B2A;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;"><div style="font-size:22px;font-weight:900;color:#C9A84C;letter-spacing:2px;">HEALTHCRED</div></div><div style="background:#f9f8f5;padding:32px;border-radius:0 0 10px 10px;border:1px solid #e8e0d0;"><p>Hi ${firstName},</p><p>Your NDA is <strong>fully executed</strong>. Access the confidential investor data room:</p><div style="text-align:center;margin:32px 0;"><a href="${accessUrl}" style="background:#C9A84C;color:#0D1B2A;padding:16px 36px;border-radius:8px;font-weight:900;text-decoration:none;">ACCESS THE INVESTOR PORTAL →</a></div><p style="font-size:12px;color:#888;text-align:center;">This link is unique to you. Do not share it.</p><div style="border-top:1px solid #e8e0d0;padding-top:20px;font-size:13px;"><strong>Chad R. LaBoy</strong> | President &amp; Founder | HealthCred<br>Direct: +1 (949) 866-3839 | <a href="mailto:chad@healthcred.com" style="color:#C9A84C;">chad@healthcred.com</a></div></div></div>`;
  return sendGmailSMTP({ user: cfg.GMAIL_USER, pass: cfg.GMAIL_PASS, to: investorEmail, subject, text, html });
}

exports.handler = async (event) => {
  const ok = { statusCode: 200, body: JSON.stringify({ received: true }) };
  if (event.httpMethod !== 'POST') return ok;
  const cfg = { GMAIL_USER: process.env.GMAIL_USER || 'chad@healthcred.com', GMAIL_PASS: process.env.GMAIL_APP_PASSWORD, PORTAL_URL: (process.env.PORTAL_URL || 'https://bridge.healthcred.com').replace(/\/$/, ''), NOTIFY_EMAIL: process.env.NOTIFICATION_EMAIL || 'chad@healthcred.com' };
  try {
    const payload = JSON.parse(event.body || '{}');
    const envelopeData = payload.data?.envelopeSummary || payload;
    const status = (envelopeData.status || envelopeData.envelopeStatus || '').toLowerCase();
    console.log(`DocuSign webhook: envelopeId=${envelopeData.envelopeId} status=${status}`);
    if (status !== 'completed') { console.log(`Status is "${status}" — skipping`); return ok; }
    const envelopeId = envelopeData.envelopeId;
    const signers = envelopeData.recipients?.signers || [];
    const investor = signers.find(s => String(s.routingOrder) === '1' || s.routingOrder === 1);
    if (!investor?.email) { console.warn('Could not identify investor signer'); return ok; }
    const token = generateAccessToken(envelopeId, investor.email);
    const accessUrl = `${cfg.PORTAL_URL}/?access=${token}&eid=${envelopeId}`;
    try {
      const profileStore = getStore({ name: 'investor-profiles', consistency: 'strong' });
      const emailHash = crypto.createHash('sha256').update(investor.email.toLowerCase().trim()).digest('hex');
      const existing = await profileStore.get(emailHash, { type: 'json' }) || {};
      const now = new Date().toISOString();
      await profileStore.setJSON(emailHash, { ...existing, email: investor.email.toLowerCase().trim(), name: investor.name || existing.name || '', envelopeId, ndaSigned: true, ndaSignedAt: now, accessToken: token, createdAt: existing.createdAt || now });
    } catch (profileErr) { console.warn('Profile save failed:', profileErr.message); }
    if (!cfg.GMAIL_PASS) { console.warn('GMAIL_APP_PASSWORD not set'); return ok; }
    await sendAccessEmail({ investorName: investor.name || 'Investor', investorEmail: investor.email, accessUrl, cfg });
    try { await sendGmailSMTP({ user: cfg.GMAIL_USER, pass: cfg.GMAIL_PASS, to: cfg.NOTIFY_EMAIL, subject: `NDA Executed — ${investor.name} (${investor.email})`, text: `NDA executed.\n\nInvestor: ${investor.name}\nEmail: ${investor.email}\nEnvelope: ${envelopeId}\nAccess: ${accessUrl}` }); } catch(e) { console.warn('Notify failed:', e.message); }
    return ok;
  } catch (err) { console.error('docusign-webhook error:', err.message); return ok; }
};
