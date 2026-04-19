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
 *
 * DocuSign Connect setup (one-time, in DocuSign Admin > Connect):
 *   URL:     https://bridge.healthcred.com/docusign-webhook
 *   Trigger: Envelope Completed
 *   Include: Recipients, Custom Fields
 *   Format:  JSON
 */

'use strict';

const crypto = require('crypto');
const tls    = require('tls');

// ── Access token ─────────────────────────────────────────────────────────────

function generateAccessToken(envelopeId, investorEmail) {
  const secret = process.env.ACCESS_TOKEN_SECRET || 'hc-bridge-secret-2024';
  return crypto
    .createHmac('sha256', secret)
    .update(`${envelopeId}:${investorEmail.toLowerCase()}`)
    .digest('hex')
    .substring(0, 40);
}

// ── Gmail SMTP (raw TLS — no external dependencies) ──────────────────────────

function sendGmailSMTP({ user, pass, to, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' },
      () => { /* TLS handshake complete */ }
    );

    socket.setTimeout(20000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
    socket.on('error', reject);

    let buf  = '';
    let step = 0;

    const boundary = `hc_${Date.now()}`;
    const headers  = [
      `From: HealthCred Investor Portal <${user}>`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'MIME-Version: 1.0',
      html
        ? `Content-Type: multipart/alternative; boundary="${boundary}"`
        : 'Content-Type: text/plain; charset=UTF-8',
    ].join('\r\n');

    let body = headers + '\r\n\r\n';
    if (html) {
      body += `--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n`;
      body += `--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${html}\r\n`;
      body += `--${boundary}--\r\n`;
    } else {
      body += text + '\r\n';
    }
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

// ── Investor access email ─────────────────────────────────────────────────────

async function sendAccessEmail({ investorName, investorEmail, accessUrl, cfg }) {
  const subject = 'HealthCred — Your NDA is Executed. Access the Investor Portal Now.';

  const firstName = investorName.split(' ')[0] || investorName;

  const text = [
    `${firstName},`,
    '',
    'Your Non-Disclosure Agreement with HealthCred Care LLC is fully executed — both signatures are complete.',
    '',
    'You now have access to the confidential HealthCred investor data room. Click the link below to enter:',
    '',
    `  ${accessUrl}`,
    '',
    'This link is unique to you. Please do not share it.',
    '',
    "Inside you'll find our full financial model, traction metrics, unit economics, and deal terms.",
    'If you have any questions, reply to this email or call me directly.',
    '',
    'Chad R. LaBoy | President & Founder | HealthCred | Corrections Infrastructure',
    'Reducing Government Risk. Expanding Healthcare Access.',
    'Direct: +1 (949) 866-3839 | Office: +1 (877) 390-4049 Ext 101',
    'chad@healthcred.com | healthcred.com',
  ].join('\n');

  const html = `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e;">
  <div style="background:#0D1B2A;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
    <div style="font-size:22px;font-weight:900;color:#C9A84C;letter-spacing:2px;">HEALTHCRED</div>
    <div style="font-size:11px;color:rgba(255,255,255,0.45);letter-spacing:3px;margin-top:4px;">CORRECTIONS INFRASTRUCTURE</div>
  </div>
  <div style="background:#f9f8f5;padding:32px;border-radius:0 0 10px 10px;border:1px solid #e8e0d0;">
    <p style="font-size:16px;color:#0D1B2A;margin-top:0;">Hi ${firstName},</p>
    <p style="color:#333;line-height:1.6;">Your Non-Disclosure Agreement with HealthCred Care LLC is <strong>fully executed</strong> — both signatures are complete.</p>
    <p style="color:#333;line-height:1.6;">You now have access to HealthCred's confidential investor data room.</p>
    <div style="text-align:center;margin:32px 0;">
      <a href="${accessUrl}" style="display:inline-block;background:#C9A84C;color:#0D1B2A;padding:16px 36px;border-radius:8px;font-weight:900;font-size:15px;text-decoration:none;letter-spacing:1px;">ACCESS THE INVESTOR PORTAL →</a>
    </div>
    <p style="font-size:12px;color:#888;text-align:center;margin-bottom:24px;">This link is unique to you. Please do not share it.</p>
    <div style="background:#fff;border:1px solid #e0d8c8;border-radius:8px;padding:16px;margin-bottom:24px;">
      <div style="font-size:12px;color:#888;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Inside the data room</div>
      <ul style="margin:0;padding-left:18px;color:#333;font-size:14px;line-height:2;">
        <li>Full financial model & projections</li>
        <li>Unit economics (PMPM, AGC, returns)</li>
        <li>Traction metrics & carrier payment data</li>
        <li>Deal terms & investment structure</li>
        <li>Market opportunity & expansion roadmap</li>
      </ul>
    </div>
    <div style="border-top:1px solid #e8e0d0;padding-top:20px;font-size:13px;color:#555;line-height:1.8;">
      <strong>Chad R. LaBoy</strong> | President &amp; Founder | HealthCred | Corrections Infrastructure<br>
      Reducing Government Risk. Expanding Healthcare Access.<br>
      Direct: +1 (949) 866-3839 | Office: +1 (877) 390-4049 Ext 101<br>
      <a href="mailto:chad@healthcred.com" style="color:#C9A84C;">chad@healthcred.com</a> | healthcred.com
    </div>
  </div>
</div>`;

  return sendGmailSMTP({
    user:    cfg.GMAIL_USER,
    pass:    cfg.GMAIL_PASS,
    to:      investorEmail,
    subject,
    text,
    html,
  });
}

// ── Handler ───────────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  // DocuSign retries on anything other than 2xx — always return 200
  const ok = { statusCode: 200, body: JSON.stringify({ received: true }) };

  if (event.httpMethod !== 'POST') return ok;

  const cfg = {
    GMAIL_USER:   process.env.GMAIL_USER        || 'chad@healthcred.com',
    GMAIL_PASS:   process.env.GMAIL_APP_PASSWORD,
    PORTAL_URL:   (process.env.PORTAL_URL       || 'https://bridge.healthcred.com').replace(/\/$/, ''),
    NOTIFY_EMAIL: process.env.NOTIFICATION_EMAIL || 'chad@healthcred.com',
  };

  try {
    const payload = JSON.parse(event.body || '{}');

    // DocuSign Connect JSON format (v2 wraps in data.envelopeSummary)
    const envelopeData = payload.data?.envelopeSummary || payload;
    const status       = (envelopeData.status || envelopeData.envelopeStatus || '').toLowerCase();

    console.log(`DocuSign webhook: envelopeId=${envelopeData.envelopeId} status=${status}`);

    // Only act on fully completed envelopes (all parties signed)
    if (status !== 'completed') {
      console.log(`Status is "${status}" — skipping email`);
      return ok;
    }

    const envelopeId = envelopeData.envelopeId;
    const signers    = envelopeData.recipients?.signers || [];

    // Find the investor (Signer, routing order 1)
    const investor = signers.find(s =>
      String(s.routingOrder) === '1' || s.routingOrder === 1
    );

    if (!investor || !investor.email) {
      console.warn('Webhook: could not identify investor signer — skipping email');
      return ok;
    }

    const token     = generateAccessToken(envelopeId, investor.email);
    const accessUrl = `${cfg.PORTAL_URL}/?access=${token}&eid=${envelopeId}`;

    console.log(`Sending access email to: ${investor.email}`);

    if (!cfg.GMAIL_PASS) {
      console.warn('GMAIL_APP_PASSWORD not set — cannot send access email');
      return ok;
    }

    await sendAccessEmail({
      investorName:  investor.name  || 'Investor',
      investorEmail: investor.email,
      accessUrl,
      cfg,
    });

    console.log(`Access email sent successfully to ${investor.email}`);

    // Also notify Chad that the NDA is fully executed
    if (cfg.GMAIL_USER && cfg.GMAIL_PASS) {
      try {
        await sendGmailSMTP({
          user:    cfg.GMAIL_USER,
          pass:    cfg.GMAIL_PASS,
          to:      cfg.NOTIFY_EMAIL,
          subject: `NDA Executed — ${investor.name} (${investor.email})`,
          text: [
            'NDA fully executed — both signatures complete.',
            '',
            `Investor: ${investor.name}`,
            `Email:    ${investor.email}`,
            `Envelope: ${envelopeId}`,
            '',
            `Access link sent to investor: ${accessUrl}`,
          ].join('\n'),
        });
      } catch (notifyErr) {
        console.warn('Chad notification email failed:', notifyErr.message);
      }
    }

    return ok;

  } catch (err) {
    console.error('docusign-webhook error:', err.message);
    return ok; // Always 200 so DocuSign does not retry endlessly
  }
};
