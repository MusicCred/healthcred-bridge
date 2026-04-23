/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: send-lead.js
 *
 * Triggered when an investor submits the interest form on bridge.healthcred.com.
 * Sends an email notification to Chad via Gmail SMTP (built-in tls module — zero dependencies)
 * and optionally sends a DocuSign contribution agreement when the CA template is configured.
 *
 * Environment variables (already set in Netlify dashboard):
 *   GMAIL_USER          = chad@healthcred.com
 *   GMAIL_APP_PASSWORD  = (16-char Google App Password)
 *   NOTIFICATION_EMAIL  = chad@healthcred.com
 *
 *   DOCUSIGN_ACCOUNT_ID        = 1dab0a51-af7c-463b-a3d2-955fa2b8d354
 *   DOCUSIGN_INTEGRATION_KEY   = 244c70f1-da74-4943-a9e0-8507101c8128
 *   DOCUSIGN_USER_ID           = a22f1670-1914-4a1c-b901-915b82c17dfc
 *   DOCUSIGN_PRIVATE_KEY       = (RSA private key, base64 encoded)
 *   DOCUSIGN_CA_TEMPLATE_ID    = (add when contribution agreement template is ready)
 *   DOCUSIGN_BASE_URL          = https://na4.docusign.net/restapi
 *   DOCUSIGN_OAUTH_URL         = https://account.docusign.com
 */

'use strict';

const tls    = require('tls');
const https  = require('https');
const crypto = require('crypto');

// ── Config ────────────────────────────────────────────────────────────────────
function getConfig() {
  return {
    GMAIL_USER:     process.env.GMAIL_USER,
    GMAIL_PASS:     process.env.GMAIL_APP_PASSWORD,
    NOTIFY_EMAIL:   process.env.NOTIFICATION_EMAIL || 'chad@healthcred.com',
    DS_ACCOUNT_ID:  process.env.DOCUSIGN_ACCOUNT_ID,
    DS_INT_KEY:     process.env.DOCUSIGN_INTEGRATION_KEY,
    DS_USER_ID:     process.env.DOCUSIGN_USER_ID,
    DS_PRIVATE_KEY: process.env.DOCUSIGN_PRIVATE_KEY,
    DS_CA_TEMPLATE: process.env.DOCUSIGN_CA_TEMPLATE_ID,
    DS_BASE_URL:    process.env.DOCUSIGN_BASE_URL  || 'https://na4.docusign.net/restapi',
    DS_OAUTH_URL:   process.env.DOCUSIGN_OAUTH_URL || 'https://account.docusign.com',
  };
}

// ── CORS ──────────────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// ── Raw Gmail SMTP via built-in tls (no nodemailer, no external deps) ─────────
function sendGmailSMTP({ user, pass, to, replyTo, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' },
      () => { /* TLS handshake complete — wait for server greeting */ }
    );

    socket.setTimeout(20000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
    socket.on('error', reject);

    let buf  = '';
    let step = 0;

    // Build MIME message with plain-text + HTML parts
    const boundary = `hc_${Date.now()}`;
    const headers  = [
      `From: HealthCred Portal <${user}>`,
      `To: ${to}`,
      replyTo ? `Reply-To: ${replyTo}` : null,
      `Subject: ${subject}`,
      'MIME-Version: 1.0',
      html
        ? `Content-Type: multipart/alternative; boundary="${boundary}"`
        : 'Content-Type: text/plain; charset=UTF-8',
    ].filter(Boolean).join('\r\n');

    let body = headers + '\r\n\r\n';
    if (html) {
      body += `--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n`;
      body += `--${boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${html}\r\n`;
      body += `--${boundary}--\r\n`;
    } else {
      body += text + '\r\n';
    }
    // Escape lines starting with '.' (SMTP transparency)
    const escapedBody = body.split('\r\n').map(l => l === '.' ? '..' : l).join('\r\n');

    const w = (cmd) => socket.write(cmd + '\r\n');

    socket.on('data', chunk => {
      buf += chunk.toString();
      let pos;
      while ((pos = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, pos);
        buf = buf.slice(pos + 2);
        const code   = parseInt(line.slice(0, 3), 10);
        const isLast = line[3] === ' '; // multi-line responses end when char[3] is space

        if (!isLast) continue; // wait for final line of multi-part reply

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

// ── Build and send notification email ────────────────────────────────────────
async function sendNotificationEmail(lead, cfg) {
  const { name, email, amount, message } = lead;
  const ts = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });

  if (!cfg.GMAIL_USER || !cfg.GMAIL_PASS) {
    console.warn('GMAIL_USER or GMAIL_APP_PASSWORD not set — skipping email');
    return { skipped: true };
  }

  const subject = `New Investor Interest — ${amount} — ${name}`;

  const text = [
    'New investor interest submitted on bridge.healthcred.com',
    '',
    `Name:    ${name}`,
    `Email:   ${email}`,
    `Amount:  ${amount}`,
    `Message: ${message || '(none)'}`,
    `Time:    ${ts} ET`,
    '',
    `Reply directly to ${email} to follow up.`,
    '',
    '— HealthCred Investor Portal',
  ].join('\n');

  const html = `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e;">
  <div style="background:#1a1a2e;padding:20px 24px;border-radius:8px 8px 0 0;">
    <h2 style="color:#c9a84c;margin:0;font-size:18px;">New Investor Interest</h2>
  </div>
  <div style="background:#f9f9f9;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e0e0e0;">
    <table style="width:100%;border-collapse:collapse;">
      <tr><td style="padding:8px 0;color:#666;width:90px;vertical-align:top;"><strong>Name</strong></td><td style="padding:8px 0;">${name}</td></tr>
      <tr><td style="padding:8px 0;color:#666;vertical-align:top;"><strong>Email</strong></td><td style="padding:8px 0;"><a href="mailto:${email}" style="color:#c9a84c;">${email}</a></td></tr>
      <tr><td style="padding:8px 0;color:#666;vertical-align:top;"><strong>Amount</strong></td><td style="padding:8px 0;font-weight:bold;">${amount}</td></tr>
      ${message ? `<tr><td style="padding:8px 0;color:#666;vertical-align:top;"><strong>Message</strong></td><td style="padding:8px 0;">${message}</td></tr>` : ''}
      <tr><td style="padding:8px 0;color:#666;vertical-align:top;"><strong>Time</strong></td><td style="padding:8px 0;font-size:13px;color:#888;">${ts} ET</td></tr>
    </table>
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid #e0e0e0;">
      <a href="mailto:${email}" style="background:#c9a84c;color:#1a1a2e;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:14px;">Reply to ${name} &rarr;</a>
    </div>
  </div>
</div>`;

  return sendGmailSMTP({
    user:    cfg.GMAIL_USER,
    pass:    cfg.GMAIL_PASS,
    to:      cfg.NOTIFY_EMAIL,
    replyTo: email,
    subject,
    text,
    html,
  });
}

// ── DocuSign JWT helpers ───────────────────────────────────────────────────────
function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request(
      { hostname, path, method: 'POST', headers: { ...headers, 'Content-Length': Buffer.byteLength(data) } },
      res => { let r = ''; res.on('data', c => r += c); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(r) }); } catch { resolve({ status: res.statusCode, body: r }); } }); }
    );
    req.on('error', reject); req.write(data); req.end();
  });
}

function makeJWT(cfg) {
  const pk  = Buffer.from(cfg.DS_PRIVATE_KEY, 'base64').toString('utf8');
  const b64 = s => Buffer.from(s).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const now = Math.floor(Date.now() / 1000);
  const h   = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const p   = b64(JSON.stringify({ iss: cfg.DS_INT_KEY, sub: cfg.DS_USER_ID, aud: new URL(cfg.DS_OAUTH_URL).hostname, iat: now, exp: now + 3600, scope: 'signature impersonation' }));
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`), { key: pk, padding: crypto.constants.RSA_PKCS1_PADDING }).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  return `${h}.${p}.${sig}`;
}

async function getDocuSignToken(cfg) {
  const res = await httpsPost(new URL(cfg.DS_OAUTH_URL).hostname, '/oauth/token',
    { 'Content-Type': 'application/x-www-form-urlencoded' },
    `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${makeJWT(cfg)}`);
  if (res.status !== 200) throw new Error(`DocuSign OAuth: ${JSON.stringify(res.body)}`);
  return res.body.access_token;
}

async function sendContributionAgreement(token, investor, cfg) {
  const res = await httpsPost(new URL(cfg.DS_BASE_URL).hostname,
    `/restapi/v2.1/accounts/${cfg.DS_ACCOUNT_ID}/envelopes`,
    { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    { templateId: cfg.DS_CA_TEMPLATE, status: 'sent',
      emailSubject: 'HealthCred Care LLC — Bridge Round Contribution Agreement',
      templateRoles: [{ roleName: 'Investor', name: investor.name, email: investor.email,
        tabs: { textTabs: [{ tabLabel: 'InvestorName', value: investor.name }, { tabLabel: 'InvestorEmail', value: investor.email }, { tabLabel: 'InvestAmount', value: investor.amount }] } }] });
  if (res.status !== 201) throw new Error(`DocuSign envelope: ${JSON.stringify(res.body)}`);
  return res.body;
}

// ── Netlify handler ───────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };

  let lead;
  try { lead = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid JSON' }) }; }

  const { name, email, amount, message } = lead;
  if (!name || !email || !amount)
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'name, email, and amount are required' }) };

  const cfg = getConfig();
  const results = { email: null, docusign: null };

  // 1 — Email Chad
  try   { results.email = await sendNotificationEmail({ name, email, amount, message }, cfg); }
  catch (err) { console.error('Email error:', err.message); results.email = { error: err.message }; }

  // 2 — DocuSign contribution agreement (when CA template is configured)
  if (cfg.DS_INT_KEY && cfg.DS_PRIVATE_KEY && cfg.DS_CA_TEMPLATE) {
    try {
      const token = await getDocuSignToken(cfg);
      const env   = await sendContributionAgreement(token, { name, email, amount }, cfg);
      results.docusign = { envelopeId: env.envelopeId };
    } catch (err) { console.error('DocuSign error:', err.message); results.docusign = { error: err.message }; }
  } else {
    results.docusign = { skipped: true, reason: 'CA template not yet configured' };
  }

  return { statusCode: 200, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, results }) };
};
