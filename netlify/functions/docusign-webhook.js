/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: docusign-webhook.js
 *
 * Receives DocuSign Connect webhooks. When an envelope reaches "completed"
 * status (both investor AND Chad have signed), generates a secure access
 * token and emails it to the investor so they can enter the data room.
 *
 * Environment variables:
 *   ACCESS_TOKEN_SECRET    = random secret string (generate one)
 *   GMAIL_SA_EMAIL         = service account email
 *   GMAIL_SA_KEY           = service account private key, base64-encoded
 *   GMAIL_USER             = chad@healthcred.com
 *   PORTAL_URL             = https://bridge.healthcred.com
 *
 * DocuSign Connect setup:
 *   URL: https://bridge.healthcred.com/docusign-webhook
 *   Trigger: Envelope Completed
 *   Include: Recipients, Custom Fields
 *   Format: JSON
 */

const crypto  = require('crypto');
const https   = require('https');

function generateAccessToken(envelopeId, investorEmail) {
  const secret = process.env.ACCESS_TOKEN_SECRET || 'hc-bridge-fallback-2024';
  return crypto
    .createHmac('sha256', secret)
    .update(`${envelopeId}:${investorEmail.toLowerCase()}`)
    .digest('hex')
    .substring(0, 40);
}

function base64url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGmailToken() {
  const saEmail  = process.env.GMAIL_SA_EMAIL;
  const saKeyB64 = process.env.GMAIL_SA_KEY;
  const impersonate = process.env.GMAIL_USER || 'chad@healthcred.com';

  if (!saEmail || !saKeyB64) throw new Error('Gmail service account not configured');

  const privateKeyPem = Buffer.from(saKeyB64, 'base64').toString('utf8');
  const now = Math.floor(Date.now() / 1000);

  const header  = base64url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const payload = base64url(Buffer.from(JSON.stringify({
    iss:   saEmail,
    sub:   impersonate,
    scope: 'https://www.googleapis.com/auth/gmail.send',
    aud:   'https://oauth2.googleapis.com/token',
    iat:   now,
    exp:   now + 3600
  })));

  const sigInput = `${header}.${payload}`;
  const sig = crypto.createSign('RSA-SHA256').update(sigInput);
  sig.end();
  const sigBytes = sig.sign(privateKeyPem);
  const jwt = `${sigInput}.${base64url(sigBytes)}`;

  return new Promise((resolve, reject) => {
    const body = `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path:     '/token',
      method:   'POST',
      headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.access_token) resolve(parsed.access_token);
          else reject(new Error(`Token error: ${data}`));
        } catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function sendAccessEmail({ investorName, investorEmail, accessUrl }) {
  const from  = process.env.GMAIL_USER || 'chad@healthcred.com';
  const token = await getGmailToken();

  const emailBody = [
    `From: Chad R. LaBoy <${from}>`,
    `To: ${investorEmail}`,
    `Subject: HealthCred — Your Investor Access is Ready`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    `${investorName},`,
    '',
    'Your Non-Disclosure Agreement has been fully executed. Both signatures are complete.',
    '',
    'You may now access the HealthCred confidential investor materials using the link below:',
    '',
    accessUrl,
    '',
    'This link is unique to you. Please do not share it.',
    '',
    'If you have any questions, reply to this email or call me directly.',
    '',
    'Chad R. LaBoy | President & Founder | HealthCred | Corrections Infrastructure',
    'Reducing Government Risk. Expanding Healthcare Access.',
    'Direct: +1 (949) 866-3839 | Office: +1 (877) 390-4049 Ext 101',
    'chad@healthcred.com | healthcred.com'
  ].join('\r\n');

  const raw = base64url(Buffer.from(emailBody, 'utf8'));

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ raw });
    const req = https.request({
      hostname: 'gmail.googleapis.com',
      path:     `/gmail/v1/users/${encodeURIComponent(from)}/messages/send`,
      method:   'POST',
      headers:  {
        'Authorization':  `Bearer ${token}`,
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(true);
        else reject(new Error(`Gmail send failed: ${data}`));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

exports.handler = async (event) => {
  const ok = { statusCode: 200, body: JSON.stringify({ received: true }) };

  if (event.httpMethod !== 'POST') return ok;

  try {
    const payload = JSON.parse(event.body || '{}');
    const envelopeData = payload.data?.envelopeSummary || payload;
    const status       = envelopeData.status || envelopeData.envelopeStatus || '';

    if (status.toLowerCase() !== 'completed') {
      console.log(`Webhook received, status=${status} — skipping`);
      return ok;
    }

    const envelopeId = envelopeData.envelopeId;
    const signers    = envelopeData.recipients?.signers || [];

    const investor = signers.find(s =>
      String(s.routingOrder) === '1' || s.routingOrder === 1
    );

    if (!investor || !investor.email) {
      console.warn('Webhook: could not find investor signer, skipping email');
      return ok;
    }

    const token     = generateAccessToken(envelopeId, investor.email);
    const portalUrl = (process.env.PORTAL_URL || 'https://bridge.healthcred.com').replace(/\/$$/, '');
    const accessUrl = `${portalUrl}/?access=${token}&eid=${envelopeId}`;

    console.log(`Sending access email to ${investor.email} for envelope ${envelopeId}`);

    await sendAccessEmail({
      investorName:  investor.name  || 'Investor',
      investorEmail: investor.email,
      accessUrl
    });

    console.log('Access email sent successfully');
    return ok;

  } catch (err) {
    console.error('docusign-webhook error:', err.message);
    return ok;
  }
};
