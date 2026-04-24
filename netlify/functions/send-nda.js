/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: send-nda.js
 */

const https  = require('https');
const crypto = require('crypto');
const { getStore: _getStore } = require('@netlify/blobs');

// Wrapper: uses explicit siteID+token from env when available (bypasses auto-inject).
function getStore(opts) {
  const siteID = process.env.NETLIFY_SITE_ID;
  const token  = process.env.NETLIFY_AUTH_TOKEN || process.env.NETLIFY_ACCESS_TOKEN;
  if (siteID && token) return _getStore({ ...opts, siteID, token });
  return _getStore(opts);
}

function getConfig() {
  return {
    ACCOUNT_ID:      process.env.DOCUSIGN_ACCOUNT_ID,
    INTEGRATION_KEY: process.env.DOCUSIGN_INTEGRATION_KEY,
    USER_ID:         process.env.DOCUSIGN_USER_ID,
    PRIVATE_KEY_B64: process.env.DOCUSIGN_PRIVATE_KEY,
    TEMPLATE_ID:     process.env.DOCUSIGN_TEMPLATE_ID,
    BASE_URL:        process.env.DOCUSIGN_BASE_URL   || 'https://na4.docusign.net/restapi',
    OAUTH_URL:       process.env.DOCUSIGN_OAUTH_URL  || 'https://account.docusign.com',
    RETURN_URL:      process.env.DOCUSIGN_RETURN_URL || 'https://bridge.healthcred.com/?signed=true',
  };
}

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function makeJWT(cfg) {
  const privateKey = Buffer.from(cfg.PRIVATE_KEY_B64, 'base64').toString('utf8');
  const header  = base64url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const now     = Math.floor(Date.now() / 1000);
  const payload = base64url(Buffer.from(JSON.stringify({ iss: cfg.INTEGRATION_KEY, sub: cfg.USER_ID, aud: new URL(cfg.OAUTH_URL).hostname, iat: now, exp: now + 3600, scope: 'signature impersonation' })));
  const sigInput = `${header}.${payload}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(sigInput);
  return `${sigInput}.${base64url(signer.sign(privateKey))}`;
}

function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request({ hostname, path, method: 'POST', headers: { ...headers, 'Content-Length': Buffer.byteLength(data) } }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch { resolve({ status: res.statusCode, body: raw }); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function getAccessToken(cfg) {
  const jwt = makeJWT(cfg);
  const res = await httpsPost(new URL(cfg.OAUTH_URL).hostname, '/oauth/token', { 'Content-Type': 'application/x-www-form-urlencoded' }, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`);
  if (res.status !== 200) throw new Error(`OAuth failed: ${JSON.stringify(res.body)}`);
  return res.body.access_token;
}

async function createEnvelope(accessToken, investor, cfg) {
  const apiHost = new URL(cfg.BASE_URL).hostname;
  const envelope = {
    compositeTemplates: [{
      serverTemplates: [{ sequence: '1', templateId: cfg.TEMPLATE_ID }],
      inlineTemplates: [{
        sequence: '2',
        recipients: {
          signers: [{
            recipientId: '1', routingOrder: '1', roleName: 'Signer',
            name: investor.name, email: investor.email,
            tabs: {
              nameTabs: [{ tabLabel: 'Investor Name', value: investor.name }],
              textTabs: [
                { tabLabel: 'Text ae802107-75ee-47bd-a9ec-694345fcbdd3', value: investor.address || '' },
                { tabLabel: 'Text fa155aa7-07cf-4b92-853f-32c1869c96f6', value: investor.phone || investor.address || '' }
              ]
            }
          }]
        }
      }]
    }],
    emailSubject: 'HealthCred Care LLC — Non-Disclosure Agreement',
    emailBlurb: `${investor.name}, please sign the NDA to access HealthCred's private investor materials.`,
    status: 'sent'
  };
  const res = await httpsPost(apiHost, `/restapi/v2.1/accounts/${cfg.ACCOUNT_ID}/envelopes`, { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, envelope);
  if (res.status !== 201) throw new Error(`Envelope creation failed: ${JSON.stringify(res.body)}`);
  return res.body.envelopeId;
}

exports.handler = async (event) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: cors, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: cors, body: JSON.stringify({ error: 'Method not allowed' }) };

  try {
    const cfg = getConfig();
    const { name, email, phone, address } = JSON.parse(event.body || '{}');
    if (!name || !email) return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Name and email are required' }) };
    if (!cfg.INTEGRATION_KEY || !cfg.PRIVATE_KEY_B64 || !cfg.TEMPLATE_ID) return { statusCode: 503, headers: cors, body: JSON.stringify({ error: 'DocuSign not fully configured' }) };

    const token = await getAccessToken(cfg);
    const envelopeId = await createEnvelope(token, { name, email, phone, address }, cfg);
    console.log('Envelope created:', envelopeId, 'for:', email);

    try {
      const profileStore = getStore({ name: 'investor-profiles', consistency: 'strong' });
      const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
      const existing = await profileStore.get(emailHash, { type: 'json' }) || {};
      const now = new Date().toISOString();
      await profileStore.setJSON(emailHash, { ...existing, email: email.toLowerCase().trim(), name: name || existing.name || '', phone: phone || existing.phone || '', envelopeId, ndaSigned: false, createdAt: existing.createdAt || now });
    } catch (profileErr) { console.warn('Initial profile save failed:', profileErr.message); }

    return { statusCode: 200, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, envelopeId }) };
  } catch (err) {
    console.error('send-nda error:', err.message);
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: err.message }) };
  }
};
