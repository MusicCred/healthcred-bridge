/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: check-nda.js
 *
 * Checks whether a DocuSign envelope has been completed (NDA signed).
 * Called by the portal's polling loop while the investor waits on screen-sent.
 *
 * GET /.netlify/functions/check-nda?envelopeId=<id>
 *
 * Returns:
 *   { completed: true,  status: "completed" }   — NDA signed, unlock portal
 *   { completed: false, status: "sent" }         — still waiting
 *   { completed: false, status: "declined" }     — investor declined
 *   { error: "..." }                             — something went wrong
 */

'use strict';

const https  = require('https');
const crypto = require('crypto');

function getConfig() {
  return {
    ACCOUNT_ID:      process.env.DOCUSIGN_ACCOUNT_ID,
    INTEGRATION_KEY: process.env.DOCUSIGN_INTEGRATION_KEY,
    USER_ID:         process.env.DOCUSIGN_USER_ID,
    PRIVATE_KEY_B64: process.env.DOCUSIGN_PRIVATE_KEY,
    BASE_URL:        process.env.DOCUSIGN_BASE_URL  || 'https://na4.docusign.net/restapi',
    OAUTH_URL:       process.env.DOCUSIGN_OAUTH_URL || 'https://account.docusign.com',
  };
}

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
};

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function httpsGet(hostname, path, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path, method: 'GET', headers },
      res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
          catch { resolve({ status: res.statusCode, body: raw }); }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request(
      { hostname, path, method: 'POST',
        headers: { ...headers, 'Content-Length': Buffer.byteLength(data) } },
      res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
          catch { resolve({ status: res.statusCode, body: raw }); }
        });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function makeJWT(cfg) {
  const privateKey = Buffer.from(cfg.PRIVATE_KEY_B64, 'base64').toString('utf8');
  const header  = b64url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const now     = Math.floor(Date.now() / 1000);
  const payload = b64url(Buffer.from(JSON.stringify({
    iss: cfg.INTEGRATION_KEY,
    sub: cfg.USER_ID,
    aud: new URL(cfg.OAUTH_URL).hostname,
    iat: now,
    exp: now + 3600,
    scope: 'signature impersonation',
  })));
  const sigInput = `${header}.${payload}`;
  const sig = b64url(crypto.sign('sha256', Buffer.from(sigInput),
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }));
  return `${sigInput}.${sig}`;
}

async function getAccessToken(cfg) {
  const jwt  = makeJWT(cfg);
  const body = `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`;
  const host = new URL(cfg.OAUTH_URL).hostname;
  const res  = await httpsPost(host, '/oauth/token',
    { 'Content-Type': 'application/x-www-form-urlencoded' }, body);
  if (res.status !== 200) throw new Error(`DocuSign OAuth failed: ${JSON.stringify(res.body)}`);
  return res.body.access_token;
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS, body: '' };
  }

  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, headers: CORS,
      body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const envelopeId = (event.queryStringParameters || {}).envelopeId;
  if (!envelopeId) {
    return { statusCode: 400, headers: CORS,
      body: JSON.stringify({ error: 'envelopeId query parameter is required' }) };
  }

  if (!/^[a-f0-9-]{36}$/i.test(envelopeId)) {
    return { statusCode: 400, headers: CORS,
      body: JSON.stringify({ error: 'Invalid envelopeId format' }) };
  }

  const cfg = getConfig();

  if (!cfg.INTEGRATION_KEY || !cfg.PRIVATE_KEY_B64) {
    return {
      statusCode: 200,
      headers: { ...CORS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ completed: false, status: 'sent', demo: true }),
    };
  }

  try {
    const token   = await getAccessToken(cfg);
    const apiHost = new URL(cfg.BASE_URL).hostname;
    const res     = await httpsGet(apiHost,
      `/restapi/v2.1/accounts/${cfg.ACCOUNT_ID}/envelopes/${envelopeId}`,
      { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' });

    if (res.status !== 200) {
      console.error('DocuSign envelope fetch failed:', res.status, res.body);
      return {
        statusCode: 200,
        headers: { ...CORS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ completed: false, status: 'unknown', error: 'Could not fetch envelope' }),
      };
    }

    const status    = res.body.status || 'unknown';
    const completed = status === 'completed';

    return {
      statusCode: 200,
      headers: { ...CORS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ completed, status }),
    };

  } catch (err) {
    console.error('check-nda error:', err.message);
    return {
      statusCode: 500,
      headers: { ...CORS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message, completed: false }),
    };
  }
};
