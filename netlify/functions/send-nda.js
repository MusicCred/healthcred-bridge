/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: send-nda.js
 *
 * Handles DocuSign envelope creation for the investor NDA gate.
 * Uses remote/email signing — DocuSign emails the investor directly.
 *
 * Environment variables:
 *   DOCUSIGN_ACCOUNT_ID        = 1dab0a51-af7c-463b-a3d2-955fa2b8d354
 *   DOCUSIGN_INTEGRATION_KEY   = 244c70f1-da74-4943-a9e0-8507101c8128
 *   DOCUSIGN_USER_ID           = a22f1670-1914-4a1c-b901-915b82c17dfc
 *   DOCUSIGN_PRIVATE_KEY       = (RSA private key, base64 encoded)
 *   DOCUSIGN_TEMPLATE_ID       = (NDA template ID in DocuSign)
 *   DOCUSIGN_BASE_URL          = https://na4.docusign.net/restapi
 *   DOCUSIGN_OAUTH_URL         = https://account.docusign.com
 *   NOTIFICATION_EMAIL         = chad@healthcred.com
 */

const https = require('https');

function getConfig() {
  return {
    ACCOUNT_ID:      process.env.DOCUSIGN_ACCOUNT_ID,
    INTEGRATION_KEY: process.env.DOCUSIGN_INTEGRATION_KEY,
    USER_ID:         process.env.DOCUSIGN_USER_ID,
    PRIVATE_KEY_B64: process.env.DOCUSIGN_PRIVATE_KEY,
    TEMPLATE_ID:     process.env.DOCUSIGN_TEMPLATE_ID,
    BASE_URL:        process.env.DOCUSIGN_BASE_URL  || 'https://na4.docusign.net/restapi',
    OAUTH_URL:       process.env.DOCUSIGN_OAUTH_URL || 'https://account.docusign.com',
  };
}

function base64url(buf) {
  return buf.toString('base64').replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=/g, '');
}

function makeJWT(cfg) {
  const crypto = require('crypto');
  const privateKey = Buffer.from(cfg.PRIVATE_KEY_B64, 'base64').toString('utf8');
  const header  = base64url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const now     = Math.floor(Date.now() / 1000);
  const payload = base64url(Buffer.from(JSON.stringify({
    iss: cfg.INTEGRATION_KEY,
    sub: cfg.USER_ID,
    aud: new URL(cfg.OAUTH_URL).hostname,
    iat: now,
    exp: now + 3600,
    scope: 'signature impersonation'
  })));
  const sigInput = header + '.' + payload;
  const sig = base64url(crypto.sign('sha256', Buffer.from(sigInput), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }));
  return sigInput + '.' + sig;
}

function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request({ hostname, path, method: 'POST', headers: { ...headers, 'Content-Length': Buffer.byteLength(data) } }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function getAccessToken(cfg) {
  const jwt = makeJWT(cfg);
  const body = 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + jwt;
  const oauthHost = new URL(cfg.OAUTH_URL).hostname;
  const res = await httpsPost(oauthHost, '/oauth/token', {
    'Content-Type': 'application/x-www-form-urlencoded'
  }, body);
  if (res.status !== 200) throw new Error('OAuth failed: ' + JSON.stringify(res.body));
  return res.body.access_token;
}

async function createEnvelope(accessToken, investor, cfg) {
  const apiHost = new URL(cfg.BASE_URL).hostname;
  const CHAD_NAME  = 'Chad R. LaBoy';
  const CHAD_EMAIL = process.env.NOTIFICATION_EMAIL || 'chad@healthcred.com';

  // No clientUserId = remote/email signing: DocuSign emails the investor directly
  const envelope = {
    templateId: cfg.TEMPLATE_ID,
    templateRoles: [
      {
        roleName:     'Signer',
        name:         investor.name,
        email:        investor.email,
        routingOrder: '1',
        tabs: {
          textTabs: [
            { tabLabel: 'Investor Name',    value: investor.name    },
            { tabLabel: 'Investor Address', value: investor.address || '' },
            { tabLabel: 'Phone',            value: investor.phone   || '' }
          ]
        }
      },
      {
        roleName:     'HealthCred Representative',
        name:         CHAD_NAME,
        email:        CHAD_EMAIL,
        routingOrder: '2'
      }
    ],
    emailSubject: 'HealthCred Care LLC — Non-Disclosure Agreement',
    emailBlurb:   investor.name + ', please review and sign the enclosed Non-Disclosure Agreement to access HealthCred private investor materials.',
    status: 'sent'
  };

  const res = await httpsPost(apiHost,
    '/restapi/v2.1/accounts/' + cfg.ACCOUNT_ID + '/envelopes',
    { 'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
    envelope
  );
  if (res.status !== 201) throw new Error('Envelope creation failed: ' + JSON.stringify(res.body));
  return res.body.envelopeId;
}

exports.handler = async (event) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: corsHeaders, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  try {
    const cfg = getConfig();
    const { name, email, phone, address } = JSON.parse(event.body || '{}');
    if (!name || !email) {
      return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Name and email are required' }) };
    }

    console.log('ENV CHECK — INTEGRATION_KEY:', cfg.INTEGRATION_KEY ? 'set' : 'MISSING');
    console.log('ENV CHECK — PRIVATE_KEY_B64:', cfg.PRIVATE_KEY_B64 ? cfg.PRIVATE_KEY_B64.length + ' chars' : 'MISSING');
    console.log('ENV CHECK — ACCOUNT_ID:', cfg.ACCOUNT_ID ? 'set' : 'MISSING');
    console.log('ENV CHECK — TEMPLATE_ID:', cfg.TEMPLATE_ID || 'MISSING');

    if (!cfg.INTEGRATION_KEY || !cfg.PRIVATE_KEY_B64 || !cfg.TEMPLATE_ID) {
      return {
        statusCode: 503,
        headers: corsHeaders,
        body: JSON.stringify({
          error: 'DocuSign not fully configured',
          missing: {
            INTEGRATION_KEY: !cfg.INTEGRATION_KEY,
            PRIVATE_KEY_B64: !cfg.PRIVATE_KEY_B64,
            TEMPLATE_ID:     !cfg.TEMPLATE_ID
          }
        })
      };
    }

    const token = await getAccessToken(cfg);
    const envelopeId = await createEnvelope(token, { name, email, phone, address }, cfg);
    console.log('Envelope created:', envelopeId, '— DocuSign email sent to:', email);

    return {
      statusCode: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, envelopeId })
    };

  } catch (err) {
    console.error('send-nda error:', err.message);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: err.message })
    };
  }
};
