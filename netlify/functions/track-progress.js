/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: track-progress.js
 *
 * Updates an investor's profile with section views, access timestamps,
 * and interest level. Called silently by the portal JS.
 *
 * POST /.netlify/functions/track-progress
 * Body: {
 *   token:              string   — HMAC access token
 *   envelopeId:         string   — DocuSign envelope ID
 *   sectionsViewed?:    string[] — sections seen this session
 *   interestLevel?:     string   — e.g. "$500,000", "$1,000,000"
 *   interestSubmitted?: boolean
 * }
 */

'use strict';

const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

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

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS, body: '' };
  }

  const json = (statusCode, body) => ({
    statusCode,
    headers: { ...CORS, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Invalid JSON' }); }

  const { token, envelopeId } = body;
  if (!token || !envelopeId) return json(400, { error: 'token and envelopeId required' });

  try {
    const store = getStore({ name: 'investor-profiles', consistency: 'strong' });
    const { blobs } = await store.list();

    let profileKey   = null;
    let profileData  = null;

    for (const { key } of blobs) {
      const p = await store.get(key, { type: 'json' });
      if (p && p.envelopeId === envelopeId) {
        const expected = generateAccessToken(envelopeId, p.email);
        if (expected === token) {
          profileKey  = key;
          profileData = p;
          break;
        }
      }
    }

    if (!profileData) return json(200, { ok: false, reason: 'profile not found' });

    const now = new Date().toISOString();
    const updated = {
      ...profileData,
      lastAccessAt:      now,
      accessCount:       (profileData.accessCount || 0) + 1,
      sectionsViewed:    body.sectionsViewed
        ? [...new Set([...(profileData.sectionsViewed || []), ...body.sectionsViewed])]
        : (profileData.sectionsViewed || []),
      interestLevel:     body.interestLevel     !== undefined ? body.interestLevel     : profileData.interestLevel,
      interestSubmitted: body.interestSubmitted !== undefined ? body.interestSubmitted : profileData.interestSubmitted,
    };

    await store.setJSON(profileKey, updated);
    return json(200, { ok: true });

  } catch (err) {
    console.error('track-progress error:', err.message);
    // Silent fail — never interrupt investor experience over analytics
    return json(200, { ok: false, error: err.message });
  }
};
