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
  return crypto.createHmac('sha256', secret).update(`${envelopeId}:${email.toLowerCase().trim()}`).digest('hex').substring(0, 40);
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };

  const json = (statusCode, body) => ({
    statusCode,
    headers: { ...CORS, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Invalid JSON' }); }

  const { token, envelopeId, sectionsViewed, interestLevel, interestSubmitted } = body;
  if (!token || !envelopeId) return json(400, { error: 'token and envelopeId required' });

  try {
    const store = getStore({ name: 'investor-profiles', consistency: 'strong' });

    // Find the profile matching this envelope
    const { blobs } = await store.list();
    let profile = null;
    let profileKey = null;

    for (const { key } of blobs) {
      const p = await store.get(key, { type: 'json' });
      if (p && p.envelopeId === envelopeId) {
        profile    = p;
        profileKey = key;
        break;
      }
    }

    if (!profile) return json(404, { error: 'Profile not found' });

    // Verify the token
    const expected = generateAccessToken(envelopeId, profile.email);
    if (token !== expected) return json(403, { error: 'Invalid token' });

    // Merge updates
    const now = new Date().toISOString();
    profile.lastAccessAt = now;
    profile.accessCount  = (profile.accessCount || 0) + 1;

    if (Array.isArray(sectionsViewed) && sectionsViewed.length > 0) {
      const existing = new Set(profile.sectionsViewed || []);
      sectionsViewed.forEach(s => existing.add(s));
      profile.sectionsViewed = Array.from(existing);
    }

    if (interestLevel !== undefined) profile.interestLevel = interestLevel;
    if (interestSubmitted !== undefined) profile.interestSubmitted = interestSubmitted;

    await store.setJSON(profileKey, profile);
    return json(200, { updated: true });

  } catch (err) {
    console.error('track-progress error:', err.message);
    return json(500, { error: err.message });
  }
};
