/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: investor-profile.js
 *
 * Reads and writes investor profiles stored in Netlify Blobs.
 * Used by the portal gate to detect returning investors and
 * by the portal interior to load/update profile state.
 *
 * GET  /.netlify/functions/investor-profile?email=... → returns profile status
 * GET  /.netlify/functions/investor-profile?token=...&eid=... → validates re-access token
 * POST /.netlify/functions/investor-profile → create/update profile
 *
 * Profile schema:
 *   { email, name, company, phone, envelopeId, ndaSigned, ndaSignedAt,
 *     accessToken, createdAt, lastAccessAt, accessCount,
 *     sectionsViewed, interestSubmitted, interestLevel, notes }
 *
 * Environment variables:
 *   ACCESS_TOKEN_SECRET  = same secret used by docusign-webhook.js
 */

'use strict';

const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

function getProfileStore() {
  return getStore({ name: 'investor-profiles', consistency: 'strong' });
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

  // ── GET: look up profile by email OR validate access token ───────────────
  if (event.httpMethod === 'GET') {
    const q = event.queryStringParameters || {};

    // Token validation: ?token=...&eid=...
    if (q.token && q.eid) {
      try {
        const store = getProfileStore();
        // We need to find the profile with matching envelopeId
        const { blobs } = await store.list();
        for (const { key } of blobs) {
          const profile = await store.get(key, { type: 'json' });
          if (profile && profile.envelopeId === q.eid) {
            const expected = generateAccessToken(q.eid, profile.email);
            if (expected === q.token) {
              return json(200, {
                valid: true,
                profile: {
                  name:              profile.name,
                  email:             profile.email,
                  company:           profile.company || '',
                  ndaSigned:         profile.ndaSigned,
                  ndaSignedAt:       profile.ndaSignedAt,
                  sectionsViewed:    profile.sectionsViewed || [],
                  interestSubmitted: profile.interestSubmitted || false,
                  interestLevel:     profile.interestLevel || null,
                  accessCount:       profile.accessCount || 1,
                  lastAccessAt:      profile.lastAccessAt,
                }
              });
            }
          }
        }
        return json(200, { valid: false });
      } catch (err) {
        console.error('investor-profile GET token error:', err.message);
        return json(200, { valid: false });
      }
    }

    // Email lookup: ?email=...
    if (!q.email) {
      return json(400, { error: 'email or token+eid required' });
    }

    try {
      const store   = getProfileStore();
      const key     = emailKey(q.email);
      const profile = await store.get(key, { type: 'json' });

      if (!profile) {
        return json(200, { exists: false });
      }

      return json(200, {
        exists:            true,
        name:              profile.name,
        ndaSigned:         profile.ndaSigned || false,
        ndaPending:        !!(profile.envelopeId && !profile.ndaSigned),
        envelopeId:        profile.envelopeId || null,
        ndaSignedAt:       profile.ndaSignedAt || null,
        sectionsViewed:    profile.sectionsViewed || [],
        interestSubmitted: profile.interestSubmitted || false,
        accessCount:       profile.accessCount || 0,
        lastAccessAt:      profile.lastAccessAt || null,
      });
    } catch (err) {
      console.error('investor-profile GET error:', err.message);
      // Blobs not available (local dev) — return not found
      return json(200, { exists: false });
    }
  }

  // ── POST: create or update a profile ────────────────────────────────────
  if (event.httpMethod === 'POST') {
    let body;
    try {
      body = JSON.parse(event.body || '{}');
    } catch {
      return json(400, { error: 'Invalid JSON' });
    }

    const { email } = body;
    if (!email) return json(400, { error: 'email is required' });

    try {
      const store   = getProfileStore();
      const key     = emailKey(email);
      const existing = await store.get(key, { type: 'json' }) || {};

      const now = new Date().toISOString();

      const updated = {
        ...existing,
        email:             email.toLowerCase().trim(),
        name:              body.name              || existing.name              || '',
        company:           body.company           || existing.company           || '',
        phone:             body.phone             || existing.phone             || '',
        envelopeId:        body.envelopeId        || existing.envelopeId        || null,
        ndaSigned:         body.ndaSigned         !== undefined ? body.ndaSigned : (existing.ndaSigned || false),
        ndaSignedAt:       body.ndaSignedAt       || existing.ndaSignedAt       || null,
        accessToken:       body.accessToken       || existing.accessToken       || null,
        createdAt:         existing.createdAt      || now,
        lastAccessAt:      body.updateAccess      ? now : (existing.lastAccessAt || now),
        accessCount:       body.updateAccess      ? ((existing.accessCount || 0) + 1) : (existing.accessCount || 0),
        sectionsViewed:    body.sectionsViewed
                             ? [...new Set([...(existing.sectionsViewed || []), ...body.sectionsViewed])]
                             : (existing.sectionsViewed || []),
        interestSubmitted: body.interestSubmitted !== undefined ? body.interestSubmitted : (existing.interestSubmitted || false),
        interestLevel:     body.interestLevel     !== undefined ? body.interestLevel     : (existing.interestLevel     || null),
        notes:             body.notes             !== undefined ? body.notes             : (existing.notes             || ''),
      };

      await store.setJSON(key, updated);

      return json(200, { success: true, profile: {
        name:              updated.name,
        email:             updated.email,
        ndaSigned:         updated.ndaSigned,
        ndaSignedAt:       updated.ndaSignedAt,
        accessCount:       updated.accessCount,
        sectionsViewed:    updated.sectionsViewed,
        interestSubmitted: updated.interestSubmitted,
      }});
    } catch (err) {
      console.error('investor-profile POST error:', err.message);
      return json(500, { error: err.message });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
