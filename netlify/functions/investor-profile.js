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

  // ── GET: look up investor by email or validate re-access token ────────────
  if (event.httpMethod === 'GET') {
    const { email, token, eid } = event.queryStringParameters || {};

    // Token validation path
    if (token && eid) {
      try {
        const store    = getProfileStore();
        const list     = await store.list();
        let   found    = null;

        for (const entry of list.blobs) {
          const profile = await store.get(entry.key, { type: 'json' });
          if (profile && profile.envelopeId === eid) { found = profile; break; }
        }

        if (!found) return json(404, { valid: false, reason: 'not_found' });

        const expected = generateAccessToken(eid, found.email);
        if (token !== expected) return json(403, { valid: false, reason: 'invalid_token' });

        // Update last access
        found.lastAccessAt = new Date().toISOString();
        found.accessCount  = (found.accessCount || 0) + 1;
        await store.setJSON(emailKey(found.email), found);

        return json(200, { valid: true, profile: {
          name:      found.name,
          email:     found.email,
          company:   found.company || '',
          ndaSigned: found.ndaSigned,
          ndaSignedAt: found.ndaSignedAt,
        }});
      } catch (err) {
        return json(500, { valid: false, reason: err.message });
      }
    }

    // Email lookup path
    if (email) {
      try {
        const store   = getProfileStore();
        const key     = emailKey(email);
        const profile = await store.get(key, { type: 'json' });

        if (!profile) return json(200, { exists: false });

        return json(200, {
          exists:    true,
          ndaSigned: profile.ndaSigned || false,
          envelopeId: profile.envelopeId || null,
          name:      profile.name || '',
        });
      } catch (err) {
        return json(500, { error: err.message });
      }
    }

    return json(400, { error: 'email or (token + eid) required' });
  }

  // ── POST: create or update profile ────────────────────────────────────────
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); }
    catch { return json(400, { error: 'Invalid JSON' }); }

    const { email, name, company, phone, envelopeId } = body;
    if (!email) return json(400, { error: 'email required' });

    try {
      const store = getProfileStore();
      const key   = emailKey(email);

      // Merge with any existing profile
      const existing = (await store.get(key, { type: 'json' })) || {};
      const updated  = {
        ...existing,
        email:     email.toLowerCase().trim(),
        name:      name      || existing.name      || '',
        company:   company   || existing.company   || '',
        phone:     phone     || existing.phone     || '',
        envelopeId: envelopeId || existing.envelopeId || null,
        createdAt:  existing.createdAt || new Date().toISOString(),
        updatedAt:  new Date().toISOString(),
      };

      await store.setJSON(key, updated);
      return json(200, { saved: true });
    } catch (err) {
      return json(500, { error: err.message });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
