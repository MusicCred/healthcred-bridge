/**
 * HealthCred — Bridge Round Investor Portal
 * Netlify Function: admin-profiles.js
 *
 * Returns all investor profiles for the Chad admin dashboard.
 * Password-protected via ADMIN_PASSWORD env var.
 *
 * GET  /.netlify/functions/admin-profiles?password=...  → all profiles
 * POST /.netlify/functions/admin-profiles               → update notes on a profile
 *   Body: { password, email, notes }
 *
 * Environment variables:
 *   ADMIN_PASSWORD  = (set in Netlify dashboard — share only with Chad)
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

function checkPassword(provided) {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) return false; // not configured — block all access
  // Constant-time compare
  try {
    return crypto.timingSafeEqual(
      Buffer.from(provided || ''),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
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

  // ── GET: list all profiles ────────────────────────────────────────────────
  if (event.httpMethod === 'GET') {
    const q        = event.queryStringParameters || {};
    const password = q.password || '';

    if (!checkPassword(password)) {
      return json(401, { error: 'Unauthorized' });
    }

    try {
      const store        = getStore({ name: 'investor-profiles', consistency: 'strong' });
      const { blobs }    = await store.list();
      const profiles     = [];

      for (const { key } of blobs) {
        const p = await store.get(key, { type: 'json' });
        if (p) {
          profiles.push({
            name:              p.name              || '',
            email:             p.email             || '',
            company:           p.company           || '',
            phone:             p.phone             || '',
            ndaSigned:         p.ndaSigned         || false,
            ndaSignedAt:       p.ndaSignedAt       || null,
            envelopeId:        p.envelopeId        || null,
            createdAt:         p.createdAt         || null,
            lastAccessAt:      p.lastAccessAt      || null,
            accessCount:       p.accessCount       || 0,
            sectionsViewed:    p.sectionsViewed    || [],
            interestSubmitted: p.interestSubmitted || false,
            interestLevel:     p.interestLevel     || null,
            notes:             p.notes             || '',
          });
        }
      }

      // Sort by most recent access
      profiles.sort((a, b) => {
        const ta = a.lastAccessAt ? new Date(a.lastAccessAt).getTime() : 0;
        const tb = b.lastAccessAt ? new Date(b.lastAccessAt).getTime() : 0;
        return tb - ta;
      });

      return json(200, { profiles, count: profiles.length });
    } catch (err) {
      console.error('admin-profiles GET error:', err.message);
      return json(500, { error: err.message });
    }
  }

  // ── POST: update notes on a profile ──────────────────────────────────────
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); }
    catch { return json(400, { error: 'Invalid JSON' }); }

    if (!checkPassword(body.password)) {
      return json(401, { error: 'Unauthorized' });
    }

    const { email, notes } = body;
    if (!email) return json(400, { error: 'email required' });

    try {
      const store   = getStore({ name: 'investor-profiles', consistency: 'strong' });
      const key     = emailKey(email);
      const profile = await store.get(key, { type: 'json' });
      if (!profile) return json(404, { error: 'Profile not found' });

      profile.notes = notes !== undefined ? notes : profile.notes;
      await store.setJSON(key, profile);
      return json(200, { success: true });
    } catch (err) {
      console.error('admin-profiles POST error:', err.message);
      return json(500, { error: err.message });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
