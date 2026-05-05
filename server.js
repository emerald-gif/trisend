// ════════════════════════════════════════════════════════════════════════════════
// Trisend — Production Express Server
// ════════════════════════════════════════════════════════════════════════════════
//
// Features:
//   • Serves dashboard.html, login.html, signup.html, index.html as static files
//   • Short link redirect with real IP geolocation (ip-api.com)
//   • Click tracking stored in Firestore subcollection
//   • Link stats API endpoint
//   • Paystack payment verification
//   • Paystack webhook (signature-validated)
//
// Setup:
//   1. npm install
//   2. Set environment variables (see below)
//   3. node server.js  OR  npm start
//
// Required environment variables:
//   FIREBASE_SERVICE_ACCOUNT  — Full JSON string of your Firebase service account key
//   PAYSTACK_SECRET_KEY       — Your Paystack secret key (sk_live_... or sk_test_...)
//   PORT                      — Server port (default 3000)
//
// ════════════════════════════════════════════════════════════════════════════════

'use strict';

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const path    = require('path');
const admin   = require('firebase-admin');

// ── App setup ─────────────────────────────────────────────────────────────────
const app  = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

// ── Firebase Admin init ───────────────────────────────────────────────────────
let firebaseReady = false;

(function initFirebase() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) {
    console.warn('[firebase] ⚠  FIREBASE_SERVICE_ACCOUNT not set — Firestore features disabled');
    return;
  }
  try {
    const serviceAccount = JSON.parse(raw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    firebaseReady = true;
    console.log('[firebase] ✓  Admin SDK initialized');
  } catch (err) {
    console.error('[firebase] ✗  Failed to parse service account JSON:', err.message);
  }
})();

function firestore() {
  if (!firebaseReady) throw new Error('Firebase is not initialized');
  return admin.firestore();
}

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Request logger (simple, no pino needed) ───────────────────────────────────
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.url}`);
  next();
});

// ── Serve static files ────────────────────────────────────────────────────────
// All HTML / JS files should live in the same directory as server.js
app.use(express.static(path.join(__dirname)));

// ── Helpers ───────────────────────────────────────────────────────────────────
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || req.ip || '';
}

function isLocalIP(ip) {
  return (
    ip === '127.0.0.1'   ||
    ip === '::1'          ||
    ip === 'localhost'    ||
    ip.startsWith('192.168.') ||
    ip.startsWith('10.')  ||
    ip.startsWith('172.16.')
  );
}

function detectDevice(ua) {
  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(ua)) return 'Mobile';
  if (/ipad|tablet|kindle|playbook|silk/i.test(ua)) return 'Tablet';
  return 'Desktop';
}

function detectBrowser(ua) {
  if (/Edg\//i.test(ua))       return 'Edge';
  if (/OPR\/|Opera/i.test(ua)) return 'Opera';
  if (/SamsungBrowser/i.test(ua)) return 'Samsung';
  if (/Chrome/i.test(ua))      return 'Chrome';
  if (/Firefox/i.test(ua))     return 'Firefox';
  if (/Safari/i.test(ua))      return 'Safari';
  if (/MSIE|Trident/i.test(ua)) return 'IE';
  return 'Other';
}

async function geoLookup(ip) {
  if (isLocalIP(ip)) return { country: 'Local', city: 'Local', region: null };
  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 3000);
    const response   = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,regionName,city`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);
    if (!response.ok) return { country: null, city: null, region: null };
    const data = await response.json();
    if (data.status !== 'success') return { country: null, city: null, region: null };
    return { country: data.country || null, city: data.city || null, region: data.regionName || null };
  } catch {
    return { country: null, city: null, region: null };
  }
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/healthz', (_req, res) => {
  res.json({ status: 'ok', firebase: firebaseReady, ts: new Date().toISOString() });
});

// ════════════════════════════════════════════════════════════════════════════════
// SHORT LINK REDIRECT
// GET /api/links/redirect/:code
// ════════════════════════════════════════════════════════════════════════════════
app.get('/api/links/redirect/:code', async (req, res) => {
  const { code } = req.params;

  if (!code || !/^[a-z0-9\-_]{2,64}$/i.test(code)) {
    return res.status(400).send(errorPage('Invalid link', 'This short link code is not valid.'));
  }

  if (!firebaseReady) {
    return res.status(503).send(errorPage('Service unavailable', 'The server is not fully configured.'));
  }

  let linkSnap;
  try {
    linkSnap = await firestore().collection('shortlinks').doc(code).get();
  } catch (err) {
    console.error('[redirect] Firestore read error:', err.message);
    return res.status(500).send(errorPage('Server error', 'Something went wrong. Please try again.'));
  }

  if (!linkSnap.exists) {
    return res.status(404).send(errorPage('Link not found', 'This short link does not exist or has been deleted.'));
  }

  const link = linkSnap.data();

  if (!link.active) {
    return res.status(410).send(errorPage('Link deactivated', 'This link has been deactivated by its owner.'));
  }

  if (link.expiresAt && new Date(link.expiresAt) < new Date()) {
    return res.status(410).send(errorPage('Link expired', 'This short link has expired and is no longer active.'));
  }

  if (link.clickLimit && typeof link.clicks === 'number' && link.clicks >= link.clickLimit) {
    return res.status(410).send(errorPage('Click limit reached', 'This link has reached its maximum number of clicks.'));
  }

  // Redirect immediately before recording analytics
  res.redirect(302, link.originalUrl);

  // Record click asynchronously (don't block the redirect)
  setImmediate(async () => {
    try {
      const ip      = getClientIP(req);
      const ua      = req.headers['user-agent'] || '';
      const device  = detectDevice(ua);
      const browser = detectBrowser(ua);
      const referer = req.headers['referer'] || null;
      const geo     = await geoLookup(ip);

      const clickData = {
        clickedAt: new Date().toISOString(),
        ip,
        country:  geo.country,
        city:     geo.city,
        region:   geo.region,
        device,
        browser,
        referer,
        userAgent: ua.slice(0, 300),
      };

      const docRef = firestore().collection('shortlinks').doc(code);
      await Promise.all([
        docRef.collection('clicks').add(clickData),
        docRef.update({ clicks: admin.firestore.FieldValue.increment(1) }),
      ]);

      console.log(`[redirect] ✓ ${code} → ${link.originalUrl.slice(0, 60)} | ${geo.country || '?'} | ${device}`);
    } catch (err) {
      console.error('[redirect] Click record error:', err.message);
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════════
// LINK STATS
// GET /api/links/stats?code=xxx
// ════════════════════════════════════════════════════════════════════════════════
app.get('/api/links/stats', async (req, res) => {
  const { code } = req.query;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Query param `code` is required.' });
  }
  if (!firebaseReady) {
    return res.status(503).json({ error: 'Firebase not initialized.' });
  }

  try {
    const docRef = firestore().collection('shortlinks').doc(code);
    const snap   = await docRef.get();
    if (!snap.exists) return res.status(404).json({ error: 'Link not found.' });

    const link     = snap.data();
    const cSnap    = await docRef.collection('clicks').orderBy('clickedAt', 'desc').limit(200).get();
    const clicks   = cSnap.docs.map(d => d.data());

    function countBy(arr, key) {
      return arr.reduce((acc, c) => {
        const k = c[key] || 'Unknown';
        acc[k] = (acc[k] || 0) + 1;
        return acc;
      }, {});
    }

    function toSortedArray(obj) {
      return Object.entries(obj)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);
    }

    res.json({
      code,
      originalUrl:  link.originalUrl,
      alias:        link.alias || null,
      active:       link.active,
      createdAt:    link.createdAt,
      expiresAt:    link.expiresAt || null,
      clickLimit:   link.clickLimit || null,
      totalClicks:  link.clicks || 0,
      countries:    toSortedArray(countBy(clicks, 'country')),
      cities:       toSortedArray(countBy(clicks, 'city')).slice(0, 10),
      devices:      toSortedArray(countBy(clicks, 'device')),
      browsers:     toSortedArray(countBy(clicks, 'browser')),
      recentClicks: clicks.slice(0, 50).map(c => ({
        country:   c.country  || null,
        city:      c.city     || null,
        device:    c.device   || null,
        browser:   c.browser  || null,
        clickedAt: c.clickedAt,
        referer:   c.referer  || null,
      })),
    });
  } catch (err) {
    console.error('[stats] Error:', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// PAYSTACK PAYMENT VERIFICATION
// POST /api/payments/verify
// Body: { reference: string, userId: string }
// ════════════════════════════════════════════════════════════════════════════════
app.post('/api/payments/verify', async (req, res) => {
  const { reference, userId } = req.body || {};

  if (!reference || typeof reference !== 'string') {
    return res.status(400).json({ error: '`reference` is required.' });
  }
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: '`userId` is required.' });
  }

  const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
  if (!PAYSTACK_SECRET) {
    console.error('[payment] PAYSTACK_SECRET_KEY not set');
    return res.status(500).json({ error: 'Payment service not configured.' });
  }

  try {
    const paystackRes = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' } }
    );

    if (!paystackRes.ok) {
      const text = await paystackRes.text();
      console.error('[payment] Paystack verify failed:', paystackRes.status, text.slice(0, 200));
      return res.status(400).json({ error: 'Could not verify payment with Paystack.' });
    }

    const json = await paystackRes.json();

    if (!json.status || json.data?.status !== 'success') {
      return res.status(400).json({ error: 'Payment was not successful.', paystackStatus: json.data?.status || 'unknown' });
    }

    // Upgrade user in Firestore
    if (firebaseReady) {
      await firestore().collection('users').doc(userId).set({
        plan:              'premium',
        upgradedAt:        new Date().toISOString(),
        paystackReference: reference,
        amount:            json.data?.amount || null,
        currency:          json.data?.currency || 'NGN',
      }, { merge: true });
      console.log(`[payment] ✓ User ${userId} upgraded to premium via ${reference}`);
    }

    res.json({ success: true, plan: 'premium', message: 'Payment verified. You are now a Premium member!' });
  } catch (err) {
    console.error('[payment] Error:', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// PAYSTACK WEBHOOK
// POST /api/webhook/paystack
// ════════════════════════════════════════════════════════════════════════════════

// Raw body parser for webhook signature validation
app.use('/api/webhook/paystack', express.raw({ type: 'application/json' }));

app.post('/api/webhook/paystack', async (req, res) => {
  const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;

  // Validate signature
  if (PAYSTACK_SECRET) {
    const signature = req.headers['x-paystack-signature'];
    if (!signature) {
      console.warn('[webhook] Missing x-paystack-signature header');
      return res.status(400).json({ error: 'Missing signature.' });
    }
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body));
    const expected = crypto.createHmac('sha512', PAYSTACK_SECRET).update(rawBody).digest('hex');
    if (expected !== signature) {
      console.warn('[webhook] Invalid signature — possible spoofed request');
      return res.status(400).json({ error: 'Invalid signature.' });
    }
  }

  // Parse body (may be Buffer from raw middleware)
  let event;
  try {
    event = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString()) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body.' });
  }

  console.log(`[webhook] Event received: ${event.event}`);

  if (event.event === 'charge.success' && event.data?.status === 'success' && firebaseReady) {
    const userId    = event.data?.metadata?.userId;
    const reference = event.data?.reference;

    if (userId) {
      try {
        await firestore().collection('users').doc(userId).set({
          plan:              'premium',
          upgradedAt:        new Date().toISOString(),
          paystackReference: reference,
          amount:            event.data?.amount || null,
          currency:          event.data?.currency || 'NGN',
        }, { merge: true });
        console.log(`[webhook] ✓ User ${userId} upgraded to premium`);
      } catch (err) {
        console.error('[webhook] Failed to update user:', err.message);
      }
    } else {
      console.warn('[webhook] charge.success received but no metadata.userId in event');
    }
  }

  // Always respond 200 to prevent Paystack retries
  res.status(200).json({ ok: true });
});

// ── 404 handler for /api routes ───────────────────────────────────────────────
app.use('/api/*', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// ── SPA fallback — serve index.html for all non-API routes ───────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Trisend server running on http://localhost:${PORT}`);
  console.log(`   Firebase: ${firebaseReady ? '✓ connected' : '✗ not configured'}`);
  console.log(`   Paystack: ${process.env.PAYSTACK_SECRET_KEY ? '✓ configured' : '✗ not configured'}\n`);
});

// ── Error page helper ─────────────────────────────────────────────────────────
function errorPage(title, message) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} — Trisend</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet"/>
<style>body{font-family:'Inter',sans-serif;}</style></head>
<body class="min-h-screen bg-gray-50 flex items-center justify-center p-6">
<div class="text-center max-w-sm">
  <div class="text-6xl mb-6">🔗</div>
  <h1 class="text-xl font-black text-gray-900 mb-2">${title}</h1>
  <p class="text-sm text-gray-500 mb-8">${message}</p>
  <a href="/" class="inline-block px-5 py-2 bg-blue-600 text-white rounded font-semibold text-sm hover:bg-blue-700">
    Go to Trisend
  </a>
</div>
</body></html>`;
}
