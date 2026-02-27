const express = require('express');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Environment Variables ─────────────────────────────────────────────────────
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC_KEY;
const FIREBASE_PROJECT = 'trisend-e7250';

// ── Firebase Admin (via REST API — no extra SDK needed) ───────────────────────
// We use Firestore REST API with a service account token.
// For simplicity on Render free tier, we call Firestore via REST.
// To use Firebase Admin SDK instead, npm install firebase-admin and see bottom note.

// ── Middleware ────────────────────────────────────────────────────────────────
// IMPORTANT: Raw body needed for Paystack webhook signature check
app.use('/webhook/paystack', express.raw({ type: 'application/json' }));

// JSON body for all other routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve static files (your index.html)
app.use(express.static(path.join(__dirname)));

// ── Paystack Helper ───────────────────────────────────────────────────────────
function paystackRequest(method, endpoint, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: endpoint,
      method,
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        'Content-Type': 'application/json',
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Invalid JSON from Paystack')); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Firestore REST Helper ─────────────────────────────────────────────────────
// Uses Firebase Firestore REST API to update user documents.
// Requires FIREBASE_WEB_API_KEY env var OR Firebase Admin SDK (see bottom).
async function updateUserPremium(userId, paystackRef) {
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/users/${userId}`;
  const body = JSON.stringify({
    fields: {
      plan: { stringValue: 'premium' },
      paystackRef: { stringValue: paystackRef },
      upgradedAt: { timestampValue: new Date().toISOString() },
    },
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'firestore.googleapis.com',
      port: 443,
      path: `/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/users/${userId}?updateMask.fieldPaths=plan&updateMask.fieldPaths=paystackRef&updateMask.fieldPaths=upgradedAt`,
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    // If you have a FIREBASE_TOKEN env var (from service account), use it:
    if (process.env.FIREBASE_TOKEN) {
      options.headers['Authorization'] = `Bearer ${process.env.FIREBASE_TOKEN}`;
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── ROUTE: Verify Payment (called from frontend after Paystack callback) ──────
// Frontend calls this to double-check payment is legit before granting premium
app.post('/api/verify-payment', async (req, res) => {
  const { reference, userId } = req.body;

  if (!reference || !userId) {
    return res.status(400).json({ success: false, message: 'Missing reference or userId' });
  }

  if (!PAYSTACK_SECRET) {
    return res.status(500).json({ success: false, message: 'Payment service not configured' });
  }

  try {
    // Verify with Paystack
    const result = await paystackRequest('GET', `/transaction/verify/${reference}`);

    if (!result.status || result.data?.status !== 'success') {
      return res.status(400).json({ success: false, message: 'Payment not successful' });
    }

    const amount = result.data.amount; // in kobo
    if (amount < 200000) { // ₦2,000 minimum
      return res.status(400).json({ success: false, message: 'Incorrect payment amount' });
    }

    // Record payment in Firestore via REST
    try {
      await updateUserPremium(userId, reference);
    } catch (fbErr) {
      // Firebase REST update might fail if no auth token set
      // The frontend also updates Firestore directly, so this is a backup
      console.warn('Firestore REST update skipped (use Firebase Admin SDK for full server-side control):', fbErr.message);
    }

    // Log successful payment
    console.log(`✅ Payment verified: ${reference} | User: ${userId} | Amount: ₦${amount / 100}`);

    return res.json({
      success: true,
      message: 'Payment verified successfully',
      data: {
        reference,
        amount: amount / 100,
        email: result.data.customer?.email,
        paidAt: result.data.paid_at,
      },
    });

  } catch (err) {
    console.error('Payment verification error:', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed. Please contact support.' });
  }
});

// ── ROUTE: Paystack Webhook ───────────────────────────────────────────────────
// Paystack sends events here automatically (charge.success, etc.)
// Set this URL in your Paystack Dashboard → Settings → API Keys & Webhooks
app.post('/webhook/paystack', async (req, res) => {
  // Always respond 200 first so Paystack doesn't retry
  res.sendStatus(200);

  // Validate signature
  if (!PAYSTACK_SECRET) return;

  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET)
    .update(req.body)
    .digest('hex');

  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('⚠️  Invalid Paystack webhook signature');
    return;
  }

  let event;
  try { event = JSON.parse(req.body); }
  catch (e) { return; }

  console.log(`📦 Paystack Webhook: ${event.event}`);

  // Handle successful charge
  if (event.event === 'charge.success') {
    const data = event.data;
    const reference = data.reference;
    const amount = data.amount;
    const email = data.customer?.email;
    const metadata = data.metadata || {};
    const userId = metadata.userId;

    console.log(`💰 Charge success: ${reference} | ${email} | ₦${amount / 100}`);

    if (amount >= 200000 && userId) {
      try {
        await updateUserPremium(userId, reference);
        console.log(`⭐ Premium granted via webhook to user: ${userId}`);
      } catch (e) {
        console.error('Webhook Firestore update failed:', e.message);
      }
    }
  }
});

// ── ROUTE: Get Paystack Public Key (safe to expose) ───────────────────────────
app.get('/api/config', (req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC || '',
    platform: 'Trisend',
  });
});

// ── ROUTE: Health Check ───────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    platform: 'Trisend',
    timestamp: new Date().toISOString(),
    paystack: PAYSTACK_SECRET ? 'configured' : 'missing',
  });
});

// ── SPA Catch-All ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ████████╗██████╗ ██╗███████╗███████╗███╗   ██╗██████╗ ');
  console.log('  ╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝████╗  ██║██╔══██╗');
  console.log('     ██║   ██████╔╝██║███████╗█████╗  ██╔██╗ ██║██║  ██║');
  console.log('     ██║   ██╔══██╗██║╚════██║██╔══╝  ██║╚██╗██║██║  ██║');
  console.log('     ██║   ██║  ██║██║███████║███████╗██║ ╚████║██████╔╝');
  console.log('     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ ');
  console.log('');
  console.log(`  🚀 Trisend running on port ${PORT}`);
  console.log(`  💳 Paystack: ${PAYSTACK_SECRET ? '✅ Configured' : '❌ Missing PAYSTACK_SECRET_KEY'}`);
  console.log(`  🔥 Firebase Project: ${FIREBASE_PROJECT}`);
  console.log(`  🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('');
});