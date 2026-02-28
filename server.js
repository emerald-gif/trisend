/**
 * TRISEND SERVER v3.0
 * ──────────────────────────────────────────────────────────────
 * SETUP REQUIRED (add these to Render/env):
 *
 *  PAYSTACK_SECRET_KEY      → your Paystack secret key
 *  PAYSTACK_PUBLIC_KEY      → your Paystack public key
 *  FIREBASE_SERVICE_ACCOUNT → JSON string of Firebase service account
 *                             (Firebase Console → Project Settings → Service Accounts
 *                              → Generate new private key → copy JSON → paste as env var)
 * ──────────────────────────────────────────────────────────────
 */

const express  = require('express');
const path     = require('path');
const crypto   = require('crypto');
const https    = require('https');
const http     = require('http');

const app  = express();
const PORT = process.env.PORT || 3000;

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC_KEY;
const FIREBASE_PROJECT = 'trisend-e7250';

// ── Firebase Admin Setup ──────────────────────────────────────────────────────
let adminDb = null;
let FieldValue = null;

try {
  const admin = require('firebase-admin');
  const svcAccount = process.env.FIREBASE_SERVICE_ACCOUNT
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    : null;

  if (svcAccount && !admin.apps.length) {
    admin.initializeApp({ credential: admin.credential.cert(svcAccount) });
    adminDb   = admin.firestore();
    FieldValue = admin.firestore.FieldValue;
    console.log('🔥 Firebase Admin: ✅ Connected');
  } else {
    console.warn('⚠️  Firebase Admin: FIREBASE_SERVICE_ACCOUNT not set. Server-side tracking disabled.');
  }
} catch (e) {
  console.warn('⚠️  Firebase Admin init failed:', e.message);
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use('/webhook/paystack', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// ── Helpers ───────────────────────────────────────────────────────────────────
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
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
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

/** Get real visitor IP (handles Render / Cloudflare proxy headers) */
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(s => s.trim());
    // First non-private IP
    for (const ip of ips) {
      if (!isPrivateIP(ip)) return ip;
    }
    return ips[0];
  }
  return req.socket?.remoteAddress || '0.0.0.0';
}

function isPrivateIP(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|127\.|localhost)/i.test(ip);
}

/** Geo-lookup via ip-api.com (free, no key) */
function geoIP(ip) {
  return new Promise(resolve => {
    if (!ip || isPrivateIP(ip)) return resolve({ country: 'Local', city: 'Local', countryCode: 'XX', lat: 0, lon: 0 });
    const options = {
      hostname: 'ip-api.com',
      port: 80,
      path: `/json/${ip}?fields=country,regionName,city,countryCode,lat,lon,org`,
      method: 'GET',
      timeout: 3000,
    };
    const req = http.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX' }); }
      });
    });
    req.on('error', () => resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX' }));
    req.on('timeout', () => { req.destroy(); resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX' }); });
    req.end();
  });
}

/** Parse device & browser from User-Agent */
function parseUA(ua = '') {
  let device = 'Desktop';
  if (/android/i.test(ua)) device = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) device = 'iOS';
  else if (/mobile/i.test(ua)) device = 'Mobile';

  let browser = 'Other';
  if (/edg\//i.test(ua)) browser = 'Edge';
  else if (/opr\/|opera/i.test(ua)) browser = 'Opera';
  else if (/firefox\/\d/i.test(ua)) browser = 'Firefox';
  else if (/chrome\/\d/i.test(ua) && !/chromium|edg/i.test(ua)) browser = 'Chrome';
  else if (/safari\/\d/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';

  return { device, browser };
}

/** Lookup + redirect short link, record click */
async function handleShortLink(req, res) {
  const code = req.params.code;

  // Skip non-link paths
  const reserved = ['login', 'signup', 'dashboard', 'admin', 'api', 'webhook', 'health', 'favicon.ico', '_next'];
  if (reserved.some(r => code.toLowerCase().startsWith(r))) {
    return res.redirect('/');
  }

  try {
    let linkData = null;

    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) linkData = { id: snap.id, ...snap.data() };
    } else {
      // Fallback: Firestore REST API (requires public read rules on shortlinks)
      const restUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/shortlinks/${code}`;
      linkData = await new Promise(resolve => {
        const opts = { method: 'GET' };
        https.get(restUrl, opts, r => {
          let d = '';
          r.on('data', c => d += c);
          r.on('end', () => {
            try {
              const doc = JSON.parse(d);
              if (doc.fields) {
                const f = doc.fields;
                resolve({
                  originalUrl: f.originalUrl?.stringValue,
                  clicks: parseInt(f.clicks?.integerValue || 0),
                  expiresAt: f.expiresAt?.stringValue || null,
                  maxClicks: f.maxClicks?.integerValue ? parseInt(f.maxClicks.integerValue) : null,
                  password: f.password?.stringValue || null,
                });
              } else resolve(null);
            } catch { resolve(null); }
          });
        }).on('error', () => resolve(null));
      });
    }

    if (!linkData || !linkData.originalUrl) {
      return res.redirect(`/?err=notfound&code=${code}`);
    }

    // Check expiry
    if (linkData.expiresAt && new Date(linkData.expiresAt) < new Date()) {
      return res.redirect(`/?err=expired`);
    }

    // Check click limit
    if (linkData.maxClicks && (linkData.clicks || 0) >= linkData.maxClicks) {
      return res.redirect(`/?err=limit`);
    }

    // Password-protected links → show unlock page
    if (linkData.password) {
      return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Protected Link · Trisend</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0;}body{font-family:'Inter',sans-serif;background:#F8FAFC;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.box{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:40px;max-width:380px;width:100%;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);}
.icon{font-size:52px;margin-bottom:16px;}h2{font-size:20px;font-weight:800;margin-bottom:8px;}
p{font-size:13px;color:#64748B;margin-bottom:20px;}
input{width:100%;padding:10px 13px;border:1.5px solid #E2E8F0;border-radius:8px;font-family:'Inter',sans-serif;font-size:14px;margin-bottom:12px;outline:none;}
input:focus{border-color:#F97316;box-shadow:0 0 0 3px rgba(249,115,22,.1);}
button{width:100%;padding:11px;background:linear-gradient(135deg,#F97316,#EF4444);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;}
.err{color:#EF4444;font-size:12px;margin-top:8px;display:none;}</style></head>
<body><div class="box"><div class="icon">🔒</div><h2>Protected Link</h2><p>Enter the password to access this link.</p>
<input type="password" id="pwd" placeholder="Enter password…" onkeydown="if(event.key==='Enter')unlock()">
<button onclick="unlock()">Unlock & Open →</button>
<p class="err" id="err">Incorrect password. Try again.</p></div>
<script>
function unlock(){
  const p=document.getElementById('pwd').value;
  const enc=btoa(p);
  if(enc==='${linkData.password}'){window.location.href='${linkData.originalUrl}';}
  else{const e=document.getElementById('err');e.style.display='block';setTimeout(()=>e.style.display='none',3000);}
}
</script></body></html>`);
    }

    // Record click asynchronously
    recordClick(code, req).catch(e => console.error('Click record error:', e));

    // Direct redirect — no intermediate page
    return res.redirect(302, linkData.originalUrl);

  } catch (err) {
    console.error('Short link error:', err.message);
    return res.redirect(`/?err=error`);
  }
}

async function recordClick(code, req) {
  const ip      = getRealIP(req);
  const ua      = req.headers['user-agent'] || '';
  const referer = req.headers['referer'] || 'direct';
  const { device, browser } = parseUA(ua);
  const geo = await geoIP(ip);

  const clickData = {
    ip,
    country:     geo.country     || 'Unknown',
    countryCode: geo.countryCode || 'XX',
    city:        geo.city        || 'Unknown',
    region:      geo.regionName  || 'Unknown',
    lat:         geo.lat         || 0,
    lon:         geo.lon         || 0,
    device,
    browser,
    referer,
    ua: ua.slice(0, 250),
    ts: new Date(),
  };

  if (adminDb) {
    // Write to clicks subcollection
    await adminDb.collection('shortlinks').doc(code).collection('clicks').add(clickData);
    // Increment counter
    await adminDb.collection('shortlinks').doc(code).update({
      clicks: FieldValue.increment(1),
      lastClickAt: FieldValue.serverTimestamp(),
    });
  }
}

// ── Page Routes ───────────────────────────────────────────────────────────────
app.get('/',         (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login',    (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/signup',   (req, res) => res.sendFile(path.join(__dirname, 'signup.html')));
app.get('/dashboard',(req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// ── Short Link Redirect ───────────────────────────────────────────────────────
// Must be BEFORE the catch-all
app.get('/:code([a-zA-Z0-9_-]{3,})', handleShortLink);

// ── API: Verify Paystack Payment ──────────────────────────────────────────────
app.post('/api/verify-payment', async (req, res) => {
  const { reference, userId } = req.body;
  if (!reference || !userId)
    return res.status(400).json({ success: false, message: 'Missing reference or userId' });
  if (!PAYSTACK_SECRET)
    return res.status(500).json({ success: false, message: 'Payment service not configured' });

  try {
    const result = await paystackRequest('GET', `/transaction/verify/${reference}`);
    if (!result.status || result.data?.status !== 'success')
      return res.status(400).json({ success: false, message: 'Payment not successful' });

    const amount = result.data.amount;
    if (amount < 200000)
      return res.status(400).json({ success: false, message: 'Incorrect payment amount' });

    if (adminDb) {
      await adminDb.collection('users').doc(userId).update({
        plan: 'premium',
        paystackRef: reference,
        upgradedAt: FieldValue.serverTimestamp(),
      });
    }

    console.log(`✅ Payment verified: ${reference} | User: ${userId} | ₦${amount / 100}`);
    return res.json({
      success: true,
      data: { reference, amount: amount / 100, email: result.data.customer?.email },
    });
  } catch (err) {
    console.error('Payment verification error:', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed.' });
  }
});

// ── API: Config ───────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({
    paystackPublicKey: PAYSTACK_PUBLIC || '',
    platform: 'Trisend',
  });
});

// ── API: Health ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok', platform: 'Trisend',
    timestamp: new Date().toISOString(),
    paystack: PAYSTACK_SECRET ? 'configured' : 'missing',
    firebase: adminDb ? 'connected' : 'client-only',
  });
});

// ── Paystack Webhook ──────────────────────────────────────────────────────────
app.post('/webhook/paystack', async (req, res) => {
  res.sendStatus(200);
  if (!PAYSTACK_SECRET) return;

  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('⚠️  Invalid Paystack webhook signature');
    return;
  }

  let event;
  try { event = JSON.parse(req.body); } catch { return; }
  console.log(`📦 Webhook: ${event.event}`);

  if (event.event === 'charge.success') {
    const { reference, amount, customer, metadata } = event.data;
    const userId = metadata?.userId;
    if (amount >= 200000 && userId && adminDb) {
      try {
        await adminDb.collection('users').doc(userId).update({
          plan: 'premium',
          paystackRef: reference,
          upgradedAt: FieldValue.serverTimestamp(),
        });
        console.log(`⭐ Premium via webhook: ${userId}`);
      } catch (e) { console.error('Webhook Firestore update failed:', e.message); }
    }
  }
});

// ── Catch-all ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ████████╗██████╗ ██╗███████╗███████╗███╗   ██╗██████╗ ');
  console.log('  ╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝████╗  ██║██╔══██╗');
  console.log('     ██║   ██████╔╝██║███████╗█████╗  ██╔██╗ ██║██║  ██║');
  console.log('     ██║   ██╔══██╗██║╚════██║██╔══╝  ██║╚██╗██║██║  ██║');
  console.log('     ██║   ██║  ██║██║███████║███████╗██║ ╚████║██████╔╝');
  console.log('     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ ');
  console.log('');
  console.log(`  🚀 Trisend v3.0 running on port ${PORT}`);
  console.log(`  💳 Paystack: ${PAYSTACK_SECRET ? '✅' : '❌ Missing PAYSTACK_SECRET_KEY'}`);
  console.log(`  🔥 Firebase Admin: ${adminDb ? '✅ Connected' : '⚠️  Set FIREBASE_SERVICE_ACCOUNT for tracking'}`);
  console.log('');
});
