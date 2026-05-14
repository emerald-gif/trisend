/**
 * TRISEND SERVER v3.2 — SECURED
 * ──────────────────────────────────────────────────────────────
 * SETUP REQUIRED — add these to Render / environment:
 *
 *  PAYSTACK_SECRET_KEY      → your Paystack secret key
 *  PAYSTACK_PUBLIC_KEY      → your Paystack public key
 *  FIREBASE_SERVICE_ACCOUNT → JSON string of Firebase service account
 *                             (Firebase Console → Project Settings →
 *                              Service Accounts → Generate new private key
 *                              → copy full JSON → paste as single env var)
 * ──────────────────────────────────────────────────────────────
 */

const express  = require('express');
const path     = require('path');
const crypto   = require('crypto');
const https    = require('https');
const http     = require('http');

const app  = express();
const PORT = process.env.PORT || 3000;

const PAYSTACK_SECRET  = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PUBLIC  = process.env.PAYSTACK_PUBLIC_KEY;
const FIREBASE_PROJECT = 'trisend-e7250';

// ── Disable Express fingerprinting ────────────────────────────────────────────
app.disable('x-powered-by');

// ── In-memory rate limiter (no extra deps needed) ─────────────────────────────
// Tracks: { count, firstHit, blocked }
const _rateBuckets = new Map();

/**
 * createRateLimiter(maxHits, windowMs, blockMs)
 * maxHits  — allowed requests per window
 * windowMs — sliding window in ms
 * blockMs  — how long to block after exceeding (0 = just reset)
 */
function createRateLimiter(maxHits, windowMs, blockMs = 0) {
  return function rateLimiter(req, res, next) {
    // Key = IP + route prefix so limits are per-endpoint not global
    const ip  = getRealIP(req);
    const key = ip + '|' + req.path.slice(0, 30);
    const now = Date.now();
    const bucket = _rateBuckets.get(key) || { count: 0, firstHit: now, blocked: false, blockedAt: 0 };

    // Check if currently blocked
    if (bucket.blocked) {
      if (blockMs && now - bucket.blockedAt < blockMs) {
        const retryAfter = Math.ceil((blockMs - (now - bucket.blockedAt)) / 1000);
        res.set('Retry-After', String(retryAfter));
        return res.status(429).json({ success: false, message: 'Too many requests. Please wait before trying again.' });
      }
      // Block expired — reset
      bucket.blocked = false; bucket.count = 0; bucket.firstHit = now;
    }

    // Slide window
    if (now - bucket.firstHit > windowMs) {
      bucket.count = 0; bucket.firstHit = now;
    }

    bucket.count++;
    if (bucket.count > maxHits) {
      bucket.blocked = true; bucket.blockedAt = now;
      _rateBuckets.set(key, bucket);
      const retryAfter = Math.ceil((blockMs || windowMs) / 1000);
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ success: false, message: 'Too many requests. Please slow down.' });
    }
    _rateBuckets.set(key, bucket);
    next();
  };
}

// Cleanup stale buckets every 10 min so memory doesn't grow forever
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000; // 30 min
  for (const [key, b] of _rateBuckets.entries()) {
    if (b.firstHit < cutoff) _rateBuckets.delete(key);
  }
}, 10 * 60 * 1000);

// Pre-built limiters
const limiterGeneral  = createRateLimiter(120,  60_000, 0);           // 120/min general
const limiterAPI      = createRateLimiter(60,   60_000, 0);           // 60/min API
const limiterPayment  = createRateLimiter(10,   60_000, 5 * 60_000);  // 10/min, block 5 min
const limiterUnlock   = createRateLimiter(5,    60_000, 10 * 60_000); // 5 attempts/min, block 10 min (brute-force)
const limiterBioCheck = createRateLimiter(20,   60_000, 0);           // 20/min username checks
const limiterWebhook  = createRateLimiter(200,  60_000, 0);           // 200/min for Paystack

// ── Open redirect protection ──────────────────────────────────────────────────
const ALLOWED_SCHEMES = /^https?:\/\//i;
function isSafeURL(url) {
  if (!url || typeof url !== 'string') return false;
  if (!ALLOWED_SCHEMES.test(url.trim())) return false;
  // Block javascript:, data:, vbscript: and other schemes
  if (/^(javascript|data|vbscript|file|blob):/i.test(url.trim())) return false;
  return true;
}
function safeRedirect(res, url, code = 302) {
  if (!isSafeURL(url)) return res.redirect(code, '/');
  return res.redirect(code, url);
}

// ── Input sanitisation ────────────────────────────────────────────────────────
function sanitizeCode(code) {
  if (!code || typeof code !== 'string') return '';
  return code.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 50);
}
function sanitizeUserId(uid) {
  if (!uid || typeof uid !== 'string') return '';
  return uid.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
}
function sanitizeUsername(u) {
  if (!u || typeof u !== 'string') return '';
  return u.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 30);
}

// ── Firebase Admin Setup ──────────────────────────────────────────────────────
let adminDb   = null;
let FieldValue = null;

try {
  const admin      = require('firebase-admin');
  const svcAccount = process.env.FIREBASE_SERVICE_ACCOUNT
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    : null;

  if (svcAccount && !admin.apps.length) {
    admin.initializeApp({ credential: admin.credential.cert(svcAccount) });
    adminDb    = admin.firestore();
    FieldValue = admin.firestore.FieldValue;
    console.log('🔥 Firebase Admin: ✅ Connected');
  } else {
    console.warn('⚠️  Firebase Admin: FIREBASE_SERVICE_ACCOUNT not set. Server-side tracking disabled.');
  }
} catch (e) {
  console.warn('⚠️  Firebase Admin init failed:', e.message);
}

// ── Middleware ────────────────────────────────────────────────────────────────
// Paystack webhook needs raw body for HMAC verification
app.use('/webhook/paystack', express.raw({ type: 'application/json' }));

// Body size limits — prevent payload flooding
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '32kb' }));

// ── Security Headers (replaces helmet, zero deps) ─────────────────────────────
app.use((req, res, next) => {
  // Prevent MIME-type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking — use SAMEORIGIN (not DENY) so Firebase auth
  // redirect handler can briefly frame the page during OAuth handshake
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  // XSS filter (legacy browsers)
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Referrer policy — don't leak full URL to third parties
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Permissions policy — block sensors/camera/mic access
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  // HSTS — force HTTPS for 1 year (only on prod)
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  // Content Security Policy
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    // apis.google.com is what Firebase redirect flow actually loads scripts from (different to www.googleapis.com)
    "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://js.paystack.co https://cdnjs.cloudflare.com https://www.googleapis.com https://fonts.googleapis.com https://accounts.google.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://paystack.com https://checkout.paystack.com https://accounts.google.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    // connect-src: Firebase Auth + Firestore + Paystack + geo providers + Google OAuth
    "connect-src 'self' https://api.paystack.co https://firestore.googleapis.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://*.firebaseio.com https://ip-api.com https://ipwho.is https://freeipapi.com https://www.googleapis.com https://apis.google.com https://paystack.com https://*.paystack.com https://accounts.google.com https://oauth2.googleapis.com https://openidconnect.googleapis.com",
    // frame-src: Firebase auth handler + Google OAuth
    "frame-src 'self' https://js.paystack.co https://checkout.paystack.com https://paystack.com https://trisend-e7250.firebaseapp.com https://accounts.google.com https://apis.google.com",
    // frame-ancestors: allows Firebase auth redirect handler to embed this page briefly
    "frame-ancestors 'self' https://trisend-e7250.firebaseapp.com https://accounts.google.com",
    "object-src 'none'",
    "base-uri 'self'",
    // form-action: MUST include firebaseapp.com — redirect flow posts from Google back through it
    "form-action 'self' https://trisend-e7250.firebaseapp.com https://accounts.google.com",
    "upgrade-insecure-requests",
  ].join('; '));
  // CORS — only allow same origin + known clients
  const origin = req.headers.origin;
  const allowedOrigins = [
    'https://trisend.onrender.com',
    'http://localhost:3000',
    'http://localhost:5000',
  ];
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// General rate limit on all routes
app.use(limiterGeneral);

// Static files
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
      res.on('data', c => (data += c));
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

/** Get real visitor IP — handles Render / Cloudflare proxy headers.
 *
 *  HOW x-forwarded-for works on Render:
 *  Render prepends the real client IP to the LEFT of the header.
 *  Format: "RealClientIP, RenderProxy1, RenderProxy2"
 *  So the LEFTMOST non-private IP is always the actual visitor.
 *
 *  Previous rightmost-first logic was wrong — it often returned
 *  Render's own US/UK datacenter IP instead of the visitor's Nigerian IP.
 */
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(s => s.trim()).filter(Boolean);
    // Leftmost non-private = real client IP on Render
    for (const ip of ips) {
      if (!isPrivateIP(ip)) return ip;
    }
    return ips[0];
  }
  // Strip IPv6-mapped IPv4 prefix (::ffff:x.x.x.x → x.x.x.x)
  const raw = req.socket?.remoteAddress || '0.0.0.0';
  return raw.replace(/^::ffff:/, '');
}

function isPrivateIP(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|127\.|localhost)/i.test(ip);
}

/**
 * Nigerian ISP org name patterns — used as tiebreaker when providers disagree.
 * Nigerian carriers (MTN, Airtel, Glo, 9mobile) route through UK/US peering
 * nodes, but their AS org name still contains the carrier name.
 */
const NIGERIAN_ORG_PATTERNS = [
  /\bmtn\b/i, /\bairtel\b/i, /\bglo\b/i, /\b9mobile\b/i,
  /\bnitel\b/i, /\bcobranet\b/i, /\bswitchtelecoms\b/i,
  /\bspectranet\b/i, /\bswift\b/i, /\bipnx\b/i,
  /\bnigeria\b/i, /\bnigcomsat\b/i, /\bcybernet\b/i,
];

function looksNigerian(org = '') {
  return NIGERIAN_ORG_PATTERNS.some(p => p.test(org));
}

/** Single provider fetch — returns null on failure */
function fetchGeo(hostname, path, port, useHttps, parseResult, timeoutMs = 3500) {
  return new Promise(resolve => {
    const lib = useHttps ? https : http;
    const opts = { hostname, port, path, method: 'GET', timeout: timeoutMs };
    const req = lib.request(opts, res => {
      let d = '';
      res.on('data', c => (d += c));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          resolve(parseResult(parsed));
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

/**
 * geoIP — queries multiple providers, uses consensus + Nigerian org fallback.
 *
 * Providers (all free, no API key):
 *   1. ip-api.com        — primary, has org field
 *   2. ipwho.is          — secondary HTTPS, fast
 *   3. freeipapi.com     — tertiary HTTPS
 *
 * Logic:
 *   - Run all 3 in parallel with individual timeouts
 *   - If 2+ providers agree on a country code → use that
 *   - If providers disagree → check org name for Nigerian ISP patterns
 *   - If org looks Nigerian → return NG regardless of IP geo result
 *   - Default: use first successful result
 */
async function geoIP(ip) {
  const UNKNOWN = { country: 'Unknown', city: 'Unknown', countryCode: 'XX', regionName: 'Unknown', org: '' };

  if (!ip || isPrivateIP(ip)) {
    return { country: 'Local', city: 'Local', countryCode: 'XX', regionName: 'Local', org: '' };
  }

  const [r1, r2, r3] = await Promise.all([
    // Provider 1: ip-api.com (HTTP, has org/AS info)
    fetchGeo(
      'ip-api.com', `/json/${ip}?fields=country,regionName,city,countryCode,lat,lon,org,as`, 80, false,
      d => d.status === 'success' ? {
        country: d.country || '', city: d.city || '', countryCode: d.countryCode || '',
        regionName: d.regionName || '', lat: d.lat, lon: d.lon,
        org: `${d.org || ''} ${d.as || ''}`.trim(),
      } : null
    ),
    // Provider 2: ipwho.is (HTTPS, no key needed)
    fetchGeo(
      'ipwho.is', `/${ip}`, 443, true,
      d => d.success !== false && d.country_code ? {
        country: d.country || '', city: d.city || '', countryCode: d.country_code || '',
        regionName: d.region || '', lat: d.latitude, lon: d.longitude,
        org: `${d.connection?.org || ''} ${d.connection?.isp || ''}`.trim(),
      } : null
    ),
    // Provider 3: freeipapi.com (HTTPS, no key needed)
    fetchGeo(
      'freeipapi.com', `/api/json/${ip}`, 443, true,
      d => d.countryCode && d.countryCode !== '-' ? {
        country: d.countryName || '', city: d.cityName || '', countryCode: d.countryCode || '',
        regionName: d.regionName || '', lat: d.latitude, lon: d.longitude,
        org: '', // freeipapi doesn't return org
      } : null
    ),
  ]);

  const results = [r1, r2, r3].filter(Boolean);
  if (!results.length) return UNKNOWN;

  // ── Consensus check ────────────────────────────────────────────────────────
  const codes = results.map(r => r.countryCode).filter(Boolean);
  const freq = {};
  codes.forEach(c => { freq[c] = (freq[c] || 0) + 1; });
  const topCode = Object.entries(freq).sort((a, b) => b[1] - a[1])[0];

  // 2+ providers agree → high confidence
  if (topCode && topCode[1] >= 2) {
    const winner = results.find(r => r.countryCode === topCode[0]) || results[0];
    console.log(`🌍 Geo consensus [${ip}]: ${topCode[0]} (${topCode[1]}/3 agree)`);
    return winner;
  }

  // ── Disagreement: check org for Nigerian ISP fingerprint ──────────────────
  const allOrgs = results.map(r => r.org || '').join(' ');
  if (looksNigerian(allOrgs)) {
    console.log(`🇳🇬 Geo override [${ip}]: Nigerian ISP detected in org "${allOrgs}" — returning NG`);
    // Use best available geo data but force country to Nigeria
    const base = results[0];
    return {
      ...base,
      country: 'Nigeria',
      countryCode: 'NG',
      regionName: base.regionName || '',
    };
  }

  // No consensus, no Nigerian override → use first successful result
  console.log(`🌍 Geo fallback [${ip}]: no consensus, using ${results[0].countryCode} from provider 1`);
  return results[0];
}

/** Parse device & browser from User-Agent string */
function parseUA(ua = '') {
  let device = 'Desktop';
  if (/android/i.test(ua))            device = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) device = 'iOS';
  else if (/mobile/i.test(ua))        device = 'Mobile';

  let browser = 'Other';
  if (/edg\//i.test(ua))                               browser = 'Edge';
  else if (/opr\/|opera/i.test(ua))                    browser = 'Opera';
  else if (/firefox\/\d/i.test(ua))                    browser = 'Firefox';
  else if (/chrome\/\d/i.test(ua) && !/edg/i.test(ua)) browser = 'Chrome';
  else if (/safari\/\d/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';

  return { device, browser };
}

// ── Short Link Handler ────────────────────────────────────────────────────────
const RESERVED_PATHS = ['login', 'signup', 'dashboard', 'api', 'webhook', 'health', 'favicon.ico', '_next', 'static'];

async function handleShortLink(req, res) {
  const code = sanitizeCode(req.params.code);
  if (!code) return res.redirect('/');

  if (RESERVED_PATHS.some(r => code.toLowerCase().startsWith(r))) {
    return res.redirect('/');
  }

  try {
    let linkData = null;

    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) linkData = { id: snap.id, ...snap.data() };
    } else {
      const restUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/shortlinks/${code}`;
      linkData = await new Promise(resolve => {
        https.get(restUrl, r => {
          let d = '';
          r.on('data', c => (d += c));
          r.on('end', () => {
            try {
              const doc = JSON.parse(d);
              if (doc.fields) {
                const f = doc.fields;
                resolve({
                  originalUrl: f.originalUrl?.stringValue,
                  clicks:      parseInt(f.clicks?.integerValue || 0),
                  activatesAt: f.activatesAt?.stringValue || null,
                  expiresAt:   f.expiresAt?.stringValue || null,
                  maxClicks:   f.maxClicks?.integerValue ? parseInt(f.maxClicks.integerValue) : null,
                  password:    f.password?.stringValue || null,
                  geoRules:    f.geoRules?.arrayValue?.values?.map(v => ({
                    country: v.mapValue?.fields?.country?.stringValue,
                    url:     v.mapValue?.fields?.url?.stringValue,
                  })) || [],
                });
              } else resolve(null);
            } catch { resolve(null); }
          });
        }).on('error', () => resolve(null));
      });
    }

    if (!linkData || !isSafeURL(linkData.originalUrl)) {
      return res.redirect(`/?err=notfound&code=${encodeURIComponent(code)}`);
    }

    if (linkData.activatesAt && new Date(linkData.activatesAt) > new Date()) {
      return res.send(scheduledPage(linkData, code));
    }

    if (linkData.expiresAt && new Date(linkData.expiresAt) < new Date()) {
      return res.send(expiredPage(linkData));
    }

    if (linkData.maxClicks && (linkData.clicks || 0) >= linkData.maxClicks) {
      return res.redirect('/?err=limit');
    }

    if (linkData.password) {
      // Pass code so unlock endpoint can verify + track
      return res.send(passwordPage(linkData, code));
    }

    // Geo-redirect
    if (linkData.geoRules && Array.isArray(linkData.geoRules) && linkData.geoRules.length > 0) {
      try {
        const ip   = getRealIP(req);
        const geo  = await geoIP(ip);
        const cc   = geo.countryCode || 'XX';
        console.log(`🌍 Geo-check: IP=${ip} Country=${cc} Rules=${linkData.geoRules.map(r=>r.country).join(',')}`);
        const rule = linkData.geoRules.find(r => r.country === cc && r.url);
        if (rule && isSafeURL(rule.url)) {
          recordClick(code, req).catch(e => console.error('Click tracking error:', e.message));
          return safeRedirect(res, rule.url, 302);
        }
      } catch (e) {
        console.error('Geo-redirect error:', e.message);
      }
    }

    recordClick(code, req).catch(e => console.error('Click tracking error:', e.message));
    return safeRedirect(res, linkData.originalUrl, 302);

  } catch (err) {
    console.error('Short link error:', err.message);
    return res.redirect('/?err=error');
  }
}

async function recordClick(code, req) {
  const ip      = getRealIP(req);
  const ua      = (req.headers['user-agent'] || '').slice(0, 300); // cap UA length
  const referer = (req.headers['referer'] || 'direct').slice(0, 200);
  const { device, browser } = parseUA(ua);
  const geo = await geoIP(ip);

  const clickMeta = {
    country:     geo.country     || 'Unknown',
    countryCode: geo.countryCode || 'XX',
    city:        geo.city        || 'Unknown',
    region:      geo.regionName  || 'Unknown',
    device,
    browser,
    referer,
    ts: new Date().toISOString(),
  };

  if (adminDb) {
    const linkRef = adminDb.collection('shortlinks').doc(code);
    await linkRef.collection('clicks').add({ ...clickMeta, ip, lat: geo.lat || 0, lon: geo.lon || 0, ua });
    await linkRef.update({
      clicks:      FieldValue.increment(1),
      lastClickAt: FieldValue.serverTimestamp(),
      clickMeta:   FieldValue.arrayUnion(clickMeta),
      clickLog:    FieldValue.arrayUnion(new Date().toISOString()), // ISO string, not Date object
    });
  }
}

// ── Scheduled Page ───────────────────────────────────────────────────────────
function scheduledPage(linkData, code) {
  // Show the date in a friendly format — server formats in UTC, browser converts to local
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coming Soon · Trisend</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Plus Jakarta Sans',sans-serif;background:#F8FAFC;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.box{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:40px;max-width:420px;width:100%;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);}
.ico{font-size:52px;margin-bottom:16px;}
h2{font-size:22px;font-weight:800;margin-bottom:8px;letter-spacing:-.3px;}
.date{font-size:14px;font-weight:700;color:#F97316;background:#FFF7ED;border:1.5px solid rgba(249,115,22,.2);border-radius:10px;padding:12px 16px;margin:16px 0;line-height:1.5;}
p{font-size:13px;color:#64748B;line-height:1.6;}
#countdown{font-size:32px;font-weight:900;color:#0F172A;letter-spacing:-1px;margin:14px 0;font-variant-numeric:tabular-nums;}
.status{font-size:13px;color:#10B981;font-weight:700;display:none;margin-top:12px;}
.brand{margin-top:24px;font-size:12px;color:#94A3B8;}
.brand a{color:#F97316;text-decoration:none;font-weight:700;}
</style>
</head>
<body>
<div class="box">
  <div class="ico">⏳</div>
  <h2>This link isn't live yet</h2>
  <div class="date" id="goLiveDate">Calculating…</div>
  <div id="countdown">–</div>
  <p>This page will automatically open the link the moment it goes live. No need to refresh!</p>
  <div class="status" id="status">🚀 Going live now…</div>
  <div class="brand">Powered by <a href="/">Trisend</a></div>
</div>
<script>
// FIX: Use server's stored ISO timestamp — client renders in its own timezone
const rawActivatesAt = '${linkData.activatesAt}';
const target = new Date(rawActivatesAt);

// Show go-live date in user's local timezone
document.getElementById('goLiveDate').textContent =
  'Goes live: ' + target.toLocaleString(undefined, {
    weekday:'long', year:'numeric', month:'long',
    day:'numeric', hour:'2-digit', minute:'2-digit'
  });

let pollTimer = null;

function pad(n){ return String(n).padStart(2,'0'); }

function tick(){
  const diff = target - Date.now();
  const cd   = document.getElementById('countdown');
  if(diff <= 0){
    cd.textContent = '00h 00m 00s';
    clearInterval(pollTimer);
    checkLive(); // immediate check
    return;
  }
  const d = Math.floor(diff/86400000);
  const h = Math.floor((diff%86400000)/3600000);
  const m = Math.floor((diff%3600000)/60000);
  const s = Math.floor((diff%60000)/1000);
  cd.textContent = (d>0?d+'d ':'')+pad(h)+'h '+pad(m)+'m '+pad(s)+'s';
}

// FIX: Poll server API instead of blind page reload
// This avoids the loop caused by timezone mismatch between browser and server
async function checkLive(){
  try{
    const r = await fetch('/api/check-live/${code}');
    const d = await r.json();
    if(d.live){
      document.getElementById('status').style.display='block';
      document.getElementById('countdown').textContent='🚀 Live!';
      setTimeout(()=>location.reload(), 800); // reload once confirmed live by server
    }else{
      // Not live yet according to server — keep polling every 5s
      setTimeout(checkLive, 5000);
    }
  }catch(e){
    // Network error — fallback to reload
    location.reload();
  }
}

// Tick every second for countdown
setInterval(tick, 1000);
tick();

// Also poll server every 10s as safety net (in case tick fires slightly off)
pollTimer = setInterval(()=>{
  if(target - Date.now() <= 10000) checkLive();
}, 10000);
</script>
</body>
</html>`;
}

// ── Expired Page ──────────────────────────────────────────────────────────────
function expiredPage(linkData) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link Expired · Trisend</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Plus Jakarta Sans',sans-serif;background:#F8FAFC;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.box{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:40px;max-width:380px;width:100%;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);}
.ico{font-size:52px;margin-bottom:16px;}
h2{font-size:22px;font-weight:800;margin-bottom:8px;letter-spacing:-.3px;}
p{font-size:13px;color:#64748B;line-height:1.6;margin-bottom:20px;}
a{display:inline-flex;padding:11px 22px;background:linear-gradient(135deg,#F97316,#EF4444);color:#fff;border-radius:10px;font-size:14px;font-weight:700;text-decoration:none;}
.brand{margin-top:20px;font-size:12px;color:#94A3B8;}
.brand a{background:none;color:#F97316;padding:0;font-size:12px;}
</style>
</head>
<body>
<div class="box">
  <div class="ico">🔒</div>
  <h2>This link has expired</h2>
  <p>The owner set an expiry date on this link and it's no longer active.</p>
  <a href="/">Create your own links →</a>
  <div class="brand">Powered by <a href="/">Trisend</a></div>
</div>
</body>
</html>`;
}

// ── Password Page ─────────────────────────────────────────────────────────────
// NOTE: Password is verified SERVER-SIDE via /api/unlock/:code
// Never expose the stored hash or redirect URL in the HTML
function passwordPage(linkData, code) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Protected Link · Trisend</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Plus Jakarta Sans',sans-serif;background:#F8FAFC;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.box{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:40px;max-width:380px;width:100%;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);}
.ico{font-size:52px;margin-bottom:16px;}
h2{font-size:20px;font-weight:800;margin-bottom:8px;letter-spacing:-.3px;}
p{font-size:13px;color:#64748B;margin-bottom:20px;line-height:1.5;}
input{width:100%;padding:11px 14px;border:1.5px solid #E2E8F0;border-radius:8px;font-family:'Plus Jakarta Sans',sans-serif;font-size:14px;margin-bottom:12px;outline:none;transition:.18s;}
input:focus{border-color:#F97316;box-shadow:0 0 0 3px rgba(249,115,22,.1);}
button{width:100%;padding:12px;background:linear-gradient(135deg,#F97316,#EF4444);color:#fff;border:none;border-radius:8px;font-family:'Plus Jakarta Sans',sans-serif;font-size:14px;font-weight:700;cursor:pointer;transition:all .18s;}
button:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 4px 14px rgba(249,115,22,.4);}
button:disabled{opacity:.6;cursor:not-allowed;transform:none;}
.err{color:#EF4444;font-size:12.5px;font-weight:600;margin-top:10px;background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:8px 12px;display:none;}
.brand{margin-top:20px;font-size:12px;color:#94A3B8;}
.brand a{color:#F97316;text-decoration:none;font-weight:700;}
</style>
</head>
<body>
<div class="box">
  <div class="ico">🔒</div>
  <h2>Protected Link</h2>
  <p>This link is password-protected.<br>Enter the password to continue.</p>
  <input type="password" id="pwd" placeholder="Enter password…" onkeydown="if(event.key==='Enter')unlock()" autocomplete="current-password">
  <button id="btn" onclick="unlock()">Unlock &amp; Open →</button>
  <div class="err" id="err"></div>
  <div class="brand">Powered by <a href="/">Trisend</a></div>
</div>
<script>
// Password verified server-side — destination URL never exposed in HTML
let _attempts = 0;
async function unlock() {
  const pwd = document.getElementById('pwd').value.trim();
  if (!pwd) return;
  if (_attempts >= 5) {
    showErr('Too many attempts. Please wait a moment.');
    return;
  }
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Checking…';
  _attempts++;
  try {
    const res = await fetch('/api/unlock/${code}', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd }),
      credentials: 'same-origin',
    });
    const data = await res.json();
    if (data.success) {
      btn.textContent = 'Opening…';
      window.location.href = data.url;
    } else {
      showErr(data.message || 'Incorrect password. Try again.');
      document.getElementById('pwd').value = '';
      document.getElementById('pwd').focus();
      btn.disabled = false; btn.textContent = 'Unlock & Open →';
    }
  } catch (e) {
    showErr('Network error. Please try again.');
    btn.disabled = false; btn.textContent = 'Unlock & Open →';
  }
}
function showErr(msg) {
  const e = document.getElementById('err');
  e.textContent = msg; e.style.display = 'block';
  setTimeout(() => e.style.display = 'none', 4000);
}
</script>
</body>
</html>`;
}

// ── Page Routes ───────────────────────────────────────────────────────────────
app.get('/',          (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login',     (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/signup',    (req, res) => res.sendFile(path.join(__dirname, 'signup.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// ── Link-in-Bio Page ─────────────────────────────────────────────────────────
app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'bio.html'));
});

// ── API: Password Link Unlock ─────────────────────────────────────────────────
// Rate limited hard — 5 attempts/min, blocked 10 min (anti brute-force)
app.post('/api/unlock/:code', limiterUnlock, async (req, res) => {
  const code     = sanitizeCode(req.params.code);
  const password = req.body?.password;

  if (!code)     return res.status(400).json({ success: false, message: 'Invalid link code' });
  if (!password || typeof password !== 'string' || password.length > 200) {
    return res.status(400).json({ success: false, message: 'Invalid password input' });
  }

  try {
    let linkData = null;
    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) linkData = { id: snap.id, ...snap.data() };
    }
    if (!linkData)          return res.status(404).json({ success: false, message: 'Link not found' });
    if (!linkData.password) return res.status(400).json({ success: false, message: 'Link is not password protected' });
    if (!isSafeURL(linkData.originalUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid link destination' });
    }

    // Check expiry and click limit even before password check
    if (linkData.expiresAt && new Date(linkData.expiresAt) < new Date()) {
      return res.json({ success: false, message: 'This link has expired.' });
    }
    if (linkData.maxClicks && (linkData.clicks || 0) >= linkData.maxClicks) {
      return res.json({ success: false, message: 'This link has reached its click limit.' });
    }

    // Constant-time comparison to prevent timing attacks
    const inputHash   = Buffer.from(password).toString('base64');
    const storedHash  = linkData.password;
    const inputBuf    = Buffer.from(inputHash.padEnd(100));
    const storedBuf   = Buffer.from(storedHash.padEnd(100));
    const match = inputBuf.length === storedBuf.length
      ? crypto.timingSafeEqual(inputBuf, storedBuf)
      : false;

    if (!match) {
      // Log failed attempt (don't reveal whether code exists)
      console.warn(`🔒 Failed unlock attempt: ${code} | IP: ${getRealIP(req)}`);
      return res.json({ success: false, message: 'Incorrect password. Try again.' });
    }

    // Password correct — record the click now (it never fired before)
    recordClick(code, req).catch(e => console.error('Password click record error:', e.message));

    return res.json({ success: true, url: linkData.originalUrl });
  } catch (e) {
    console.error('Unlock error:', e.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ── API: Check if scheduled link is now live ──────────────────────────────────
app.get('/api/check-live/:code', limiterAPI, async (req, res) => {
  const code = sanitizeCode(req.params.code);
  if (!code) return res.json({ live: false });
  try {
    let activatesAt = null;
    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) activatesAt = snap.data().activatesAt || null;
    }
    if (!activatesAt) return res.json({ live: true }); // no schedule = always live
    const goLive = new Date(activatesAt);
    const live   = goLive <= new Date();
    res.json({ live, activatesAt, serverTime: new Date().toISOString() });
  } catch (e) {
    res.json({ live: false, error: e.message });
  }
});

// ── API: My IP (for debugging geo-detect) ────────────────────────────────────
app.get('/api/my-ip', limiterAPI, async (req, res) => {
  const ip  = getRealIP(req);
  const geo = await geoIP(ip);
  const forwarded = req.headers['x-forwarded-for'] || 'none';
  const cfCountry = req.headers['cf-ipcountry'] || 'not present';
  res.json({
    detectedIP:        ip,
    forwardedHeader:   forwarded,
    cfIpCountry:       cfCountry,
    country:           geo.country,
    countryCode:       geo.countryCode,
    city:              geo.city,
    region:            geo.regionName,
    org:               geo.org || '(not returned)',
    isNigerianOrg:     looksNigerian(geo.org || ''),
    tip:               'If countryCode is wrong, check cfIpCountry and org fields. Nigerian ISPs (MTN/Airtel/Glo/9mobile) are detected via org name.',
  });
});

// ── API: Check username availability ─────────────────────────────────────────
app.get('/api/bio/check/:username', limiterBioCheck, async (req, res) => {
  const username = sanitizeUsername(req.params.username);
  if(!username || username.length < 3)
    return res.json({ available: false, reason: 'Username must be at least 3 characters' });
  if(username.length > 30)
    return res.json({ available: false, reason: 'Username too long (max 30 chars)' });

  // Reserved usernames
  const RESERVED = ['admin','trisend','api','u','qr','login','signup','dashboard','help','support','about','home'];
  if(RESERVED.includes(username))
    return res.json({ available: false, reason: 'That username is reserved' });

  try{
    if(adminDb){
      const snap = await adminDb.collection('biopages').doc(username).get();
      return res.json({ available: !snap.exists, username });
    }
    // Fallback REST check
    const restUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/biopages/${username}`;
    const exists = await new Promise(resolve => {
      https.get(restUrl, r => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try{ const doc = JSON.parse(d); resolve(!!doc.fields); }
          catch{ resolve(false); }
        });
      }).on('error', () => resolve(false));
    });
    res.json({ available: !exists, username });
  }catch(e){
    res.json({ available: false, reason: 'Could not check username' });
  }
});

// ── Dynamic QR Redirect ──────────────────────────────────────────────────────
app.get('/qr/:code([a-zA-Z0-9_-]{4,})', async (req, res) => {
  const code = req.params.code;
  try {
    let destination = null;

    if (adminDb) {
      const snap = await adminDb.collection('dynamicqr').doc(code).get();
      if (snap.exists) {
        const data = snap.data();
        destination = data.destination;

        // Record scan async — don't await, don't slow down redirect
        const ip = getRealIP(req);
        const ua = req.headers['user-agent'] || '';
        const { device, browser } = parseUA(ua);
        geoIP(ip).then(geo => {
          adminDb.collection('dynamicqr').doc(code).update({
            scans: FieldValue.increment(1),
            lastScannedAt: FieldValue.serverTimestamp(),
            scanMeta: FieldValue.arrayUnion({
              country:     geo.country     || 'Unknown',
              countryCode: geo.countryCode || 'XX',
              city:        geo.city        || 'Unknown',
              device, browser,
              ts: new Date().toISOString(),
            }),
          }).catch(e => console.error('Dynamic QR scan record error:', e.message));
        });
      }
    } else {
      // Fallback: Firestore REST
      const restUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/dynamicqr/${code}`;
      const data = await new Promise(resolve => {
        https.get(restUrl, r => {
          let d = '';
          r.on('data', c => d += c);
          r.on('end', () => {
            try {
              const doc = JSON.parse(d);
              if (doc.fields) resolve({ destination: doc.fields.destination?.stringValue });
              else resolve(null);
            } catch { resolve(null); }
          });
        }).on('error', () => resolve(null));
      });
      if (data) destination = data.destination;
    }

    if (!destination) return res.redirect('/?err=qrnotfound');
    return res.redirect(302, destination);

  } catch (err) {
    console.error('Dynamic QR error:', err.message);
    return res.redirect('/?err=error');
  }
});

// ── Short Link Redirect ───────────────────────────────────────────────────────
// Must be BEFORE the catch-all 404 handler
app.get('/:code([a-zA-Z0-9_-]{3,})', handleShortLink);

// ── API: Verify Paystack Payment ──────────────────────────────────────────────
app.post('/api/verify-payment', limiterPayment, async (req, res) => {
  const reference = req.body?.reference;
  const userId    = sanitizeUserId(req.body?.userId);

  if (!reference || typeof reference !== 'string' || !/^[A-Za-z0-9_-]{6,100}$/.test(reference)) {
    return res.status(400).json({ success: false, message: 'Invalid payment reference' });
  }
  if (!userId) {
    return res.status(400).json({ success: false, message: 'Invalid userId' });
  }
  if (!PAYSTACK_SECRET) {
    return res.status(500).json({ success: false, message: 'Payment service not configured' });
  }

  try {
    const result = await paystackRequest('GET', `/transaction/verify/${encodeURIComponent(reference)}`);

    if (!result.status || result.data?.status !== 'success') {
      return res.status(400).json({ success: false, message: 'Payment not successful' });
    }

    const amount   = result.data.amount;
    const currency = result.data.currency;
    const validNGN = currency === 'NGN' && amount >= 200000;
    const validUSD = currency === 'USD' && amount >= 500;
    if (!validNGN && !validUSD) {
      return res.status(400).json({ success: false, message: 'Incorrect payment amount' });
    }

    // Verify the userId in metadata matches the one supplied
    const metaUserId = result.data.metadata?.userId;
    if (metaUserId && metaUserId !== userId) {
      console.warn(`⚠️  userId mismatch in verify-payment: supplied=${userId}, metadata=${metaUserId}`);
      return res.status(403).json({ success: false, message: 'Payment does not match user' });
    }

    if (adminDb) {
      const premiumExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await adminDb.collection('users').doc(userId).update({
        plan:             'premium',
        paystackRef:      reference,
        premiumExpiresAt: premiumExpiresAt,
        premiumStartedAt: FieldValue.serverTimestamp(),
        upgradedAt:       FieldValue.serverTimestamp(),
      });
      console.log(`✅ Payment verified: ${reference} | User: ${userId} | Expires: ${premiumExpiresAt.toDateString()}`);
    }

    return res.json({
      success: true,
      data: { reference, amount: amount / 100, email: result.data.customer?.email },
    });
  } catch (err) {
    console.error('Payment verification error:', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed. Please try again.' });
  }
});

// ── API: Location ─────────────────────────────────────────────────────────────
app.get('/api/location', limiterAPI, async (req, res) => {
  try {
    const ip  = getRealIP(req);

    // Fast path: Cloudflare sets this header for free on any proxied site
    // It's reliable — use it as a strong signal if present
    const cfCountry = req.headers['cf-ipcountry'];

    const geo = await geoIP(ip);
    let cc = geo.countryCode || 'XX';

    // If Cloudflare says Nigeria and our geo says something else → trust CF
    // CF header is sourced from MaxMind which is the most accurate DB
    if (cfCountry && cfCountry !== 'XX' && cfCountry !== cc) {
      console.log(`🌐 CF header override [${ip}]: cf-ipcountry=${cfCountry} vs geo=${cc} → using CF`);
      cc = cfCountry;
    }

    // Nigerian ISP org fallback at the API layer too
    // (catches cases where geoIP returned a result but org-check was inconclusive)
    if (cc !== 'NG' && looksNigerian(geo.org || '')) {
      console.log(`🇳🇬 Org override at API layer [${ip}]: ${geo.org} → forcing NG`);
      cc = 'NG';
    }

    const isNigeria = cc === 'NG';
    const currency  = isNigeria ? 'NGN' : 'USD';
    const amount    = isNigeria ? 200000 : 500;   // kobo / cents
    const display   = isNigeria ? '₦2,000' : '$5';

    res.json({
      countryCode: cc,
      country:     cc === 'NG' ? 'Nigeria' : (geo.country || 'Unknown'),
      currency,
      amount,
      display,
      isNigeria,
    });
  } catch (e) {
    console.error('Location API error:', e.message);
    // Fallback to NGN on any error — better to under-charge than over-charge a Nigerian user
    res.json({ countryCode: 'NG', country: 'Nigeria', currency: 'NGN', amount: 200000, display: '₦2,000', isNigeria: true });
  }
});

// ── API: Config ───────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({ paystackPublicKey: PAYSTACK_PUBLIC || '', platform: 'Trisend' });
});

// ── API: Health ───────────────────────────────────────────────────────────────
// Minimal public info — no secrets, no internal state exposed
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    platform:  'Trisend v3.2',
    timestamp: new Date().toISOString(),
  });
});

// ── Paystack Webhook ──────────────────────────────────────────────────────────
app.post('/webhook/paystack', limiterWebhook, async (req, res) => {
  res.sendStatus(200); // Always 200 first to prevent Paystack retries
  if (!PAYSTACK_SECRET) return;

  const sig  = req.headers['x-paystack-signature'];
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
  if (!sig || hash !== sig) {
    console.warn('⚠️  Invalid Paystack webhook signature — ignored');
    return;
  }

  let event;
  try { event = JSON.parse(req.body); } catch { return; }
  console.log(`📦 Webhook: ${event.event}`);

  if (event.event === 'charge.success') {
    const { reference, amount, currency, metadata } = event.data;
    const userId   = sanitizeUserId(metadata?.userId);
    const validPmt = (currency === 'NGN' && amount >= 200000) || (currency === 'USD' && amount >= 500);
    if (validPmt && userId && adminDb) {
      try {
        const premiumExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await adminDb.collection('users').doc(userId).update({
          plan:             'premium',
          paystackRef:      reference,
          premiumExpiresAt: premiumExpiresAt,
          premiumStartedAt: FieldValue.serverTimestamp(),
          upgradedAt:       FieldValue.serverTimestamp(),
        });
        console.log(`⭐ Premium via webhook: ${userId} | Expires: ${premiumExpiresAt.toDateString()}`);
      } catch (e) {
        console.error('Webhook Firestore update failed:', e.message);
      }
    }
  }
});

// ── Catch-all ─────────────────────────────────────────────────────────────────
app.use((req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ████████╗██████╗ ██╗███████╗███████╗███╗   ██╗██████╗ ');
  console.log('  ╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝████╗  ██║██╔══██╗');
  console.log('     ██║   ██████╔╝██║███████╗█████╗  ██╔██╗ ██║██║  ██║');
  console.log('     ██║   ██╔══██╗██║╚════██║██╔══╝  ██║╚██╗██║██║  ██║');
  console.log('     ██║   ██║  ██║██║███████║███████╗██║ ╚████║██████╔╝ ');
  console.log('     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ ');
  console.log('');
  console.log(`  🚀 Trisend v3.2 running on port ${PORT}`);
  console.log(`  💳 Paystack: ${PAYSTACK_SECRET ? '✅ Ready' : '❌ Missing PAYSTACK_SECRET_KEY'}`);
  console.log(`  🔥 Firebase Admin: ${adminDb ? '✅ Connected' : '⚠️  Set FIREBASE_SERVICE_ACCOUNT for tracking'}`);
  console.log(`  🔒 Security: Rate limiting ✅ | CSP ✅ | HSTS ✅ | Input validation ✅`);
  console.log('');
});
