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
const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
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
const limiterSafeScan = createRateLimiter(30,   60_000, 2 * 60_000);  // 30/min, block 2 min

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
  // SAMEORIGIN (not DENY) — Firebase auth redirect handler briefly frames the page
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    // apis.google.com = what Firebase redirect flow loads scripts from (≠ www.googleapis.com)
    "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://js.paystack.co https://cdnjs.cloudflare.com https://www.googleapis.com https://fonts.googleapis.com https://accounts.google.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://paystack.com https://checkout.paystack.com https://accounts.google.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    // connect-src: Firebase + Paystack + all 3 geo providers + Google OAuth
    "connect-src 'self' https://api.paystack.co https://firestore.googleapis.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://*.firebaseio.com https://ip-api.com https://ipwho.is https://freeipapi.com https://www.googleapis.com https://apis.google.com https://paystack.com https://*.paystack.com https://accounts.google.com https://oauth2.googleapis.com",
    // frame-src: Firebase auth handler + Google OAuth popup
    "frame-src 'self' https://js.paystack.co https://checkout.paystack.com https://paystack.com https://trisend-e7250.firebaseapp.com https://accounts.google.com",
    "frame-ancestors 'self' https://trisend-e7250.firebaseapp.com https://accounts.google.com",
    "object-src 'none'",
    "base-uri 'self'",
    // form-action must include firebaseapp.com — Google OAuth callback posts through it
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

/** Get real visitor IP — handles Render / Cloudflare proxy headers */
/**
 * getRealIP — extract real visitor IP from Render proxy headers.
 *
 * On Render, x-forwarded-for format is: "RealClientIP, RenderProxy1, RenderProxy2"
 * The LEFTMOST non-private IP is always the actual visitor.
 * Previous rightmost-first logic was wrong — it returned Render's US/UK datacenter IP.
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
  // Strip IPv6-mapped IPv4 prefix (::ffff:1.2.3.4 → 1.2.3.4)
  const raw = req.socket?.remoteAddress || '0.0.0.0';
  return raw.replace(/^::ffff:/, '');
}

function isPrivateIP(ip) {
  // Strip IPv6-mapped prefix before checking
  const clean = ip.replace(/^::ffff:/, '');
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1$|fc|fd)/i.test(clean)
    || clean === 'localhost';
}

/**
 * Nigerian ISP org/AS name patterns.
 * Nigerian carriers (MTN, Airtel, Glo, 9mobile) often route through UK/US
 * peering nodes — their geo resolves to wrong country but org name is correct.
 */
const NIGERIAN_ORG_PATTERNS = [
  /\bmtn\b/i, /\bairtel\b/i, /\bglo\b/i, /\b9mobile\b/i, /\betisalat\b/i,
  /\bnitel\b/i, /\bspectranet\b/i, /\bswift\b/i, /\bipnx\b/i,
  /\bcobranet\b/i, /\bswitch.*telecom/i, /\bcybernet\b/i,
  /\bnigeria\b/i, /\bnigcomsat\b/i, /\blink.*direct\b/i,
];

function looksNigerian(org = '') {
  return NIGERIAN_ORG_PATTERNS.some(p => p.test(org));
}

/** Single geo provider fetch — returns null on any failure */
function fetchGeo(hostname, path, port, useHttps, parseResult, timeoutMs = 4000) {
  return new Promise(resolve => {
    const lib = useHttps ? https : http;
    const opts = { hostname, port, path, method: 'GET', timeout: timeoutMs };
    const req = lib.request(opts, res => {
      let d = '';
      res.on('data', c => (d += c));
      res.on('end', () => {
        try { resolve(parseResult(JSON.parse(d))); }
        catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

/**
 * geoIP — multi-provider geo lookup with consensus + Nigerian ISP fallback.
 *
 * Providers (all free, no API key):
 *   1. ip-api.com   — has org/AS field, most detailed
 *   2. ipwho.is     — HTTPS, fast secondary
 *   3. freeipapi.com — HTTPS, tertiary
 *
 * Logic:
 *   - All 3 run in parallel with individual timeouts
 *   - 2+ agree on country → use that (high confidence)
 *   - Providers disagree → check org name for Nigerian ISP fingerprint
 *   - Nigerian org detected → force NG regardless of IP geo
 *   - Fallback → first successful result
 */
async function geoIP(ip) {
  const UNKNOWN = { country: 'Unknown', city: 'Unknown', countryCode: 'XX', regionName: 'Unknown', org: '' };

  if (!ip || ip === '0.0.0.0') return UNKNOWN;
  if (isPrivateIP(ip)) return { country: 'Local', city: 'Local', countryCode: 'XX', regionName: 'Local', org: '' };

  const [r1, r2, r3] = await Promise.all([
    // Provider 1: ip-api.com (HTTP, has org/AS — best for Nigerian detection)
    fetchGeo('ip-api.com', `/json/${ip}?fields=status,country,regionName,city,countryCode,lat,lon,org,as`, 80, false,
      d => d.status === 'success' ? {
        country: d.country || '', city: d.city || '', countryCode: d.countryCode || '',
        regionName: d.regionName || '', lat: d.lat, lon: d.lon,
        org: `${d.org || ''} ${d.as || ''}`.trim(),
      } : null
    ),
    // Provider 2: ipwho.is (HTTPS)
    fetchGeo('ipwho.is', `/${ip}`, 443, true,
      d => d.success !== false && d.country_code ? {
        country: d.country || '', city: d.city || '', countryCode: d.country_code || '',
        regionName: d.region || '', lat: d.latitude, lon: d.longitude,
        org: `${d.connection?.org || ''} ${d.connection?.isp || ''}`.trim(),
      } : null
    ),
    // Provider 3: freeipapi.com (HTTPS)
    fetchGeo('freeipapi.com', `/api/json/${ip}`, 443, true,
      d => d.countryCode && d.countryCode !== '-' ? {
        country: d.countryName || '', city: d.cityName || '', countryCode: d.countryCode || '',
        regionName: d.regionName || '', lat: d.latitude, lon: d.longitude,
        org: '',
      } : null
    ),
  ]);

  const results = [r1, r2, r3].filter(Boolean);
  if (!results.length) return UNKNOWN;

  // ── Consensus: 2+ providers agree → use that ─────────────────────────────
  const codes = results.map(r => r.countryCode).filter(Boolean);
  const freq = {};
  codes.forEach(c => { freq[c] = (freq[c] || 0) + 1; });
  const [topCode, topCount] = Object.entries(freq).sort((a, b) => b[1] - a[1])[0] || [];

  if (topCode && topCount >= 2) {
    const winner = results.find(r => r.countryCode === topCode) || results[0];
    console.log(`🌍 Geo consensus [${ip}]: ${topCode} (${topCount}/3 agree)`);
    return winner;
  }

  // ── Disagreement: check org name for Nigerian ISP fingerprint ────────────
  const allOrgs = results.map(r => r.org || '').join(' ');
  if (looksNigerian(allOrgs)) {
    console.log(`🇳🇬 Nigerian ISP detected [${ip}]: "${allOrgs}" → forcing NG`);
    return { ...results[0], country: 'Nigeria', countryCode: 'NG' };
  }

  console.log(`🌍 Geo fallback [${ip}]: using first result → ${results[0].countryCode}`);
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
        const ip  = getRealIP(req);
        const geo = await geoIP(ip);
        let cc    = geo.countryCode || 'XX';

        // cf-ipcountry header is most reliable when Cloudflare is in front — same logic as /api/location
        const cfCountry = req.headers['cf-ipcountry'];
        if (cfCountry && cfCountry !== 'XX' && cfCountry !== cc) {
          console.log(`🌐 Geo-redirect CF override [${ip}]: cf-ipcountry=${cfCountry} vs geo=${cc} → using CF`);
          cc = cfCountry;
        }

        // Nigerian ISP org fallback — carriers often route through UK/US peering nodes
        if (cc !== 'NG' && looksNigerian(geo.org || '')) {
          console.log(`🇳🇬 Geo-redirect org override [${ip}]: ${geo.org} → forcing NG`);
          cc = 'NG';
        }

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

// ── Click deduplication store ─────────────────────────────────────────────────
// Key: ip+code → last click timestamp. Prevents double-counting within 10 min window.
const _clickDedup = new Map();
setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [k, v] of _clickDedup) { if (v < cutoff) _clickDedup.delete(k); }
}, 2 * 60 * 1000);

// Bot/crawler user-agent patterns — never count these
const BOT_PATTERN = /bot|crawl|spider|slurp|mediapartners|facebookexternalhit|whatsapp|telegram|twitterbot|linkedinbot|embedly|quora|outbrain|pinterest|vkshare|w3c_validator|curl|wget|python-requests|go-http|java\/|axios|node-fetch|prerender|headless|phantomjs|puppeteer|selenium|chrome-lighthouse|googleweblight|adsbot|feedfetcher|applebot|baiduspider|yandex|semrush|ahrefs|mj12bot|dotbot|rogerbot|screaming|archive\.org/i;

// Prefetch/prerender — browser sends these headers when pre-loading, not real clicks
function isPrerender(req) {
  const purpose = req.headers['purpose'] || req.headers['x-purpose'] || req.headers['sec-purpose'] || '';
  const moz     = req.headers['x-moz'] || '';
  return /prefetch|prerender/i.test(purpose) || /prefetch/i.test(moz);
}

async function recordClick(code, req) {
  const ua = (req.headers['user-agent'] || '').slice(0, 400);

  // 1. Drop prefetch/prerender requests — browser loading ahead, not a real click
  if (isPrerender(req)) return;

  // 2. Drop known bots and crawlers
  if (BOT_PATTERN.test(ua)) return;

  const ip = getRealIP(req);

  // 3. Deduplicate: same IP + same link within 10 minutes = one click
  const dedupKey = `${ip}|${code}`;
  const lastClick = _clickDedup.get(dedupKey);
  if (lastClick && Date.now() - lastClick < 10 * 60 * 1000) {
    console.log(`⏭ Dedup skip: ${code} from ${ip}`);
    return;
  }
  _clickDedup.set(dedupKey, Date.now());

  const referer          = (req.headers['referer'] || 'direct').slice(0, 200);
  const { device, browser } = parseUA(ua);
  const geo              = await geoIP(ip);
  const tsISO            = new Date().toISOString();

  const clickMeta = {
    country:     geo.country     || 'Unknown',
    countryCode: geo.countryCode || 'XX',
    city:        geo.city        || 'Unknown',
    region:      geo.regionName  || 'Unknown',
    device,
    browser,
    referer,
    ts: tsISO,
  };

  if (adminDb) {
    const linkRef = adminDb.collection('shortlinks').doc(code);
    // Subcollection click doc — full detail, queryable
    linkRef.collection('clicks').add({
      ...clickMeta,
      ip,
      lat: geo.lat || 0,
      lon: geo.lon || 0,
      ua,
    }).catch(e => console.error('Click doc write error:', e.message));

    // Root doc update — atomic increment + cap clickMeta at 500 to avoid 1MB Firestore doc limit
    linkRef.get().then(docSnap => {
      const existing = docSnap.data()?.clickMeta || [];
      const capped = [...existing.slice(-499), clickMeta]; // keep last 500 entries
      return linkRef.update({
        clicks:      FieldValue.increment(1),
        lastClickAt: FieldValue.serverTimestamp(),
        clickMeta:   capped,
        // FIX: removed clickLog: FieldValue.arrayUnion(tsISO) — it was
        // unbounded and would hit Firestore's 1MB document limit at ~41k
        // clicks, silently dropping all subsequent click writes.
        // Full click history lives in the 'clicks' subcollection instead.
      });
    }).catch(e => console.error('Click root update error:', e.message));
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
let _tickTimer = null;
let _checking  = false;   // guard against simultaneous checkLive calls
let _redirecting = false; // guard against double-redirect

function pad(n){ return String(n).padStart(2,'0'); }

function tick(){
  const diff = target - Date.now();
  const cd   = document.getElementById('countdown');
  if(diff <= 0){
    cd.textContent = '00h 00m 00s';
    // Stop the tick loop — we're done counting
    clearInterval(_tickTimer);
    clearInterval(pollTimer);
    checkLive();
    return;
  }
  const d = Math.floor(diff/86400000);
  const h = Math.floor((diff%86400000)/3600000);
  const m = Math.floor((diff%3600000)/60000);
  const s = Math.floor((diff%60000)/1000);
  cd.textContent = (d>0?d+'d ':'')+pad(h)+'h '+pad(m)+'m '+pad(s)+'s';
}

async function checkLive(){
  // Prevent multiple simultaneous calls
  if(_checking || _redirecting) return;
  _checking = true;
  try{
    const r = await fetch('/api/check-live/${code}');
    const d = await r.json();
    if(d.live){
      if(_redirecting) return;
      _redirecting = true;
      document.getElementById('status').style.display='block';
      document.getElementById('countdown').textContent='🚀 Going live…';
      // Navigate directly to the code — server will now redirect to the real URL
      // Use replace() so this scheduled page is NOT in browser history
      setTimeout(()=>{ window.location.replace('/${code}?t='+Date.now()); }, 600);
    }else{
      _checking = false;
      // Not live yet — retry in 4s
      setTimeout(checkLive, 4000);
    }
  }catch(e){
    _checking = false;
    // Network error — retry in 6s
    setTimeout(checkLive, 6000);
  }
}

// Tick every second for countdown
_tickTimer = setInterval(tick, 1000);
tick();

// Safety-net poll: start checking every 5s when within 15s of go-live
pollTimer = setInterval(()=>{
  const diff = target - Date.now();
  if(diff <= 15000 && diff > -5000) checkLive();
}, 5000);
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
app.get('/',            (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login',       (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/signup',      (req, res) => res.sendFile(path.join(__dirname, 'signup.html')));
app.get('/dashboard',   (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/pages',       (req, res) => res.sendFile(path.join(__dirname, 'pagebuilder.html')));

// ── Universal Page Builder renderer (/p/:slug) ───────────────────────────────
app.get('/p/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'page.html'));
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
    } else {
      // REST fallback — mirrors handleShortLink so unlock works even without Firebase Admin
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
                  expiresAt:   f.expiresAt?.stringValue || null,
                  maxClicks:   f.maxClicks?.integerValue ? parseInt(f.maxClicks.integerValue) : null,
                  password:    f.password?.stringValue || null,
                });
              } else resolve(null);
            } catch { resolve(null); }
          });
        }).on('error', () => resolve(null));
      });
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
  // Never cache this — browser must always get fresh answer
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (!code) return res.json({ live: false });
  try {
    let activatesAt = null;
    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) activatesAt = snap.data().activatesAt || null;
    } else {
      // REST fallback
      const restUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents/shortlinks/${code}`;
      activatesAt = await new Promise(resolve => {
        https.get(restUrl, r => {
          let d = '';
          r.on('data', c => (d += c));
          r.on('end', () => {
            try {
              const doc = JSON.parse(d);
              resolve(doc.fields?.activatesAt?.stringValue || null);
            } catch { resolve(null); }
          });
        }).on('error', () => resolve(null));
      });
    }
    if (!activatesAt) return res.json({ live: true }); // no schedule = always live
    const goLive = new Date(activatesAt);
    const live   = goLive <= new Date();
    res.json({ live, activatesAt, serverTime: new Date().toISOString() });
  } catch (e) {
    res.json({ live: false, error: e.message });
  }
});

// ── API: My IP debug ──────────────────────────────────────────────────────────
app.get('/api/my-ip', limiterAPI, async (req, res) => {
  const ip  = getRealIP(req);
  const geo = await geoIP(ip);
  res.json({
    detectedIP:      ip,
    forwardedHeader: req.headers['x-forwarded-for'] || 'none',
    cfIpCountry:     req.headers['cf-ipcountry'] || 'not present',
    country:         geo.country,
    countryCode:     geo.countryCode,
    city:            geo.city,
    region:          geo.regionName,
    org:             geo.org || '(none)',
    isNigerianOrg:   looksNigerian(geo.org || ''),
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

        // Record scan async — bot and prefetch filtered, same as short links
        const ip = getRealIP(req);
        const ua = (req.headers['user-agent'] || '');
        if (!BOT_PATTERN.test(ua) && !isPrerender(req)) {
          const dedupKey = `qr|${ip}|${code}`;
          const lastScan = _clickDedup.get(dedupKey);
          if (!lastScan || Date.now() - lastScan >= 10 * 60 * 1000) {
            _clickDedup.set(dedupKey, Date.now());
            const { device, browser } = parseUA(ua);
            geoIP(ip).then(geo => {
              const scanEntry = {
                country:     geo.country     || 'Unknown',
                countryCode: geo.countryCode || 'XX',
                city:        geo.city        || 'Unknown',
                device, browser,
                ts: new Date().toISOString(),
              };
              // FIX: use a capped read-then-write instead of arrayUnion —
              // arrayUnion has no size limit and will eventually breach
              // Firestore's 1MB document cap for popular QR codes, causing
              // all subsequent scan writes to fail silently.
              adminDb.collection('dynamicqr').doc(code).get().then(snap => {
                const existing = snap.data()?.scanMeta || [];
                const capped   = [...existing.slice(-499), scanEntry]; // keep last 500
                return adminDb.collection('dynamicqr').doc(code).update({
                  scans:         FieldValue.increment(1),
                  lastScannedAt: FieldValue.serverTimestamp(),
                  scanMeta:      capped,
                });
              }).catch(e => console.error('Dynamic QR scan record error:', e.message));
            });
          }
        }
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
    // FIX: short links always run isSafeURL before redirecting; QR codes didn't
    if (!isSafeURL(destination)) return res.redirect('/?err=qrnotfound');
    return safeRedirect(res, destination, 302);

  } catch (err) {
    console.error('Dynamic QR error:', err.message);
    return res.redirect('/?err=error');
  }
});

// ── API: Health ───────────────────────────────────────────────────────────────
// FIX: Must be registered BEFORE /:code — "health" matches [a-zA-Z0-9_-]{3,}
// and was previously swallowed by the short link handler, returning a 302 to /
// instead of the expected 200 JSON. Render health checks were silently failing.
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    platform:  'Trisend v3.2',
    timestamp: new Date().toISOString(),
  });
});

// ── Short Link Redirect ───────────────────────────────────────────────────────
// Must be BEFORE the catch-all 404 handler, but AFTER all specific GET routes
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

    // Verify the userId in metadata matches the one supplied.
    // FIX: Previously `if (metaUserId && ...)` allowed anyone with a valid
    // reference (that had no metadata) to upgrade any arbitrary userId.
    // Now we REQUIRE metaUserId to be present and matching.
    const metaUserId = result.data.metadata?.userId;
    if (!metaUserId || metaUserId !== userId) {
      console.warn(`⚠️  userId mismatch in verify-payment: supplied=${userId}, metadata=${metaUserId}`);
      return res.status(403).json({ success: false, message: 'Payment reference was not issued for this account' });
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
    const ip = getRealIP(req);

    // Cloudflare sets cf-ipcountry for free on any proxied site — most reliable signal
    const cfCountry = req.headers['cf-ipcountry'];

    const geo = await geoIP(ip);
    let cc = geo.countryCode || 'XX';

    // CF header override — trust it over our geo if they disagree
    if (cfCountry && cfCountry !== 'XX' && cfCountry !== cc) {
      console.log(`🌐 CF header override [${ip}]: cf-ipcountry=${cfCountry} vs geo=${cc} → using CF`);
      cc = cfCountry;
    }

    // Nigerian ISP org fallback at API layer
    if (cc !== 'NG' && looksNigerian(geo.org || '')) {
      console.log(`🇳🇬 Org override at API [${ip}]: ${geo.org} → forcing NG`);
      cc = 'NG';
    }

    const isNigeria = cc === 'NG';
    const currency  = isNigeria ? 'NGN' : 'USD';
    const amount    = isNigeria ? 200000 : 500;
    const display   = isNigeria ? '₦2,000' : '$5';

    console.log(`📍 Location [${ip}]: ${cc} | ${geo.country} | CF:${cfCountry||'none'} | org:${geo.org||'?'}`);

    res.json({
      countryCode: cc,
      country:     cc === 'NG' ? 'Nigeria' : (geo.country || 'Unknown'),
      currency, amount, display, isNigeria,
    });
  } catch (e) {
    console.error('Location API error:', e.message);
    // Default to NGN on any error — better to under-charge than wrongly bill a Nigerian user
    res.json({ countryCode: 'NG', country: 'Nigeria', currency: 'NGN', amount: 200000, display: '₦2,000', isNigeria: true });
  }
});

// ── API: Safe Scan ────────────────────────────────────────────────────────────
app.post('/api/safe-scan', limiterSafeScan, async (req, res) => {
  const { url } = req.body;

  // Basic validation
  if (!url || typeof url !== 'string' || url.length > 2000) {
    return res.status(400).json({ result: 'caution', reason: 'Invalid URL supplied.' });
  }

  // Must be http/https
  let parsed;
  try {
    parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.json({ result: 'caution', reason: 'Non-web URL — proceed carefully.' });
    }
  } catch {
    return res.status(400).json({ result: 'caution', reason: 'Could not parse URL.' });
  }

  // No API key configured — return caution, don't crash
  if (!SAFE_BROWSING_KEY) {
    console.warn('[SafeScan] GOOGLE_SAFE_BROWSING_KEY not set — returning caution');
    return res.json({ result: 'caution', reason: 'Safety check unavailable right now.' });
  }

  try {
    const body = JSON.stringify({
      client: { clientId: 'trisend', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    });

    // Use Node's built-in https — no extra deps
    const response = await new Promise((resolve, reject) => {
      const reqOpts = {
        hostname: 'safebrowsing.googleapis.com',
        path: `/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      };
      const r = https.request(reqOpts, res2 => {
        let data = '';
        res2.on('data', chunk => data += chunk);
        res2.on('end', () => resolve({ status: res2.statusCode, body: data }));
      });
      r.on('error', reject);
      r.setTimeout(5000, () => { r.destroy(); reject(new Error('timeout')); });
      r.write(body);
      r.end();
    });

    const data = JSON.parse(response.body);

    if (data.matches && data.matches.length > 0) {
      const types = data.matches.map(m => m.threatType).join(', ');
      return res.json({ result: 'danger', reason: types });
    }

    return res.json({ result: 'safe' });

  } catch (err) {
    console.error('[SafeScan] Error:', err.message);
    // Network/timeout — return caution, not danger (don't false-flag)
    return res.json({ result: 'caution', reason: 'Check timed out — could not verify.' });
  }
});

// ── API: Config ───────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({ paystackPublicKey: PAYSTACK_PUBLIC || '', platform: 'Trisend' });
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
