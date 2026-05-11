/**
 * TRISEND SERVER v3.1
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

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC_KEY;
const FIREBASE_PROJECT = 'trisend-e7250';

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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

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
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(s => s.trim());
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

/** Geo-lookup via ip-api.com (free, no key needed) */
function geoIP(ip) {
  return new Promise(resolve => {
    if (!ip || isPrivateIP(ip)) {
      return resolve({ country: 'Local', city: 'Local', countryCode: 'XX', regionName: 'Local' });
    }
    const opts = {
      hostname: 'ip-api.com',
      port: 80,
      path: `/json/${ip}?fields=country,regionName,city,countryCode,lat,lon,org`,
      method: 'GET',
      timeout: 3000,
    };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => (data += c));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX', regionName: 'Unknown' }); }
      });
    });
    req.on('error', () => resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX', regionName: 'Unknown' }));
    req.on('timeout', () => { req.destroy(); resolve({ country: 'Unknown', city: 'Unknown', countryCode: 'XX', regionName: 'Unknown' }); });
    req.end();
  });
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
  const code = req.params.code;

  if (RESERVED_PATHS.some(r => code.toLowerCase().startsWith(r))) {
    return res.redirect('/');
  }

  try {
    let linkData = null;

    if (adminDb) {
      // ── Primary: Firebase Admin SDK ──
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) linkData = { id: snap.id, ...snap.data() };
    } else {
      // ── Fallback: Firestore REST API (requires public read rules on shortlinks) ──
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

    if (!linkData || !linkData.originalUrl) {
      return res.redirect(`/?err=notfound&code=${encodeURIComponent(code)}`);
    }

    // Check if link has activated yet (scheduling)
    if (linkData.activatesAt && new Date(linkData.activatesAt) > new Date()) {
      return res.send(scheduledPage(linkData));
    }

    // Check expiry
    if (linkData.expiresAt && new Date(linkData.expiresAt) < new Date()) {
      return res.send(expiredPage(linkData));
    }

    // Check click limit
    if (linkData.maxClicks && (linkData.clicks || 0) >= linkData.maxClicks) {
      return res.redirect('/?err=limit');
    }

    // Password-protected — show unlock page
    if (linkData.password) {
      // If password supplied in POST body (from unlock API), handle it there
      return res.send(passwordPage(linkData, code));
    }
    }

    // ── Geo-Redirect — check country rules before default redirect ────────────
    if (linkData.geoRules && Array.isArray(linkData.geoRules) && linkData.geoRules.length > 0) {
      try {
        const ip  = getRealIP(req);
        const geo = await geoIP(ip);
        const cc  = geo.countryCode || 'XX';
        const rule = linkData.geoRules.find(r => r.country === cc && r.url);
        if (rule) {
          recordClick(code, req).catch(e => console.error('Click tracking error:', e.message));
          return res.redirect(302, rule.url);
        }
        // No matching rule — fall through to default URL
      } catch (e) {
        console.error('Geo-redirect error:', e.message);
        // Fall through to default on error
      }
    }

    // Fire-and-forget click tracking
    recordClick(code, req).catch(e => console.error('Click tracking error:', e.message));

    return res.redirect(302, linkData.originalUrl);

  } catch (err) {
    console.error('Short link error:', err.message);
    return res.redirect('/?err=error');
  }
}

/**
 * ── FIX: recordClick now writes to BOTH:
 *    1. clicks subcollection (detailed log per click)
 *    2. clickMeta[] array on the shortlink document (for dashboard analytics)
 *
 * Previously only wrote to subcollection, so dashboard country/device/browser
 * charts never populated.
 */
async function recordClick(code, req) {
  const ip      = getRealIP(req);
  const ua      = req.headers['user-agent'] || '';
  const referer = req.headers['referer'] || 'direct';
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

  const fullClickDoc = {
    ...clickMeta,
    ip,
    lat: geo.lat || 0,
    lon: geo.lon || 0,
    ua:  ua.slice(0, 250),
  };

  if (adminDb) {
    const linkRef = adminDb.collection('shortlinks').doc(code);

    // Write full detail to subcollection
    await linkRef.collection('clicks').add(fullClickDoc);

    // ── FIX: Push compact meta to the document's clickMeta[] array ──
    // This is what the dashboard reads for analytics charts
    await linkRef.update({
      clicks:      FieldValue.increment(1),
      lastClickAt: FieldValue.serverTimestamp(),
      clickMeta:   FieldValue.arrayUnion(clickMeta),
      // clickLog stores ISO strings — readable by both Admin SDK and client SDK
      clickLog:    FieldValue.arrayUnion(new Date().toISOString()),
    });
  }
}

// ── Scheduled Page ───────────────────────────────────────────────────────────
function scheduledPage(linkData) {
  const activates = new Date(linkData.activatesAt);
  const formatted = activates.toLocaleString('en-US', {
    weekday:'long', year:'numeric', month:'long',
    day:'numeric', hour:'2-digit', minute:'2-digit', timeZoneName:'short'
  });
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
.box{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:40px;max-width:400px;width:100%;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);}
.ico{font-size:52px;margin-bottom:16px;}
h2{font-size:22px;font-weight:800;margin-bottom:8px;letter-spacing:-.3px;}
.date{font-size:14px;font-weight:700;color:#F97316;background:#FFF7ED;border:1.5px solid rgba(249,115,22,.2);border-radius:10px;padding:12px 16px;margin:16px 0;}
p{font-size:13px;color:#64748B;line-height:1.6;}
#countdown{font-size:28px;font-weight:900;color:#0F172A;letter-spacing:-1px;margin:14px 0;}
.brand{margin-top:24px;font-size:12px;color:#94A3B8;}
.brand a{color:#F97316;text-decoration:none;font-weight:700;}
</style>
</head>
<body>
<div class="box">
  <div class="ico">⏳</div>
  <h2>This link isn't live yet</h2>
  <div class="date">Goes live: ${formatted}</div>
  <div id="countdown"></div>
  <p>Come back when it's live — or bookmark this page and refresh.</p>
  <div class="brand">Powered by <a href="/">Trisend</a></div>
</div>
<script>
const target=new Date('${linkData.activatesAt}');
function tick(){
  const diff=target-Date.now();
  if(diff<=0){location.reload();return;}
  const d=Math.floor(diff/86400000);
  const h=Math.floor((diff%86400000)/3600000);
  const m=Math.floor((diff%3600000)/60000);
  const s=Math.floor((diff%60000)/1000);
  document.getElementById('countdown').textContent=
    (d>0?d+'d ':'')+String(h).padStart(2,'0')+'h '+String(m).padStart(2,'0')+'m '+String(s).padStart(2,'0')+'s';
}
tick();setInterval(tick,1000);
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
input{width:100%;padding:11px 14px;border:1.5px solid #E2E8F0;border-radius:8px;font-family:'Plus Jakarta Sans',sans-serif;font-size:14px;margin-bottom:12px;outline:none;}
input:focus{border-color:#F97316;box-shadow:0 0 0 3px rgba(249,115,22,.1);}
button{width:100%;padding:12px;background:linear-gradient(135deg,#F97316,#EF4444);color:#fff;border:none;border-radius:8px;font-family:'Plus Jakarta Sans',sans-serif;font-size:14px;font-weight:700;cursor:pointer;transition:all .18s;}
button:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(249,115,22,.4);}
button:disabled{opacity:.6;transform:none;}
.err{color:#EF4444;font-size:12px;font-weight:600;margin-top:8px;display:none;}
.brand{margin-top:20px;font-size:12px;color:#94A3B8;}
.brand a{color:#F97316;text-decoration:none;font-weight:700;}
</style>
</head>
<body>
<div class="box">
  <div class="ico">🔒</div>
  <h2>Protected Link</h2>
  <p>This link is password-protected.<br>Enter the password to continue.</p>
  <input type="password" id="pwd" placeholder="Enter password…" onkeydown="if(event.key==='Enter')unlock()">
  <button id="unlockBtn" onclick="unlock()">Unlock &amp; Open →</button>
  <p class="err" id="errMsg">Incorrect password. Try again.</p>
  <div class="brand">Powered by <a href="/">Trisend</a></div>
</div>
<script>
// FIX: Use server-side unlock endpoint so clicks are recorded properly
async function unlock(){
  const pwd=document.getElementById('pwd').value;
  if(!pwd)return;
  const btn=document.getElementById('unlockBtn');
  btn.disabled=true;btn.textContent='Checking…';
  try{
    const res=await fetch('/api/unlock/${code}',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    const data=await res.json();
    if(data.success){
      window.location.href=data.url;
    }else{
      const e=document.getElementById('errMsg');
      e.style.display='block';
      e.textContent=data.message||'Incorrect password. Try again.';
      setTimeout(()=>e.style.display='none',3000);
      document.getElementById('pwd').value='';
      document.getElementById('pwd').focus();
      btn.disabled=false;btn.textContent='Unlock & Open →';
    }
  }catch(err){
    btn.disabled=false;btn.textContent='Unlock & Open →';
    document.getElementById('errMsg').style.display='block';
    setTimeout(()=>document.getElementById('errMsg').style.display='none',3000);
  }
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

// ── API: Password Link Unlock (records click properly) ────────────────────────
app.post('/api/unlock/:code', async (req, res) => {
  const code = req.params.code;
  const { password } = req.body;
  if (!password) return res.json({ success: false, message: 'No password provided' });

  try {
    let linkData = null;
    if (adminDb) {
      const snap = await adminDb.collection('shortlinks').doc(code).get();
      if (snap.exists) linkData = { id: snap.id, ...snap.data() };
    }
    if (!linkData) return res.json({ success: false, message: 'Link not found' });
    if (!linkData.password) return res.json({ success: false, message: 'Link not protected' });

    // Verify password (stored as btoa string)
    const inputEncoded = Buffer.from(password).toString('base64');
    if (inputEncoded !== linkData.password) {
      return res.json({ success: false, message: 'Incorrect password. Try again.' });
    }

    // Check expiry / click limit even after unlock
    const now = new Date();
    if (linkData.expiresAt && new Date(linkData.expiresAt) < now)
      return res.json({ success: false, message: 'This link has expired.' });
    if (linkData.maxClicks && (linkData.clicks || 0) >= linkData.maxClicks)
      return res.json({ success: false, message: 'Click limit reached.' });

    // FIX: Record click NOW that password is verified — this was never happening before
    recordClick(code, req).catch(e => console.error('Password click record error:', e.message));

    return res.json({ success: true, url: linkData.originalUrl });
  } catch (e) {
    console.error('Unlock error:', e.message);
    return res.json({ success: false, message: 'Server error. Try again.' });
  }
});

// ── API: Check username availability ─────────────────────────────────────────
app.get('/api/bio/check/:username', async (req, res) => {
  const username = req.params.username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
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

    const amount   = result.data.amount;
    const currency = result.data.currency;
    // Accept ₦2,000 NGN or $5 USD — both are valid premium payments
    const validNGN = currency === 'NGN' && amount >= 200000;
    const validUSD = currency === 'USD' && amount >= 500;
    if (!validNGN && !validUSD)
      return res.status(400).json({ success: false, message: 'Incorrect payment amount' });

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
    return res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// ── API: Location — detects user country from IP for currency switching ───────
app.get('/api/location', async (req, res) => {
  try {
    const ip  = getRealIP(req);
    const geo = await geoIP(ip);
    const cc  = geo.countryCode || 'XX';

    // Nigeria → NGN, everyone else → USD
    const isNigeria  = cc === 'NG';
    const currency   = isNigeria ? 'NGN' : 'USD';
    const amount     = isNigeria ? 200000 : 500;   // kobo / cents
    const display    = isNigeria ? '₦2,000' : '$5';

    res.json({
      countryCode: cc,
      country:     geo.country || 'Unknown',
      currency,
      amount,
      display,
      isNigeria,
    });
  } catch (e) {
    // Fallback to NGN on any error
    res.json({ countryCode: 'NG', country: 'Nigeria', currency: 'NGN', amount: 200000, display: '₦2,000', isNigeria: true });
  }
});

// ── API: Config ───────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({ paystackPublicKey: PAYSTACK_PUBLIC || '', platform: 'Trisend' });
});

// ── API: Health ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    platform:  'Trisend v3.2',
    timestamp: new Date().toISOString(),
    paystack:  PAYSTACK_SECRET ? 'configured' : 'missing',
    firebase:  adminDb ? 'connected' : 'client-only',
  });
});

// ── Paystack Webhook ──────────────────────────────────────────────────────────
app.post('/webhook/paystack', async (req, res) => {
  // Always 200 first to prevent Paystack retries
  res.sendStatus(200);
  if (!PAYSTACK_SECRET) return;

  const sig  = req.headers['x-paystack-signature'];
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
  if (hash !== sig) {
    console.warn('⚠️  Invalid Paystack webhook signature — ignored');
    return;
  }

  let event;
  try { event = JSON.parse(req.body); } catch { return; }

  console.log(`📦 Webhook: ${event.event}`);

  if (event.event === 'charge.success') {
    const { reference, amount, currency, metadata } = event.data;
    const userId = metadata?.userId;
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
  console.log('');
});
