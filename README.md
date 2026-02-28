# Trisend 🔲🔗
### QR Code Generator & URL Shortener Platform

A full-stack web app with:
- **QR Code Generator** — 8 types, custom colors/shapes/frames/logo (Premium)
- **URL Shortener** — Server-side redirects with real IP geolocation tracking
- **Analytics** — Clicks, countries, devices, browsers from actual data
- **Paystack Payments** — ₦2,000 one-time lifetime Premium upgrade
- **Admin Panel** — User management, notifications, bug reports
- **AI Chat Assistant** — Built-in help bot

---

## File Structure

```
├── server.js               # Express server — redirects, geolocation, Paystack
├── index.html              # Landing page
├── login.html              # Login (email/password + Google)
├── signup.html             # Signup page
├── dashboard.html          # Full dashboard app (QR, links, analytics, admin)
├── package.json            # Node dependencies
├── render.yaml             # One-click Render deployment
├── firestore.rules         # Firestore security rules
├── firestore.indexes.json  # Required composite indexes
├── .env.example            # Environment variable template
└── README.md               # This file
```

---

## Deploy in 5 Steps

### Step 1 — Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com) → project `trisend-e7250`
2. **Authentication** → Sign-in methods → Enable:
   - ✅ Email/Password
   - ✅ Google
3. **Firestore Database** → Create database → Start in **production mode** → choose a region
4. **Firestore Rules** → paste the contents of `firestore.rules` → Publish
5. **Firestore Indexes** → use Firebase CLI:
   ```bash
   npm install -g firebase-tools
   firebase login
   firebase use trisend-e7250
   firebase deploy --only firestore:indexes
   ```
6. **Service Account** → Project Settings (gear icon) → Service Accounts tab → **Generate new private key** → download JSON file

### Step 2 — Paystack Setup

1. Log in to [Paystack Dashboard](https://dashboard.paystack.com)
2. **Settings → API Keys** → copy your **Secret Key** and **Public Key**
3. **Settings → Webhooks** → Add webhook URL:
   ```
   https://YOUR-APP-NAME.onrender.com/webhook/paystack
   ```

### Step 3 — Deploy to Render

1. Push all files to a **GitHub repository**
2. Go to [Render](https://render.com) → **New → Web Service**
3. Connect your GitHub repo
4. Configure:
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Environment:** Node
5. Add **Environment Variables** (click "Add Environment Variable" for each):

   | Key | Value |
   |-----|-------|
   | `PAYSTACK_SECRET_KEY` | Your Paystack secret key |
   | `PAYSTACK_PUBLIC_KEY` | Your Paystack public key |
   | `FIREBASE_SERVICE_ACCOUNT` | The entire contents of your service account JSON, on one line |

   > **Tip for FIREBASE_SERVICE_ACCOUNT:** Open the downloaded JSON file in a text editor, select all, copy, then paste as the value. Render handles multi-line values fine in the dashboard.

6. Click **Deploy** — your app will be live at `https://your-app.onrender.com`

### Step 4 — Configure Firebase Auth Domain

1. Firebase Console → **Authentication → Settings → Authorized domains**
2. Click **Add domain** → enter your Render URL: `your-app.onrender.com`

### Step 5 — Grant Yourself Admin Access

1. Sign up on your deployed site
2. Firebase Console → **Firestore Database → users collection**
3. Find your user document (it will have your email)
4. Click **Add field** → Field: `role`, Type: string, Value: `admin`
5. Save — you now have access to the Admin Panel in the dashboard sidebar

---

## How Short Links Work

```
User creates link in dashboard
        ↓
Firestore: shortlinks/{code} = { originalUrl, userId, clicks, ... }
        ↓
Visitor opens: yourdomain.com/abc123
        ↓
server.js handleShortLink():
  1. Read Firestore for code "abc123"
  2. Check expiry / click limits / password
  3. Get real IP from x-forwarded-for header
  4. Call ip-api.com for country/city/lat/lon
  5. Parse User-Agent for device + browser
  6. Write to shortlinks/abc123/clicks/{id}
  7. Increment shortlinks/abc123.clicks
  8. HTTP 302 → originalUrl
```

---

## How QR Codes Work

- **Free users:** Generate any of 8 types (URL, WiFi, vCard, Email, Phone, SMS, Location, Text)
- **Premium users:** Custom foreground/background colors, dot/rounded shapes, 4 frame styles, logo embed
- Logo embedding uses **Error Correction Level H (30%)** so QR remains scannable
- Generated client-side using [QRious](https://github.com/neocotic/qrious) library
- Canvas manipulation for shapes, frames, and logo overlay

---

## Paystack Integration

- **Amount:** ₦2,000 (200,000 kobo)
- **Currency:** NGN
- **Flow:** `PaystackPop.setup()` → user pays → callback → `/api/verify-payment` → Firestore user plan updated to `premium`
- **Webhook:** `/webhook/paystack` verifies HMAC signature for server-side confirmation

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYSTACK_SECRET_KEY` | ✅ | Paystack secret key (starts with `sk_live_`) |
| `PAYSTACK_PUBLIC_KEY` | ✅ | Paystack public key (starts with `pk_live_`) |
| `FIREBASE_SERVICE_ACCOUNT` | ✅ | Full service account JSON string |
| `PORT` | Optional | Server port (default: 3000) |
| `NODE_ENV` | Optional | Set to `production` on Render |

---

## Firestore Data Structure

```
users/
  {uid}/
    displayName, email, photoURL, plan, role, createdAt

shortlinks/
  {code}/
    userId, originalUrl, code, clicks, expiresAt, maxClicks, password, createdAt
    clicks/
      {auto-id}/
        ip, country, countryCode, city, region, lat, lon,
        device, browser, referer, ua, ts

qrcodes/
  {auto-id}/
    userId, type, data, label, scans, createdAt

notifications/
  {auto-id}/
    title, message, type, target (all/free/premium), createdAt, sentBy

user_reads/
  {uid}/
    ids: [notificationId, ...]

bugs/
  {auto-id}/
    userId, email, title, description, status (open/resolved), createdAt
```

---

## Tech Stack

- **Frontend:** Vanilla JS, Firebase SDK (client), QRious, Paystack inline.js
- **Backend:** Node.js, Express
- **Database:** Firebase Firestore
- **Auth:** Firebase Authentication
- **Payments:** Paystack
- **Geolocation:** ip-api.com (free tier, no API key needed)
- **Hosting:** Render (free tier works fine)

---

## Support

📧 trisendmailer@gmail.com
