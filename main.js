// ════════════════════════════════════════════════════════════════════════════════
// Trisend — main.js
// Complete dashboard JavaScript — QR codes, short links, analytics, settings,
// Paystack payments, Firebase Auth + Firestore
// ════════════════════════════════════════════════════════════════════════════════
//
// SETUP INSTRUCTIONS:
//   1. Replace the Firebase config values below with your own project config.
//      Get them from: Firebase Console → Project Settings → Your Apps
//   2. Replace PAYSTACK_PUBLIC_KEY with your Paystack public key.
//      Get it from: dashboard.paystack.com → Settings → API Keys
//   3. Make sure server.js has FIREBASE_SERVICE_ACCOUNT and PAYSTACK_SECRET_KEY
//      set as environment variables.
//   4. Firestore rules: allow read/write when request.auth.uid == resource.data.userId
// ════════════════════════════════════════════════════════════════════════════════

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  signOut,
  updateProfile,
  updatePassword,
  deleteUser,
  GoogleAuthProvider,
} from "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js";
import {
  getFirestore,
  collection,
  query,
  where,
  orderBy,
  limit,
  getDocs,
  addDoc,
  deleteDoc,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  onSnapshot,
  serverTimestamp,
  increment,
} from "https://www.gstatic.com/firebasejs/11.1.0/firebase-firestore.js";

// ════════════════════════════════════════════════════════════════════════════════
// ██  CONFIG — FILL THESE IN  ██
// ════════════════════════════════════════════════════════════════════════════════

const FIREBASE_CONFIG = {
  apiKey:            "YOUR_API_KEY",
  authDomain:        "YOUR_PROJECT_ID.firebaseapp.com",
  projectId:         "YOUR_PROJECT_ID",
  storageBucket:     "YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId:             "YOUR_APP_ID",
};

const PAYSTACK_PUBLIC_KEY = "YOUR_PAYSTACK_PUBLIC_KEY"; // e.g. "pk_live_xxx" or "pk_test_xxx"

// The base URL of your server (where server.js is running).
// In production this is just "" (same origin).
// In local development change to e.g. "http://localhost:3000"
const SERVER_BASE = "";

// ════════════════════════════════════════════════════════════════════════════════
// FIREBASE INIT
// ════════════════════════════════════════════════════════════════════════════════

const firebaseApp = initializeApp(FIREBASE_CONFIG);
const auth        = getAuth(firebaseApp);
const db          = getFirestore(firebaseApp);

// ════════════════════════════════════════════════════════════════════════════════
// APP STATE
// ════════════════════════════════════════════════════════════════════════════════

const State = {
  user:        null,   // Firebase Auth user object
  isPremium:   false,  // whether user has premium plan
  currentTab:  "qr",  // active tab id
  qrType:      "url", // currently selected QR type
  qrDataUrl:   null,  // current QR preview image data URL
  userUnsubFn: null,  // Firestore real-time listener unsubscriber
};

// ════════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════════════════════════════════════════════

function $(id) { return document.getElementById(id); }

function toast(message, type = "success") {
  const el = $("toast");
  el.textContent  = message;
  el.className    = type; // "success" or "error"
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 3800);
}

function showSpinner(btnEl, label = "") {
  btnEl.disabled = true;
  btnEl._originalHTML = btnEl.innerHTML;
  btnEl.innerHTML = `<span class="spinner"></span>${label ? " " + label : ""}`;
}

function hideSpinner(btnEl) {
  btnEl.disabled = false;
  btnEl.innerHTML = btnEl._originalHTML || btnEl.innerHTML;
}

function randCode(len = 7) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function isValidUrl(str) {
  try { new URL(str); return true; } catch { return false; }
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

function formatDateTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text)
    .then(() => toast("Copied to clipboard!"))
    .catch(() => toast("Could not copy — try manually", "error"));
}

// ════════════════════════════════════════════════════════════════════════════════
// SIDEBAR NAVIGATION
// ════════════════════════════════════════════════════════════════════════════════

const NAV_ITEMS = [
  { id: "qr",        label: "QR Codes",    icon: "⬡" },
  { id: "links",     label: "Short Links", icon: "🔗" },
  { id: "analytics", label: "Analytics",   icon: "📊" },
  { id: "settings",  label: "Settings",    icon: "⚙️" },
];

function renderNav() {
  const html = NAV_ITEMS.map(item => `
    <button class="nav-item${State.currentTab === item.id ? " active" : ""}"
            id="nav-${item.id}"
            onclick="App.switchTab('${item.id}')">
      <span class="nav-icon">${item.icon}</span>
      ${item.label}
    </button>`).join("");
  const desktopEl = $("desktop-nav-links");
  const mobileEl  = $("mobile-nav-links");
  if (desktopEl) desktopEl.innerHTML = html;
  if (mobileEl)  mobileEl.innerHTML  = html;
}

function renderSidebarUser() {
  const user    = State.user;
  const initial = (user?.displayName || user?.email || "U")[0].toUpperCase();
  const name    = user?.displayName || user?.email || "Account";
  const plan    = State.isPremium ? "PREMIUM" : "FREE";
  const cls     = State.isPremium ? "badge-premium" : "badge-free";

  const html = `
    <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;">
      <div style="width:32px;height:32px;border-radius:50%;background:${State.isPremium ? "linear-gradient(135deg,#1d4ed8,#7c3aed)" : "#e2e8f0"};
                  color:${State.isPremium ? "#fff" : "#475569"};display:flex;align-items:center;
                  justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;">
        ${initial}
      </div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${name}</div>
        <span class="badge ${cls}">${plan}</span>
      </div>
    </div>`;

  const desktopEl = $("sidebar-user-block");
  const mobileEl  = $("mobile-sidebar-user");
  const mobileBadge = $("mobile-plan-badge");
  if (desktopEl) desktopEl.innerHTML = html;
  if (mobileEl)  mobileEl.innerHTML  = html;
  if (mobileBadge) mobileBadge.innerHTML = `<span class="badge ${cls}" style="font-size:10px;">${plan}</span>`;
}

// ════════════════════════════════════════════════════════════════════════════════
// TAB SWITCHING
// ════════════════════════════════════════════════════════════════════════════════

function switchTab(tabId) {
  State.currentTab = tabId;

  document.querySelectorAll(".tab-pane").forEach(el => el.classList.remove("active"));
  const pane = $("tab-" + tabId);
  if (pane) pane.classList.add("active");

  renderNav();
  App.closeMobileSidebar();

  if (tabId === "analytics") Analytics.load();
  if (tabId === "links")     Links.load();
  if (tabId === "qr")        QRCodes.load();
}

// ════════════════════════════════════════════════════════════════════════════════
// AUTH GUARD & USER SETUP
// ════════════════════════════════════════════════════════════════════════════════

function initAuth() {
  onAuthStateChanged(auth, async user => {
    if (!user) {
      window.location.href = "login.html";
      return;
    }

    State.user = user;

    // Pre-fill settings fields
    const emailEl = $("settings-email");
    const nameEl  = $("settings-name");
    if (emailEl) emailEl.value = user.email || "";
    if (nameEl)  nameEl.value  = user.displayName || "";

    // Hide password change for Google sign-in users
    const isGoogle = user.providerData.some(p => p.providerId === "google.com");
    const pwCard   = $("password-card");
    if (pwCard && isGoogle) pwCard.style.display = "none";

    // Subscribe to real-time plan updates
    if (State.userUnsubFn) State.userUnsubFn();
    State.userUnsubFn = onSnapshot(doc(db, "users", user.uid), snap => {
      const plan = snap.exists() ? (snap.data().plan || "free") : "free";
      State.isPremium = plan === "premium";
      applyPremiumUI();
      renderSidebarUser();
    });

    renderNav();
    renderSidebarUser();
    QRCodes.load();
  });
}

function applyPremiumUI() {
  // QR colors
  const fence   = $("qr-color-fence");
  const pickers = $("qr-color-pickers");
  if (fence && pickers) {
    fence.style.display   = State.isPremium ? "none"  : "flex";
    pickers.style.display = State.isPremium ? "flex"  : "none";
  }

  // Links form premium row
  const premRow   = $("lf-premium-row");
  const premFence = $("lf-premium-fence");
  if (premRow && premFence) {
    premRow.style.display   = State.isPremium ? "flex" : "none";
    premFence.style.display = State.isPremium ? "none" : "flex";
  }

  // Settings plan card
  const freeBlock    = $("settings-free-block");
  const premiumBlock = $("settings-premium-block");
  const planBadge    = $("settings-plan-badge");
  if (freeBlock && premiumBlock) {
    freeBlock.style.display    = State.isPremium ? "none"  : "block";
    premiumBlock.style.display = State.isPremium ? "block" : "none";
  }
  if (planBadge) {
    planBadge.className   = `badge ${State.isPremium ? "badge-premium" : "badge-free"}`;
    planBadge.textContent = State.isPremium ? "PREMIUM" : "FREE";
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// QR CODES MODULE
// ════════════════════════════════════════════════════════════════════════════════

const QR_TYPES = {
  url: {
    label: "URL",
    fields: () => `
      <div><label class="form-label">URL <span style="color:#dc2626">*</span></label>
      <input class="form-input" id="qf-url" type="url" placeholder="https://example.com" autocomplete="url"/></div>`
  },
  wifi: {
    label: "WiFi",
    fields: () => `
      <div><label class="form-label">Network name (SSID) <span style="color:#dc2626">*</span></label>
      <input class="form-input" id="qf-ssid" type="text" placeholder="MyHomeNetwork"/></div>
      <div><label class="form-label">Password</label>
      <input class="form-input" id="qf-wifi-pass" type="password" placeholder="WiFi password (blank if open)"/></div>
      <div><label class="form-label">Security</label>
      <select class="form-input" id="qf-security"><option value="WPA">WPA/WPA2</option><option value="WEP">WEP</option><option value="nopass">None</option></select></div>`
  },
  vcard: {
    label: "vCard",
    fields: () => `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div><label class="form-label">First name</label><input class="form-input" id="qf-fname" type="text" placeholder="John"/></div>
        <div><label class="form-label">Last name</label><input class="form-input" id="qf-lname" type="text" placeholder="Doe"/></div>
      </div>
      <div><label class="form-label">Phone</label><input class="form-input" id="qf-phone" type="tel" placeholder="+234 800 000 0000"/></div>
      <div><label class="form-label">Email</label><input class="form-input" id="qf-email" type="email" placeholder="john@example.com"/></div>
      <div><label class="form-label">Organisation</label><input class="form-input" id="qf-org" type="text" placeholder="Company name (optional)"/></div>`
  },
  email: {
    label: "Email",
    fields: () => `
      <div><label class="form-label">Email address <span style="color:#dc2626">*</span></label>
      <input class="form-input" id="qf-email" type="email" placeholder="someone@example.com"/></div>
      <div><label class="form-label">Subject</label>
      <input class="form-input" id="qf-subject" type="text" placeholder="Hello (optional)"/></div>
      <div><label class="form-label">Body</label>
      <textarea class="form-input" id="qf-body" placeholder="Message body (optional)"></textarea></div>`
  },
  phone: {
    label: "Phone",
    fields: () => `
      <div><label class="form-label">Phone number <span style="color:#dc2626">*</span></label>
      <input class="form-input" id="qf-phone" type="tel" placeholder="+234 800 000 0000"/></div>`
  },
  sms: {
    label: "SMS",
    fields: () => `
      <div><label class="form-label">Phone number <span style="color:#dc2626">*</span></label>
      <input class="form-input" id="qf-phone" type="tel" placeholder="+234 800 000 0000"/></div>
      <div><label class="form-label">Pre-filled message</label>
      <textarea class="form-input" id="qf-message" placeholder="Your message here (optional)"></textarea></div>`
  },
  location: {
    label: "Location",
    fields: () => `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div><label class="form-label">Latitude <span style="color:#dc2626">*</span></label>
        <input class="form-input" id="qf-lat" type="text" placeholder="6.5244"/></div>
        <div><label class="form-label">Longitude <span style="color:#dc2626">*</span></label>
        <input class="form-input" id="qf-lng" type="text" placeholder="3.3792"/></div>
      </div>`
  },
  text: {
    label: "Text",
    fields: () => `
      <div><label class="form-label">Plain text <span style="color:#dc2626">*</span></label>
      <textarea class="form-input" id="qf-text" placeholder="Any text you want encoded in the QR code…" style="min-height:100px;"></textarea></div>`
  },
};

function getFieldVal(id) {
  const el = $(id);
  return el ? el.value.trim() : "";
}

function buildQRString(type) {
  switch (type) {
    case "url":
      return getFieldVal("qf-url");

    case "wifi": {
      const ssid = getFieldVal("qf-ssid");
      if (!ssid) return null;
      const pass = getFieldVal("qf-wifi-pass");
      const sec  = getFieldVal("qf-security") || "WPA";
      return `WIFI:T:${sec};S:${ssid};P:${pass};;`;
    }

    case "vcard": {
      const fn   = `${getFieldVal("qf-fname")} ${getFieldVal("qf-lname")}`.trim();
      const org  = getFieldVal("qf-org");
      const tel  = getFieldVal("qf-phone");
      const mail = getFieldVal("qf-email");
      return [
        "BEGIN:VCARD",
        "VERSION:3.0",
        fn   ? `FN:${fn}`          : "",
        org  ? `ORG:${org}`        : "",
        tel  ? `TEL:${tel}`        : "",
        mail ? `EMAIL:${mail}`     : "",
        "END:VCARD",
      ].filter(Boolean).join("\n");
    }

    case "email": {
      const to      = getFieldVal("qf-email");
      if (!to) return null;
      const subject = getFieldVal("qf-subject");
      const body    = getFieldVal("qf-body");
      let s = `mailto:${to}`;
      const params  = [];
      if (subject) params.push(`subject=${encodeURIComponent(subject)}`);
      if (body)    params.push(`body=${encodeURIComponent(body)}`);
      if (params.length) s += "?" + params.join("&");
      return s;
    }

    case "phone": {
      const p = getFieldVal("qf-phone");
      return p ? `tel:${p}` : null;
    }

    case "sms": {
      const p = getFieldVal("qf-phone");
      if (!p) return null;
      const m = getFieldVal("qf-message");
      return m ? `sms:${p}?body=${encodeURIComponent(m)}` : `sms:${p}`;
    }

    case "location": {
      const lat = getFieldVal("qf-lat");
      const lng = getFieldVal("qf-lng");
      if (!lat || !lng) return null;
      return `geo:${lat},${lng}`;
    }

    case "text":
      return getFieldVal("qf-text") || null;

    default:
      return null;
  }
}

function renderQRImage(data) {
  if (!data) return null;
  const canvas = document.createElement("canvas");
  const fg     = State.isPremium ? ($("qr-fg")?.value || "#000000") : "#000000";
  const bg     = State.isPremium ? ($("qr-bg")?.value || "#ffffff") : "#ffffff";
  try {
    const qr = new QRious({
      element:    canvas,
      value:      data,
      size:       320,
      foreground: fg,
      background: bg,
      level:      "H",
      padding:    16,
    });
    return qr.toDataURL("image/png");
  } catch {
    toast("QR generation failed — check your input values.", "error");
    return null;
  }
}

const QRCodes = {
  _loaded: false,

  initTypeGrid() {
    const grid = $("qr-type-grid");
    if (!grid) return;
    grid.querySelectorAll(".qr-type-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const type = btn.dataset.type;
        if (type === State.qrType) return;
        State.qrType   = type;
        State.qrDataUrl = null;
        // Update active class
        grid.querySelectorAll(".qr-type-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        // Re-render dynamic fields
        this.renderFields();
        // Reset preview
        this.resetPreview();
      });
    });
    // Render initial fields
    this.renderFields();
  },

  renderFields() {
    const container = $("qr-dynamic-fields");
    if (!container) return;
    const def = QR_TYPES[State.qrType];
    container.innerHTML = def ? def.fields() : "";
  },

  resetPreview() {
    State.qrDataUrl = null;
    $("qr-preview-empty").style.display  = "block";
    $("qr-preview-img").style.display    = "none";
    $("qr-preview-meta").style.display   = "none";
    $("qr-download-btn").style.display   = "none";
  },

  showPreview(dataUrl, label, type) {
    State.qrDataUrl = dataUrl;
    const img = $("qr-preview-img");
    const meta = $("qr-preview-meta");
    img.src             = dataUrl;
    img.style.display   = "block";
    $("qr-preview-empty").style.display  = "none";
    $("qr-preview-meta").style.display   = "block";
    $("qr-download-btn").style.display   = "inline-flex";
    $("qr-preview-label").textContent    = label || "QR Code";
    $("qr-preview-type").textContent     = type.toUpperCase();
  },

  async load() {
    if (!State.user) return;
    const list = $("qr-list");
    if (!list) return;

    list.innerHTML = [1,2,3].map(() =>
      `<div class="skeleton" style="height:60px;border-radius:8px;margin-bottom:8px;"></div>`
    ).join("");

    try {
      const q    = query(collection(db, "qrcodes"), where("userId","==", State.user.uid), orderBy("createdAt","desc"), limit(50));
      const snap = await getDocs(q);
      const codes = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      const badge = $("qr-count-badge");
      if (badge) { badge.textContent = codes.length; badge.style.display = codes.length ? "inline-flex" : "none"; }

      if (codes.length === 0) {
        list.innerHTML = `<div class="empty-state"><div class="es-icon">⬡</div><p class="es-text">No QR codes yet. Generate your first one above.</p></div>`;
        return;
      }

      list.innerHTML = codes.map(c => `
        <div class="link-row" id="qr-row-${c.id}">
          <div style="width:44px;height:44px;border-radius:6px;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;">⬡</div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:13.5px;font-weight:700;margin-bottom:2px;">${c.name || "Untitled QR"}</div>
            <div style="font-size:11.5px;color:#94a3b8;">
              ${(c.type || "url").toUpperCase()} &nbsp;·&nbsp; Created ${formatDate(c.createdAt)}
              ${c.colors ? '&nbsp;·&nbsp; <span style="color:#7c3aed;font-weight:600;">Custom colors</span>' : ""}
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0;">
            <button class="btn btn-ghost btn-icon" title="Regenerate & Download" onclick="QRCodes.redownload('${c.id}','${escHtml(c.data)}','${escHtml(c.name)}','${c.type}',${c.colors ? JSON.stringify(c.colors).replace(/"/g,"&quot;") : "null"})">
              <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3"/></svg>
            </button>
            <button class="btn btn-ghost btn-icon" title="Delete" style="color:#94a3b8;" onmouseenter="this.style.color='#dc2626'" onmouseleave="this.style.color='#94a3b8'" onclick="QRCodes.delete('${c.id}')">
              <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </div>
        </div>`).join("");
    } catch (err) {
      console.error("[QR] load error:", err);
      list.innerHTML = `<p style="color:#dc2626;font-size:13px;">Failed to load QR codes. Please refresh.</p>`;
    }
  },

  redownload(id, data, name, type, colors) {
    const fg = (State.isPremium && colors?.fg) ? colors.fg : "#000000";
    const bg = (State.isPremium && colors?.bg) ? colors.bg : "#ffffff";
    const canvas = document.createElement("canvas");
    try {
      new QRious({ element: canvas, value: data, size: 320, foreground: fg, background: bg, level: "H", padding: 16 });
      const a     = document.createElement("a");
      a.href     = canvas.toDataURL("image/png");
      a.download = (name || "qrcode").replace(/\s+/g, "-") + ".png";
      a.click();
    } catch {
      toast("Could not regenerate QR code.", "error");
    }
  },

  async delete(id) {
    if (!confirm("Delete this QR code? This cannot be undone.")) return;
    try {
      await deleteDoc(doc(db, "qrcodes", id));
      const row = $("qr-row-" + id);
      if (row) row.remove();
      toast("QR code deleted.");
      this.load();
    } catch {
      toast("Failed to delete QR code.", "error");
    }
  },
};

function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── QR Code actions wired to buttons in dashboard.html ───────────────────────

function previewQR() {
  const data = buildQRString(State.qrType);
  if (!data) { toast("Fill in the required fields first.", "error"); return; }
  const url  = renderQRImage(data);
  if (!url)  return;
  const label = $("qr-label")?.value.trim() || "QR Code";
  QRCodes.showPreview(url, label, State.qrType);
}

async function saveQR() {
  const data = buildQRString(State.qrType);
  if (!data) { toast("Fill in the required fields first.", "error"); return; }
  if (!State.user) return;

  const url = renderQRImage(data);
  if (!url) return;

  const label = $("qr-label")?.value.trim() || State.qrType.toUpperCase() + " QR";
  QRCodes.showPreview(url, label, State.qrType);

  const btn = $("qr-save-btn");
  showSpinner(btn, "Saving…");

  try {
    await addDoc(collection(db, "qrcodes"), {
      userId:    State.user.uid,
      name:      label,
      type:      State.qrType,
      data,
      colors:    State.isPremium
                   ? { fg: $("qr-fg")?.value || "#000000", bg: $("qr-bg")?.value || "#ffffff" }
                   : null,
      createdAt: new Date().toISOString(),
    });
    toast("QR code saved successfully!");
    QRCodes.load();
  } catch (err) {
    console.error("[QR] save error:", err);
    toast("Failed to save QR code.", "error");
  } finally {
    hideSpinner(btn);
  }
}

function downloadQR() {
  if (!State.qrDataUrl) { toast("Preview a QR code first.", "error"); return; }
  const label = $("qr-label")?.value.trim() || "qrcode";
  const a     = document.createElement("a");
  a.href     = State.qrDataUrl;
  a.download = label.replace(/\s+/g, "-") + ".png";
  a.click();
}

// ════════════════════════════════════════════════════════════════════════════════
// SHORT LINKS MODULE
// ════════════════════════════════════════════════════════════════════════════════

const Links = {
  async load() {
    if (!State.user) return;
    const list = $("links-list");
    if (!list) return;

    list.innerHTML = [1,2].map(() =>
      `<div class="skeleton" style="height:74px;border-radius:8px;margin-bottom:8px;"></div>`
    ).join("");

    try {
      const q    = query(collection(db, "shortlinks"), where("userId","==", State.user.uid), orderBy("createdAt","desc"), limit(100));
      const snap = await getDocs(q);
      const links = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      const badge = $("links-count-badge");
      if (badge) { badge.textContent = links.length; badge.style.display = links.length ? "inline-flex" : "none"; }

      if (links.length === 0) {
        list.innerHTML = `<div class="empty-state"><div class="es-icon">🔗</div><p class="es-text">No short links yet. Create your first one above.</p></div>`;
        return;
      }

      list.innerHTML = links.map(lk => {
        const shortUrl = `${window.location.origin}${SERVER_BASE}/api/links/redirect/${lk.code}`;
        const isExpired = lk.expiresAt && new Date(lk.expiresAt) < new Date();
        const isLimited = lk.clickLimit && lk.clicks >= lk.clickLimit;
        const statusLabel = !lk.active ? "inactive" : isExpired ? "expired" : isLimited ? "limit reached" : "active";
        const statusCls   = (!lk.active || isExpired || isLimited) ? "badge-inactive" : "badge-active";

        return `
          <div class="link-row" id="link-row-${lk.id}">
            <div style="flex:1;min-width:0;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;flex-wrap:wrap;">
                <span style="font-size:13.5px;font-weight:800;font-family:monospace;color:#1d4ed8;">${lk.code}</span>
                <span class="badge ${statusCls}">${statusLabel}</span>
                ${lk.clickLimit  ? `<span class="badge badge-premium" style="font-size:9px;">LIMIT ${lk.clickLimit}</span>` : ""}
                ${lk.password    ? `<span class="badge badge-premium" style="font-size:9px;">🔒 PW</span>` : ""}
                ${lk.expiresAt   ? `<span class="badge badge-free" style="font-size:9px;">EXP ${formatDate(lk.expiresAt)}</span>` : ""}
              </div>
              <div style="font-size:12px;color:#64748b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px;" title="${escHtml(lk.originalUrl)}">${lk.originalUrl}</div>
              <div style="font-size:11.5px;color:#94a3b8;margin-top:3px;">
                ${lk.clicks || 0} click${(lk.clicks||0) !== 1 ? "s" : ""} &nbsp;·&nbsp; Created ${formatDate(lk.createdAt)}
              </div>
            </div>
            <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;">
              <button class="btn btn-ghost btn-icon" title="Copy short link" onclick="copyToClipboard('${shortUrl}')">
                <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
              </button>
              <button class="btn btn-ghost btn-icon" title="View analytics" onclick="App.openLinkAnalytics('${lk.code}')">
                <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
              </button>
              <button class="btn btn-ghost btn-icon" title="Delete" style="color:#94a3b8;" onmouseenter="this.style.color='#dc2626'" onmouseleave="this.style.color='#94a3b8'" onclick="Links.delete('${lk.id}','${lk.code}')">
                <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              </button>
            </div>
          </div>`;
      }).join("");
    } catch (err) {
      console.error("[Links] load error:", err);
      list.innerHTML = `<p style="color:#dc2626;font-size:13px;">Failed to load links. Please refresh.</p>`;
    }
  },

  async delete(id, code) {
    if (!confirm(`Delete short link "${code}"? This cannot be undone.`)) return;
    try {
      await deleteDoc(doc(db, "shortlinks", id));
      const row = $("link-row-" + id);
      if (row) row.remove();
      toast("Link deleted.");
      this.load();
    } catch {
      toast("Failed to delete link.", "error");
    }
  },
};

// ── Link form submit ──────────────────────────────────────────────────────────

function initLinkForm() {
  const form = $("link-form");
  if (!form) return;
  form.addEventListener("submit", async e => {
    e.preventDefault();
    if (!State.user) return;

    const url      = $("lf-url")?.value.trim();
    const alias    = $("lf-alias")?.value.trim().toLowerCase().replace(/[^a-z0-9\-_]/g,"").slice(0, 64);
    const expiry   = $("lf-expiry")?.value;
    const clkLimit = $("lf-clicklimit")?.value;
    const password = $("lf-password")?.value;

    if (!url)           { toast("Destination URL is required.", "error"); return; }
    if (!isValidUrl(url)) { toast("Enter a valid URL including https://", "error"); return; }
    if (alias && !/^[a-z0-9\-_]+$/.test(alias)) { toast("Alias can only contain letters, numbers, hyphens, underscores.", "error"); return; }

    const btn = $("lf-submit-btn");
    showSpinner(btn, "Creating…");

    try {
      const code = alias || randCode();

      // Check alias uniqueness
      const existing = await getDoc(doc(db, "shortlinks", code));
      if (existing.exists()) {
        toast(`The alias "${code}" is already taken. Try another.`, "error");
        hideSpinner(btn);
        return;
      }

      const linkData = {
        originalUrl: url,
        userId:      State.user.uid,
        code,
        alias:       alias || null,
        clicks:      0,
        active:      true,
        createdAt:   new Date().toISOString(),
      };

      if (expiry) linkData.expiresAt = new Date(expiry).toISOString();

      if (State.isPremium) {
        if (clkLimit && parseInt(clkLimit) > 0) linkData.clickLimit = parseInt(clkLimit);
        if (password) linkData.password = password;
      }

      await setDoc(doc(db, "shortlinks", code), linkData);

      const shortUrl = `${window.location.origin}${SERVER_BASE}/api/links/redirect/${code}`;
      toast("Short link created!");

      // Show the URL for easy copying
      const list = $("links-list");
      if (list) {
        const flash = document.createElement("div");
        flash.style.cssText = "padding:12px 16px;background:#eff6ff;border:1.5px solid #bfdbfe;border-radius:8px;margin-bottom:8px;display:flex;align-items:center;gap:10px;";
        flash.innerHTML = `
          <span style="font-size:12px;color:#1d4ed8;font-weight:600;flex:1;word-break:break-all;">${shortUrl}</span>
          <button class="btn btn-primary btn-sm" onclick="copyToClipboard('${shortUrl}');this.textContent='Copied!'">Copy</button>`;
        list.prepend(flash);
        setTimeout(() => flash.remove(), 8000);
      }

      form.reset();
      Links.load();
    } catch (err) {
      console.error("[Links] create error:", err);
      toast("Failed to create link. Please try again.", "error");
    } finally {
      hideSpinner(btn);
    }
  });
}

// ════════════════════════════════════════════════════════════════════════════════
// ANALYTICS MODULE
// ════════════════════════════════════════════════════════════════════════════════

const Analytics = {
  _selectedCode: null,
  _links: [],

  async load() {
    if (!State.user) return;
    const root = $("analytics-root");
    if (!root) return;

    root.innerHTML = `<div class="skeleton" style="height:48px;border-radius:8px;margin-bottom:16px;"></div>
      <div class="skeleton" style="height:120px;border-radius:8px;"></div>`;

    try {
      const q    = query(collection(db, "shortlinks"), where("userId","==", State.user.uid), orderBy("createdAt","desc"), limit(100));
      const snap = await getDocs(q);
      this._links = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      if (this._links.length === 0) {
        root.innerHTML = `<div class="empty-state"><div class="es-icon">📊</div>
          <p class="es-text">Create a short link first to start seeing analytics data here.</p></div>`;
        return;
      }

      if (!this._selectedCode || !this._links.find(l => l.code === this._selectedCode)) {
        this._selectedCode = this._links[0].code;
      }

      this.renderShell(root);
      this.loadClicks(this._selectedCode);
    } catch (err) {
      console.error("[Analytics] load error:", err);
      root.innerHTML = `<p style="color:#dc2626;font-size:13px;">Failed to load analytics. Please refresh.</p>`;
    }
  },

  renderShell(root) {
    const options = this._links.map(l =>
      `<option value="${l.code}" ${l.code === this._selectedCode ? "selected" : ""}>${l.code}${l.alias ? " (" + l.alias + ")" : ""} — ${l.clicks || 0} clicks</option>`
    ).join("");

    root.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
        <label class="form-label" style="margin:0;white-space:nowrap;">Select link</label>
        <select class="form-input" id="analytics-select" style="max-width:320px;" onchange="Analytics.onSelect(this.value)">
          ${options}
        </select>
      </div>
      <div id="analytics-stats-area"></div>`;
  },

  onSelect(code) {
    this._selectedCode = code;
    this.loadClicks(code);
  },

  async loadClicks(code) {
    const area = $("analytics-stats-area");
    if (!area) return;
    area.innerHTML = [1,2,3,4].map(() =>
      `<div class="skeleton" style="height:72px;border-radius:10px;margin-bottom:12px;"></div>`).join("");

    try {
      const q    = query(collection(db, "shortlinks", code, "clicks"), orderBy("clickedAt","desc"), limit(200));
      const snap = await getDocs(q);
      const clicks = snap.docs.map(d => d.data());
      const link   = this._links.find(l => l.code === code) || {};

      this.renderStats(area, link, clicks);
    } catch (err) {
      console.error("[Analytics] clicks error:", err);
      area.innerHTML = `<p style="color:#dc2626;font-size:13px;">Failed to load click data.</p>`;
    }
  },

  renderStats(container, link, clicks) {
    const countBy = (key) => {
      const m = {};
      clicks.forEach(c => { const k = c[key] || "Unknown"; m[k] = (m[k]||0) + 1; });
      return Object.entries(m).sort(([,a],[,b]) => b-a);
    };

    const countries = countBy("country");
    const devices   = countBy("device");
    const browsers  = countBy("browser");
    const total     = link.clicks || 0;
    const shortUrl  = `${window.location.origin}${SERVER_BASE}/api/links/redirect/${link.code}`;

    function breakdownRows(entries) {
      if (!entries.length) return `<p style="font-size:12.5px;color:#94a3b8;padding:8px 0;">No data yet.</p>`;
      const max = entries[0][1];
      return entries.slice(0,8).map(([name, count]) => `
        <div class="breakdown-row">
          <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">
            <div style="font-size:13px;font-weight:500;min-width:100px;">${name}</div>
            <div style="flex:1;"><div class="progress-bar"><div class="progress-fill" style="width:${Math.round((count/max)*100)}%"></div></div></div>
          </div>
          <div style="font-size:13px;font-weight:700;margin-left:12px;min-width:30px;text-align:right;">${count}</div>
        </div>`).join("");
    }

    // Free users see limited analytics
    const geoSection = State.isPremium
      ? `<div class="stat-card">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:14px;">Countries</div>
            ${breakdownRows(countries)}
          </div>
          <div class="stat-card">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:14px;">Browsers</div>
            ${breakdownRows(browsers)}
          </div>`
      : `<div class="premium-fence" style="grid-column:1/-1;">
          <span class="pf-icon">🌍</span>
          <span class="pf-text">Country &amp; browser breakdown — Premium only</span>
          <span class="pf-link" onclick="App.openUpgradeModal()">Upgrade ↗</span>
        </div>`;

    container.innerHTML = `
      <!-- Short link meta -->
      <div class="card card-sm" style="margin-bottom:16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
        <div style="flex:1;min-width:0;">
          <span style="font-size:12.5px;font-weight:800;font-family:monospace;color:#1d4ed8;">${link.code}</span>
          <span style="font-size:12px;color:#94a3b8;margin-left:8px;word-break:break-all;">${link.originalUrl?.slice(0,60) || ""}${(link.originalUrl?.length||0)>60?"…":""}</span>
        </div>
        <button class="btn btn-outline btn-sm" onclick="copyToClipboard('${shortUrl}')">Copy link</button>
      </div>

      <!-- Stat cards -->
      <div class="grid-4" style="margin-bottom:16px;">
        <div class="stat-card"><div style="font-size:26px;font-weight:900;color:#1d4ed8;">${total}</div><div style="font-size:12px;color:#64748b;margin-top:4px;">Total clicks</div></div>
        <div class="stat-card"><div style="font-size:26px;font-weight:900;color:#7c3aed;">${countries.length}</div><div style="font-size:12px;color:#64748b;margin-top:4px;">Countries</div></div>
        <div class="stat-card"><div style="font-size:26px;font-weight:900;color:#0891b2;">${devices.length}</div><div style="font-size:12px;color:#64748b;margin-top:4px;">Device types</div></div>
        <div class="stat-card"><div style="font-size:26px;font-weight:900;color:#16a34a;">${link.active ? "Active" : "Off"}</div><div style="font-size:12px;color:#64748b;margin-top:4px;">Status</div></div>
      </div>

      <!-- Breakdowns -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
        <div class="stat-card">
          <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:14px;">Devices</div>
          ${breakdownRows(devices)}
        </div>
        ${geoSection}
      </div>

      <!-- Recent clicks table -->
      ${clicks.length > 0 ? `
      <div class="card" style="overflow-x:auto;">
        <div style="font-size:13.5px;font-weight:700;margin-bottom:14px;">Recent Clicks</div>
        <table style="width:100%;border-collapse:collapse;font-size:12.5px;">
          <thead>
            <tr style="border-bottom:2px solid #e2e8f0;">
              <th style="text-align:left;padding:6px 8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;">Country</th>
              <th style="text-align:left;padding:6px 8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;">City</th>
              <th style="text-align:left;padding:6px 8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;">Device</th>
              <th style="text-align:left;padding:6px 8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;">Browser</th>
              <th style="text-align:left;padding:6px 8px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;">Time</th>
            </tr>
          </thead>
          <tbody>
            ${clicks.slice(0, 30).map(c => `
              <tr style="border-bottom:1px solid #f1f5f9;">
                <td style="padding:8px;color:#374151;">${c.country || "—"}</td>
                <td style="padding:8px;color:#374151;">${State.isPremium ? (c.city || "—") : '<span style="color:#94a3b8;font-style:italic;">Premium</span>'}</td>
                <td style="padding:8px;color:#374151;">${c.device || "—"}</td>
                <td style="padding:8px;color:#374151;">${c.browser || "—"}</td>
                <td style="padding:8px;color:#94a3b8;white-space:nowrap;">${formatDateTime(c.clickedAt)}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>` : `<div class="empty-state"><div class="es-icon">📊</div><p class="es-text">No clicks recorded yet. Share your link to start tracking.</p></div>`}`;
  },
};

// Make Analytics accessible globally (called from HTML onchange)
window.Analytics = Analytics;

// ════════════════════════════════════════════════════════════════════════════════
// SETTINGS MODULE
// ════════════════════════════════════════════════════════════════════════════════

function initSettingsForms() {
  // Profile form
  const profileForm = $("profile-form");
  if (profileForm) {
    profileForm.addEventListener("submit", async e => {
      e.preventDefault();
      if (!State.user) return;
      const name = $("settings-name")?.value.trim() || "";
      const btn  = profileForm.querySelector("button[type=submit]");
      showSpinner(btn, "Saving…");
      try {
        await updateProfile(State.user, { displayName: name });
        await updateDoc(doc(db, "users", State.user.uid), { displayName: name, updatedAt: new Date().toISOString() });
        renderSidebarUser();
        toast("Profile updated.");
      } catch (err) {
        console.error("[Settings] profile error:", err);
        toast("Failed to update profile.", "error");
      } finally {
        hideSpinner(btn);
      }
    });
  }

  // Password form
  const pwForm = $("password-form");
  if (pwForm) {
    pwForm.addEventListener("submit", async e => {
      e.preventDefault();
      if (!State.user) return;
      const pw  = $("new-password")?.value || "";
      if (pw.length < 6) { toast("Password must be at least 6 characters.", "error"); return; }
      const btn = pwForm.querySelector("button[type=submit]");
      showSpinner(btn, "Updating…");
      try {
        await updatePassword(State.user, pw);
        $("new-password").value = "";
        toast("Password updated.");
      } catch (err) {
        if (err.code === "auth/requires-recent-login") {
          toast("Sign out and sign back in before changing your password.", "error");
        } else {
          toast("Failed to update password.", "error");
        }
      } finally {
        hideSpinner(btn);
      }
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// PAYSTACK PAYMENT
// ════════════════════════════════════════════════════════════════════════════════

async function startPaystackPayment() {
  if (!State.user) { toast("You must be logged in.", "error"); return; }

  if (!PAYSTACK_PUBLIC_KEY || PAYSTACK_PUBLIC_KEY.includes("YOUR_PAYSTACK")) {
    toast("Paystack is not configured. Add your public key to main.js.", "error");
    return;
  }

  const btn = $("upgrade-pay-btn");
  showSpinner(btn, "Loading payment…");

  try {
    const handler = window.PaystackPop.setup({
      key:      PAYSTACK_PUBLIC_KEY,
      email:    State.user.email,
      amount:   200000,          // ₦2,000 in kobo
      currency: "NGN",
      ref:      "TRISEND_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8).toUpperCase(),
      metadata: {
        userId:      State.user.uid,
        userEmail:   State.user.email,
        custom_fields: [
          { display_name: "User ID",    variable_name: "userId",    value: State.user.uid },
          { display_name: "User Email", variable_name: "userEmail", value: State.user.email },
        ],
      },

      callback: async (response) => {
        hideSpinner(btn);
        App.closeUpgradeModal();
        toast("Payment received! Verifying…");

        try {
          const res = await fetch(`${SERVER_BASE}/api/payments/verify`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ reference: response.reference, userId: State.user.uid }),
          });

          const data = await res.json();

          if (res.ok && data.success) {
            toast("🎉 You are now a Premium member!");
            // The onSnapshot listener will automatically update the UI
          } else {
            toast(
              "Payment received but verification failed. Contact support with ref: " + response.reference,
              "error"
            );
          }
        } catch (err) {
          console.error("[Payment] verify error:", err);
          toast("Verification error. Please contact support with ref: " + response.reference, "error");
        }
      },

      onClose: () => {
        hideSpinner(btn);
        toast("Payment window closed.");
      },
    });

    handler.openIframe();
  } catch (err) {
    console.error("[Payment] Paystack init error:", err);
    toast("Failed to open payment window. Make sure Paystack script is loaded.", "error");
    hideSpinner(btn);
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// MOBILE SIDEBAR
// ════════════════════════════════════════════════════════════════════════════════

function openMobileSidebar() {
  const overlay = $("mobile-sidebar-overlay");
  if (overlay) overlay.classList.add("open");
}

function closeMobileSidebar() {
  const overlay = $("mobile-sidebar-overlay");
  if (overlay) overlay.classList.remove("open");
}

// ════════════════════════════════════════════════════════════════════════════════
// MODALS
// ════════════════════════════════════════════════════════════════════════════════

function openUpgradeModal()  { const m = $("upgrade-modal");  if (m) m.style.display = "flex"; }
function closeUpgradeModal() { const m = $("upgrade-modal");  if (m) m.style.display = "none"; }
function openDeleteModal()   { const m = $("delete-modal");   if (m) m.style.display = "flex"; }
function closeDeleteModal()  {
  const m  = $("delete-modal");
  const ci = $("delete-confirm-input");
  if (m)  m.style.display = "none";
  if (ci) ci.value = "";
}

// Close modals on backdrop click
["upgrade-modal","delete-modal"].forEach(id => {
  const el = $(id);
  if (!el) return;
  el.addEventListener("click", e => { if (e.target === el) el.style.display = "none"; });
});

// ════════════════════════════════════════════════════════════════════════════════
// ACCOUNT ACTIONS
// ════════════════════════════════════════════════════════════════════════════════

async function userSignOut() {
  try {
    if (State.userUnsubFn) State.userUnsubFn();
    await signOut(auth);
    window.location.href = "login.html";
  } catch {
    toast("Sign out failed. Please try again.", "error");
  }
}

async function confirmDeleteAccount() {
  const input = $("delete-confirm-input")?.value.trim();
  if (input !== "DELETE") { toast('Type "DELETE" exactly to confirm.', "error"); return; }
  if (!State.user)        { toast("Not logged in.", "error"); return; }

  try {
    await deleteUser(State.user);
    window.location.href = "index.html";
  } catch (err) {
    if (err.code === "auth/requires-recent-login") {
      toast("Sign out and sign back in before deleting your account.", "error");
    } else {
      console.error("[Settings] delete error:", err);
      toast("Failed to delete account.", "error");
    }
    closeDeleteModal();
  }
}

function openLinkAnalytics(code) {
  Analytics._selectedCode = code;
  switchTab("analytics");
}

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API — wired to onclick attributes in dashboard.html
// ════════════════════════════════════════════════════════════════════════════════

window.App = {
  switchTab,
  previewQR,
  saveQR,
  downloadQR,
  openUpgradeModal,
  closeUpgradeModal,
  openDeleteModal,
  closeDeleteModal,
  startPaystackPayment,
  openMobileSidebar,
  closeMobileSidebar,
  signOut:               userSignOut,
  confirmDeleteAccount,
  openLinkAnalytics,
};

window.QRCodes = QRCodes;
window.Links   = Links;
window.copyToClipboard = copyToClipboard;

// ════════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  QRCodes.initTypeGrid();
  initLinkForm();
  initSettingsForms();
  initAuth();          // triggers onAuthStateChanged → loads data
});
