/* ============================================================================
   EDOM & YOHI — PREMIUM WEDDING WEBSITE
   Complete single-file Node.js application
   Stack: Express + PostgreSQL + Cloudinary + Resend
   Deploy: Render Web Service
   ============================================================================ */

import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import multer from "multer";
import pg from "pg";
import { v2 as cloudinary } from "cloudinary";
import { Resend } from "resend";

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------- DATABASE (PostgreSQL on Render requires SSL) ---------- */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },   // required for Render managed Postgres[reference:6]
  max: 5,
  idleTimeoutMillis: 30000
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS rsvps (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150),
  phone VARCHAR(30),
  attending BOOLEAN NOT NULL,
  guests INTEGER DEFAULT 1 CHECK (guests BETWEEN 1 AND 10),
  message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS media (
  id SERIAL PRIMARY KEY,
  type VARCHAR(10) NOT NULL CHECK (type IN ('image','video')),
  url TEXT NOT NULL,
  public_id TEXT,
  caption TEXT,
  is_featured BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS guests (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150),
  phone VARCHAR(30),
  invited_by VARCHAR(50) DEFAULT 'Edom & Yohi',
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rsvps_attending ON rsvps(attending, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_featured ON media(is_featured, created_at DESC);
`;

async function initDb(retries = 6) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query(SCHEMA);
      console.log("✅ Database ready");
      return;
    } catch (err) {
      console.warn(`DB attempt ${i + 1} failed:`, err.message);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error("❌ DB initialisation failed after retries");
}

/* ---------- SERVICES ---------- */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

/* ---------- SECURITY MIDDLEWARE ---------- */
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const rsvpLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const apiLimiter   = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api", apiLimiter);

/* ---------- HELPERS ---------- */
function sha256(x) {
  return crypto.createHash("sha256").update(x).digest("hex");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

/* ---------- ADMIN AUTH ---------- */
const ADMIN_COOKIE = "ey_admin";

function signAdminToken() {
  return jwt.sign({ role: "admin" }, process.env.JWT_SECRET, { expiresIn: "12h" });
}

function requireAdmin(req, res, next) {
  const token = req.cookies[ADMIN_COOKIE];
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== "admin") throw new Error("bad role");
    next();
  } catch {
    res.status(401).json({ error: "Session expired" });
  }
}

/* ---------- MULTER (memory storage → Cloudinary) ---------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$|^video\/(mp4|webm|quicktime)$/.test(file.mimetype);
    cb(ok ? null : new Error("Only images or videos allowed"), ok);
  }
});

/* ============================================================================
   API ROUTES
   ============================================================================ */

/* ---------- HEALTH ---------- */
app.get("/api/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

/* ---------- AUTH ---------- */
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: "Password required" });
  if (!process.env.ADMIN_PASSWORD_HASH)
    return res.status(500).json({ error: "Admin not configured" });

  const ok = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: "Incorrect password" });

  res.cookie(ADMIN_COOKIE, signAdminToken(), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 12 * 60 * 60 * 1000,
    path: "/"
  });
  res.json({ ok: true });
});

app.post("/api/admin/logout", (_req, res) => {
  res.clearCookie(ADMIN_COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (_req, res) => res.json({ ok: true }));

/* ---------- MEDIA (public read) ---------- */
app.get("/api/media", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, type, url, caption, is_featured FROM media ORDER BY is_featured DESC, created_at DESC"
  );
  res.json(rows);
});

/* ---------- MEDIA (admin write) ---------- */
app.post("/api/admin/media", requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const { caption } = req.body || {};
  const type = req.file.mimetype.startsWith("video") ? "video" : "image";

  try {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          resource_type: type === "video" ? "video" : "image",
          folder: "edom-yohi-wedding"
        },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(req.file.buffer);
    });

    const { rows } = await pool.query(
      `INSERT INTO media (type, url, public_id, caption)
       VALUES ($1, $2, $3, $4) RETURNING id, type, url, caption, is_featured`,
      [type, result.secure_url, result.public_id, String(caption || "").slice(0, 200)]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Cloudinary upload failed:", err.message);
    res.status(500).json({ error: "Upload failed. Please try again." });
  }
});

app.patch("/api/admin/media/:id/feature", requireAdmin, async (req, res) => {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("UPDATE media SET is_featured = FALSE");
    const { rowCount } = await c.query(
      "UPDATE media SET is_featured = TRUE WHERE id = $1",
      [Number(req.params.id)]
    );
    await c.query("COMMIT");
    if (!rowCount) return res.status(404).json({ error: "Media not found" });
    res.json({ ok: true });
  } catch {
    await c.query("ROLLBACK");
    res.status(500).json({ error: "Could not feature media" });
  } finally {
    c.release();
  }
});

app.delete("/api/admin/media/:id", requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT public_id, type FROM media WHERE id = $1", [Number(req.params.id)]);
  if (!rows.length) return res.status(404).json({ error: "Media not found" });

  if (rows[0].public_id) {
    try {
      await cloudinary.uploader.destroy(rows[0].public_id, {
        resource_type: rows[0].type === "video" ? "video" : "image"
      });
    } catch (e) {
      console.warn("Cloudinary destroy warning:", e.message);
    }
  }
  await pool.query("DELETE FROM media WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ---------- RSVP (public submit) ---------- */
app.post("/api/rsvp", rsvpLimiter, async (req, res) => {
  const { name, email, phone, attending, guests, message } = req.body || {};

  const cleanName = String(name || "").trim().slice(0, 100);
  const cleanEmail = String(email || "").trim().slice(0, 150);
  const cleanPhone = String(phone || "").trim().slice(0, 30);
  const cleanMsg   = String(message || "").trim().slice(0, 500);

  if (cleanName.length < 2)
    return res.status(400).json({ error: "Please enter your full name." });
  if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail))
    return res.status(400).json({ error: "Please enter a valid email address." });
  if (typeof attending !== "boolean")
    return res.status(400).json({ error: "Please select whether you will attend." });

  const guestCount = Math.min(Math.max(parseInt(guests, 10) || 1, 1), 10);

  const { rows } = await pool.query(
    `INSERT INTO rsvps (name, email, phone, attending, guests, message)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at`,
    [cleanName, cleanEmail || null, cleanPhone || null, attending, guestCount, cleanMsg || null]
  );

  /* Optional email notification (fails silently if not configured) */
  if (resend && process.env.ADMIN_EMAIL && process.env.FROM_EMAIL) {
    resend.emails.send({
      from: process.env.FROM_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: `New RSVP from ${cleanName}`,
      html: `
        <div style="font-family:Georgia,serif;background:#0a0a0a;color:#EDE3D0;padding:32px;border-radius:12px">
          <h2 style="color:#D4AF37">New RSVP for EDOM &amp; Yohi</h2>
          <p><strong>Name:</strong> ${esc(cleanName)}</p>
          <p><strong>Email:</strong> ${cleanEmail ? esc(cleanEmail) : "—"}</p>
          <p><strong>Phone:</strong> ${cleanPhone ? esc(cleanPhone) : "—"}</p>
          <p><strong>Attending:</strong> ${attending ? "Yes" : "No"}</p>
          <p><strong>Guests:</strong> ${guestCount}</p>
          <p><strong>Date:</strong> ${new Date(rows[0].created_at).toUTCString()}</p>
          ${cleanMsg ? `<hr style="border-color:#333"><p style="white-space:pre-wrap">${esc(cleanMsg)}</p>` : ""}
        </div>`
    }).catch(err => console.warn("Resend email skipped:", err.message));
  }

  res.status(201).json({ ok: true });
});

/* ---------- RSVP (admin read) ---------- */
app.get("/api/admin/rsvps", requireAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, name, email, phone, attending, guests, message, created_at FROM rsvps ORDER BY created_at DESC"
  );
  res.json(rows);
});

app.delete("/api/admin/rsvps/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM rsvps WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ---------- GUEST LIST (admin) ---------- */
app.get("/api/admin/guests", requireAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, name, email, phone, invited_by, notes, created_at FROM guests ORDER BY created_at DESC"
  );
  res.json(rows);
});

app.post("/api/admin/guests", requireAdmin, async (req, res) => {
  const { name, email, phone, notes } = req.body || {};
  const cleanName = String(name || "").trim().slice(0, 100);
  if (cleanName.length < 2) return res.status(400).json({ error: "Name required" });

  const { rows } = await pool.query(
    "INSERT INTO guests (name, email, phone, notes) VALUES ($1,$2,$3,$4) RETURNING id, name, email, phone, notes",
    [cleanName, String(email || "").slice(0, 150) || null,
     String(phone || "").slice(0, 30) || null, String(notes || "").slice(0, 300) || null]
  );
  res.status(201).json(rows[0]);
});

app.delete("/api/admin/guests/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM guests WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ============================================================================
   PUBLIC FRONTEND (inlined HTML)
   ============================================================================ */
const PUBLIC_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>EDOM & Yohi — Wedding Invitation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Cormorant+Garamond:ital,wght@0,400;0,600;1,400&family=Montserrat:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root{--black:#080808;--gold:#D4AF37;--gold2:#F3E3A8;--gold3:#B8912E;--text:#EDE3D0;--muted:#A89880;--line:rgba(212,175,55,.22);--serif:"Cormorant Garamond",Georgia,serif;--script:"Great Vibes",cursive;--sans:"Montserrat",sans-serif}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth}
body{margin:0;background:var(--black);color:var(--text);font-family:var(--sans);font-weight:300;line-height:1.65;overflow-x:hidden;-webkit-font-smoothing:antialiased}
img{max-width:100%;display:block}
a{color:var(--gold);text-decoration:none}
.wrap{max-width:820px;margin:0 auto;padding:0 22px}
.sec{padding:80px 0;position:relative}
.sec+.sec{border-top:1px solid var(--line)}
.topbar{position:fixed;inset:0 0 auto 0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:14px 20px;padding-top:calc(14px + env(safe-area-inset-top,0px));background:linear-gradient(180deg,rgba(8,8,8,.92),transparent);backdrop-filter:blur(8px)}
.brand{font-family:var(--serif);font-size:19px;letter-spacing:4px;color:var(--gold)}
.hero{min-height:100vh;min-height:100svh;display:flex;align-items:center;justify-content:center;text-align:center;padding:120px 20px 70px;position:relative;overflow:hidden;background:radial-gradient(ellipse at 20% 10%,rgba(212,175,55,.10),transparent 55%),radial-gradient(ellipse at 80% 90%,rgba(212,175,55,.08),transparent 55%),var(--black)}
.hero-bg{position:absolute;inset:0;background-size:cover;background-position:center;opacity:0;transition:opacity 1.4s ease}
.hero-bg.on{opacity:.42}
.hero-bg::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(8,8,8,.55),rgba(8,8,8,.85))}
.rings{width:120px;height:120px;margin:0 auto 22px;filter:drop-shadow(0 0 18px rgba(212,175,55,.55));position:relative;z-index:1}
.rings svg{width:100%;height:100%;overflow:visible}
.rings .r{fill:none;stroke:url(#gg);stroke-width:2.2;stroke-linecap:round;stroke-dasharray:270;stroke-dashoffset:270;animation:draw 2.4s ease forwards}
.rings .r2{animation-delay:.5s}
@keyframes draw{to{stroke-dashoffset:0}}
.kicker{font-family:var(--serif);font-style:italic;font-size:15px;color:var(--gold);margin:0 0 8px}
.names{font-family:var(--script);font-size:clamp(56px,17vw,116px);line-height:.95;margin:0;color:var(--gold2);font-weight:400;letter-spacing:1px}
.names .amp{font-family:var(--serif);font-style:italic;color:var(--gold);font-size:.55em;margin:0 6px;display:inline-block;transform:translateY(-.15em)}
.tag{font-family:var(--serif);font-size:clamp(15px,3.6vw,19px);color:var(--champagne);margin:18px auto 0;max-width:520px;line-height:1.6}
.cta{display:inline-flex;align-items:center;gap:8px;margin-top:30px;padding:13px 30px;border:1px solid var(--gold);border-radius:999px;color:var(--gold);font-size:12px;letter-spacing:2px;text-transform:uppercase;transition:.3s}
.cta:hover{background:var(--gold);color:#000}
.cd{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;max-width:520px;margin:36px auto 0}
.cd div{border:1px solid var(--line);border-radius:12px;padding:14px 4px;background:rgba(255,255,255,.02)}
.cd b{display:block;font-family:var(--serif);font-size:clamp(26px,6vw,38px);font-weight:600;color:var(--gold2);line-height:1}
.cd span{display:block;font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-top:6px}
@media(max-width:420px){.cd{grid-template-columns:repeat(2,1fr)}}
.sec-k{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--gold3);text-align:center;margin:0 0 6px}
.sec-t{font-family:var(--script);font-size:clamp(38px,8vw,56px);color:var(--gold);text-align:center;margin:0 0 8px;font-weight:400}
.sec-s{font-family:var(--serif);font-style:italic;text-align:center;color:var(--muted);margin:0 auto 34px;max-width:560px}
.letter{max-width:640px;margin:0 auto;border:1px solid var(--line);border-radius:18px;padding:32px 28px;background:linear-gradient(180deg,rgba(212,175,55,.05),transparent);position:relative}
.letter::before{content:"❝";position:absolute;top:10px;left:20px;font-family:var(--serif);font-size:56px;color:var(--gold);opacity:.28;line-height:1}
.letter p{font-family:var(--serif);font-size:18px;line-height:1.85;margin:0 0 16px;color:var(--text);position:relative}
.letter .sig{font-family:var(--script);font-size:30px;color:var(--gold);margin-top:20px;text-align:right}
.details{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:620px;margin:0 auto}
@media(max-width:560px){.details{grid-template-columns:1fr}}
.card{border:1px solid var(--line);border-radius:16px;padding:26px 20px;text-align:center;background:rgba(255,255,255,.02)}
.card .v{font-family:var(--serif);font-size:19px;color:var(--champagne);margin:0;line-height:1.45}
.card .s{font-size:13px;color:var(--muted);margin:6px 0 0}
.map{display:inline-flex;align-items:center;gap:6px;margin-top:12px;font-size:12px;letter-spacing:1px;border-bottom:1px solid var(--line);padding-bottom:2px}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;max-width:820px;margin:0 auto}
.gallery .item{border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#101010}
.gallery .item img,.gallery .item video{width:100%;aspect-ratio:4/3;object-fit:cover;display:block}
.gallery .item .cap{padding:8px 12px;font-size:12px;color:var(--muted);text-align:center}
.rsvp-form{max-width:520px;margin:0 auto;display:flex;flex-direction:column;gap:12px}
.rsvp-form input,.rsvp-form textarea,.rsvp-form select{font:inherit;font-size:15px;color:var(--text);background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:10px;padding:13px 15px;width:100%;transition:.25s}
.rsvp-form input:focus,.rsvp-form textarea:focus,.rsvp-form select:focus{outline:none;border-color:var(--gold)}
.rsvp-form label{font-size:13px;color:var(--muted);margin-bottom:2px}
.btn{font:inherit;font-size:12px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;background:var(--gold);color:#000;border:1px solid var(--gold);border-radius:999px;padding:13px 28px;font-weight:600;transition:.3s}
.btn:hover{background:transparent;color:var(--gold)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.status{min-height:1.2em;text-align:center;font-size:13px;margin:10px 0 0;color:var(--muted)}
.status.ok{color:#7dd3a0}.status.err{color:#e0796f}
.foot{text-align:center;padding:60px 20px calc(50px + env(safe-area-inset-bottom,0px));border-top:1px solid var(--line)}
.foot .n{font-family:var(--script);font-size:40px;color:var(--gold);margin:0}
.foot p{color:var(--muted);font-size:12px;letter-spacing:1px;margin:8px 0 0}
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">E &amp; Y</div>
</header>

<section class="hero">
  <div class="hero-bg" id="heroBg"></div>
  <div style="position:relative;z-index:2">
    <div class="rings">
      <svg viewBox="0 0 120 120">
        <defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#F3E3A8"/><stop offset="50%" stop-color="#D4AF37"/><stop offset="100%" stop-color="#B8912E"/></linearGradient></defs>
        <circle class="r" cx="46" cy="66" r="28"/>
        <circle class="r r2" cx="74" cy="66" r="28"/>
      </svg>
    </div>
    <p class="kicker">The Wedding Celebration Of</p>
    <h1 class="names">Edom<span class="amp">&amp;</span>Yohi</h1>
    <p class="tag">Two Hearts. One Promise. One Beautiful Forever.</p>
    <div class="cd">
      <div><b id="d">00</b><span>Days</span></div>
      <div><b id="h">00</b><span>Hours</span></div>
      <div><b id="m">00</b><span>Minutes</span></div>
      <div><b id="s">00</b><span>Seconds</span></div>
    </div>
    <a class="cta" href="#rsvp">RSVP Now</a>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <p class="sec-k">From Edom to Yohi</p>
    <h2 class="sec-t">Our Love Story</h2>
    <div class="letter">
      <p>Yohi, you are not just someone I chose to walk beside. You are the woman who makes my future feel beautiful and my heart feel at home. Your smile is a blessing in my life, your presence is my happiness, and your place in my heart is one that nobody else could ever take.</p>
      <p>I do not promise a perfect life, but I promise to stand beside you, respect you, protect our dreams, pray with you, and choose you through every season of life.</p>
      <p>You are my Yohi, my special person, my future wife, and the woman with whom I want to build a beautiful family.</p>
      <p class="sig">— Edom</p>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <p class="sec-k">The Word That Guides Us</p>
    <h2 class="sec-t">Our Bible Verse</h2>
    <div class="letter" style="text-align:center">
      <p style="font-style:italic">“Love is patient, love is kind. It does not envy, it does not boast, it is not proud. It does not dishonor others, it is not self-seeking, it is not easily angered, it keeps no record of wrongs. Love does not delight in evil but rejoices with the truth. It always protects, always trusts, always hopes, always perseveres.”</p>
      <p style="font-size:14px;color:var(--gold3)">1 Corinthians 13:4–7</p>
      <p style="font-style:italic;margin-top:20px">“Two are better than one, because they have a good return for their labor.”</p>
      <p style="font-size:14px;color:var(--gold3)">Ecclesiastes 4:9</p>
    </div>
  </div>
</section>

<section class="sec" id="details">
  <div class="wrap">
    <p class="sec-k">The Celebration</p>
    <h2 class="sec-t">When &amp; Where</h2>
    <div class="details">
      <div class="card">
        <h3 style="font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:var(--gold3)">Date</h3>
        <p class="v">28 Ginbot 2029</p>
        <p class="s">Monday · 10:00 AM</p>
      </div>
      <div class="card">
        <h3 style="font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:var(--gold3)">Venue</h3>
        <p class="v">Hawassa Apostolic Church</p>
        <p class="s">Hawassa, Ethiopia</p>
        <a class="map" target="_blank" rel="noopener" href="https://www.google.com/maps/search/?api=1&query=Hawassa%20Apostolic%20Church%2C%20Ethiopia">Open in Maps →</a>
      </div>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <p class="sec-k">Our Moments</p>
    <h2 class="sec-t">Photo &amp; Video Gallery</h2>
    <div class="gallery" id="gallery"></div>
  </div>
</section>

<section class="sec" id="rsvp">
  <div class="wrap">
    <p class="sec-k">Be Our Guest</p>
    <h2 class="sec-t">RSVP</h2>
    <p class="sec-s">Please let us know if you can join us</p>
    <form class="rsvp-form" id="rsvpForm">
      <label>Full Name *</label>
      <input type="text" id="rName" required maxlength="100" placeholder="Your full name">
      <label>Email</label>
      <input type="email" id="rEmail" maxlength="150" placeholder="you@example.com">
      <label>Phone</label>
      <input type="tel" id="rPhone" maxlength="30" placeholder="+251 ...">
      <label>Will you attend? *</label>
      <select id="rAttending" required>
        <option value="">Select…</option>
        <option value="yes">Yes, I will attend</option>
        <option value="no">No, I cannot attend</option>
      </select>
      <label>Number of guests (including you)</label>
      <input type="number" id="rGuests" min="1" max="10" value="1">
      <label>Message (optional)</label>
      <textarea id="rMsg" maxlength="500" rows="3" placeholder="Your wishes…"></textarea>
      <button class="btn" type="submit" id="rsvpBtn">Send RSVP</button>
    </form>
    <p class="status" id="rsvpStatus" role="status" aria-live="polite"></p>
  </div>
</section>

<footer class="foot">
  <p class="n">Edom &amp; Yohi</p>
  <p>With love — 28 Ginbot 2029 · Hawassa</p>
</footer>

<script>
var $ = function(s){ return document.querySelector(s); };

/* Countdown */
var target = new Date("2029-05-28T10:00:00+03:00").getTime();
function tick(){
  var diff = target - Date.now(); if (diff < 0) diff = 0;
  var s = Math.floor(diff / 1000);
  $("#d").textContent = String(Math.floor(s / 86400)).padStart(2, "0");
  $("#h").textContent = String(Math.floor((s % 86400) / 3600)).padStart(2, "0");
  $("#m").textContent = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  $("#s").textContent = String(s % 60).padStart(2, "0");
}
tick(); setInterval(tick, 1000);

/* Hero background from featured media */
fetch("/api/media").then(function(r){ return r.json(); }).then(function(list){
  var featured = list.find(function(m){ return m.is_featured; });
  if (featured && featured.type === "image") {
    var bg = $("#heroBg");
    bg.style.backgroundImage = "url('" + featured.url + "')";
    bg.classList.add("on");
  }
  var gallery = $("#gallery");
  gallery.innerHTML = "";
  if (!list.length) {
    gallery.innerHTML = '<p style="color:var(--muted);text-align:center">Photos coming soon</p>';
    return;
  }
  list.forEach(function(m){
    var d = document.createElement("div");
    d.className = "item";
    if (m.type === "video") {
      var v = document.createElement("video");
      v.src = m.url; v.controls = true; v.preload = "metadata";
      d.appendChild(v);
    } else {
      var im = document.createElement("img");
      im.src = m.url; im.alt = m.caption || "Wedding photo"; im.loading = "lazy";
      d.appendChild(im);
    }
    if (m.caption) {
      var cap = document.createElement("div");
      cap.className = "cap"; cap.textContent = m.caption;
      d.appendChild(cap);
    }
    gallery.appendChild(d);
  });
}).catch(function(e){ console.warn("Media unavailable", e); });

/* RSVP submit */
$("#rsvpForm").addEventListener("submit", function(e){
  e.preventDefault();
  var btn = $("#rsvpBtn"), st = $("#rsvpStatus");
  var name = $("#rName").value.trim();
  var email = $("#rEmail").value.trim();
  var phone = $("#rPhone").value.trim();
  var attendingVal = $("#rAttending").value;
  var guests = parseInt($("#rGuests").value, 10) || 1;
  var message = $("#rMsg").value.trim();

  st.className = "status"; st.textContent = "";
  if (name.length < 2) { st.className = "status err"; st.textContent = "Please enter your name."; return; }
  if (!attendingVal) { st.className = "status err"; st.textContent = "Please select attendance."; return; }

  btn.disabled = true;
  st.textContent = "Sending…";

  fetch("/api/rsvp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: name,
      email: email,
      phone: phone,
      attending: attendingVal === "yes",
      guests: guests,
      message: message
    })
  }).then(function(r){ return r.json().then(function(d){ return { ok: r.ok, data: d }; }); })
    .then(function(res){
      if (!res.ok) throw new Error(res.data.error || "Failed");
      st.className = "status ok";
      st.textContent = "Thank you! Your RSVP has been received.";
      $("#rsvpForm").reset();
    })
    .catch(function(err){
      st.className = "status err";
      st.textContent = err.message || "Could not send. Please try again.";
    })
    .finally(function(){ btn.disabled = false; });
});
<\/script>
</body>
</html>`;

/* ============================================================================
   ADMIN FRONTEND (inlined HTML)
   ============================================================================ */
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — EDOM &amp; Yohi</title>
<style>
:root{--black:#080808;--gold:#D4AF37;--line:rgba(212,175,55,.25);--text:#EDE3D0;--muted:#A89880;--red:#e0796f;--green:#7dd3a0}
*{box-sizing:border-box}
body{margin:0;background:var(--black);color:var(--text);font-family:Montserrat,system-ui,sans-serif;font-weight:300;min-height:100vh;padding:24px 16px;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto}
h1{font-family:Georgia,serif;color:var(--gold);font-weight:400;text-align:center;margin:0 0 6px}
.sub{text-align:center;color:var(--muted);font-size:13px;margin:0 0 24px}
.card{border:1px solid var(--line);border-radius:14px;padding:24px;background:rgba(255,255,255,.02);margin-bottom:18px}
input,button,textarea,select{font:inherit;font-size:14px}
input[type=password],input[type=file],input[type=text],input[type=email],input[type=tel],textarea,select{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#111;color:var(--text);margin-bottom:10px}
button{cursor:pointer;border-radius:999px;padding:10px 20px;border:1px solid var(--gold);background:var(--gold);color:#000;font-weight:600;transition:.25s}
button:hover{background:transparent;color:var(--gold)}
button:disabled{opacity:.5;cursor:not-allowed}
button.ghost{background:transparent;color:var(--gold)}
button.danger{border-color:var(--red);background:transparent;color:var(--red)}
button.danger:hover{background:var(--red);color:#000}
button.small{padding:6px 12px;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.tabs{display:flex;gap:8px;margin-bottom:18px}
.tabs button{flex:1}
.tabs button.active{background:var(--gold);color:#000}
.hidden{display:none!important}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--gold3);font-weight:500;text-transform:uppercase;letter-spacing:1px;font-size:11px}
.msg{font-size:13px;margin:10px 0 0;min-height:1em}
.msg.err{color:var(--red)}.msg.ok{color:var(--green)}
.media-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:14px}
.media-item{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#111}
.media-item img,.media-item video{width:100%;aspect-ratio:1;object-fit:cover;display:block}
.media-item .actions{padding:6px;display:flex;gap:4px;flex-wrap:wrap}
</style>
</head>
<body>
<div class="wrap">
  <h1>EDOM &amp; Yohi — Admin</h1>
  <p class="sub">Private control panel</p>

  <div id="loginView" class="card">
    <input id="pwd" type="password" placeholder="Admin password" autocomplete="current-password">
    <div class="row">
      <button id="loginBtn">Sign in</button>
      <button id="logoutBtn" class="ghost hidden">Sign out</button>
    </div>
    <p id="loginMsg" class="msg"></p>
  </div>

  <div id="dashView" class="hidden">
    <div class="tabs">
      <button id="tabRsvp" class="active">RSVPs</button>
      <button id="tabGuests" class="ghost">Guest List</button>
      <button id="tabMedia" class="ghost">Media</button>
    </div>

    <!-- RSVPs -->
    <div id="rsvpPane" class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2 style="margin:0;color:var(--gold);font-weight:400;font-size:18px">Guest RSVPs</h2>
        <button class="ghost small" id="refreshRsvp">Refresh</button>
      </div>
      <div id="rsvpList"></div>
    </div>

    <!-- Guest List -->
    <div id="guestsPane" class="card hidden">
      <h2 style="margin:0 0 10px;color:var(--gold);font-weight:400;font-size:18px">Add Guest</h2>
      <input type="text" id="gName" placeholder="Full name *" maxlength="100">
      <input type="email" id="gEmail" placeholder="Email" maxlength="150">
      <input type="tel" id="gPhone" placeholder="Phone" maxlength="30">
      <input type="text" id="gNotes" placeholder="Notes" maxlength="300">
      <button id="addGuestBtn">Add Guest</button>
      <p id="guestMsg" class="msg"></p>
      <div id="guestList" style="margin-top:14px"></div>
    </div>

    <!-- Media -->
    <div id="mediaPane" class="card hidden">
      <h2 style="margin:0 0 10px;color:var(--gold);font-weight:400;font-size:18px">Upload Media</h2>
      <input type="file" id="mediaFile" accept="image/*,video/*">
      <input type="text" id="mediaCaption" placeholder="Caption (optional)" maxlength="200">
      <div class="row">
        <button id="uploadMediaBtn">Upload</button>
      </div>
      <p id="mediaMsg" class="msg"></p>
      <div id="mediaGrid" class="media-grid"></div>
    </div>
  </div>
</div>

<script>
var $ = function(s){ return document.querySelector(s); };
function msg(el, text, type){ var e = $(el); e.textContent = text; e.className = "msg " + (type || ""); }
function esc(s){ return String(s).replace(/[&<>"']/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); }

function api(path, opts){
  opts = opts || {};
  return fetch(path, {
    credentials: "same-origin",
    headers: Object.assign({ "Content-Type": "application/json" }, opts.headers || {}),
    method: opts.method, body: opts.body
  }).then(function(r){
    return r.json().catch(function(){ return {}; }).then(function(d){
      if (!r.ok) throw new Error(d.error || ("HTTP " + r.status));
      return d;
    });
  });
}

/* Session */
function checkSession(){
  api("/api/admin/me").then(showDash).catch(function(){
    $("#dashView").classList.add("hidden");
    $("#loginView").classList.remove("hidden");
  });
}
function showDash(){
  $("#loginView").classList.add("hidden");
  $("#dashView").classList.remove("hidden");
  $("#logoutBtn").classList.remove("hidden");
  loadRsvps(); loadGuests(); loadMedia();
}

$("#loginBtn").onclick = function(){
  msg("#loginMsg", "");
  api("/api/admin/login", { method: "POST", body: JSON.stringify({ password: $("#pwd").value }) })
    .then(function(){ $("#pwd").value = ""; showDash(); })
    .catch(function(e){ msg("#loginMsg", e.message, "err"); });
};
$("#pwd").addEventListener("keydown", function(e){ if (e.key === "Enter") $("#loginBtn").click(); });
$("#logoutBtn").onclick = function(){
  api("/api/admin/logout", { method: "POST" }).then(function(){
    $("#dashView").classList.add("hidden");
    $("#loginView").classList.remove("hidden");
    $("#logoutBtn").classList.add("hidden");
  });
};

/* Tabs */
function setTab(name){
  ["rsvp","guests","media"].forEach(function(n){
    var btn = $("#tab" + n.charAt(0).toUpperCase() + n.slice(1));
    var pane = $("#" + n + "Pane");
    if (n === name) { btn.classList.add("active"); btn.classList.remove("ghost"); pane.classList.remove("hidden"); }
    else { btn.classList.remove("active"); btn.classList.add("ghost"); pane.classList.add("hidden"); }
  });
}
$("#tabRsvp").onclick = function(){ setTab("rsvp"); };
$("#tabGuests").onclick = function(){ setTab("guests"); };
$("#tabMedia").onclick = function(){ setTab("media"); };

/* RSVPs */
function loadRsvps(){
  api("/api/admin/rsvps").then(function(list){
    var el = $("#rsvpList");
    if (!list.length) { el.innerHTML = '<p style="color:var(--muted)">No RSVPs yet.</p>'; return; }
    var html = '<table><thead><tr><th>Name</th><th>Email</th><th>Attending</th><th>Guests</th><th>Date</th><th></th></tr></thead><tbody>';
    list.forEach(function(r){
      html += '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.email || "—") + '</td><td>' + (r.attending ? "Yes" : "No") + '</td><td>' + r.guests + '</td><td>' + new Date(r.created_at).toLocaleDateString() + '</td><td><button class="danger small" data-del-rsvp="' + r.id + '">Delete</button></td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
    el.querySelectorAll("[data-del-rsvp]").forEach(function(b){
      b.onclick = function(){
        if (!confirm("Delete this RSVP?")) return;
        api("/api/admin/rsvps/" + b.getAttribute("data-del-rsvp"), { method: "DELETE" }).then(loadRsvps).catch(function(e){ alert(e.message); });
      };
    });
  }).catch(function(e){ $("#rsvpList").innerHTML = '<p style="color:var(--red)">' + esc(e.message) + '</p>'; });
}
$("#refreshRsvp").onclick = loadRsvps;

/* Guests */
function loadGuests(){
  api("/api/admin/guests").then(function(list){
    var el = $("#guestList");
    if (!list.length) { el.innerHTML = '<p style="color:var(--muted)">No guests added yet.</p>'; return; }
    var html = '<table><thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Notes</th><th></th></tr></thead><tbody>';
    list.forEach(function(g){
      html += '<tr><td>' + esc(g.name) + '</td><td>' + esc(g.email || "—") + '</td><td>' + esc(g.phone || "—") + '</td><td>' + esc(g.notes || "—") + '</td><td><button class="danger small" data-del-guest="' + g.id + '">Delete</button></td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
    el.querySelectorAll("[data-del-guest]").forEach(function(b){
      b.onclick = function(){
        if (!confirm("Delete this guest?")) return;
        api("/api/admin/guests/" + b.getAttribute("data-del-guest"), { method: "DELETE" }).then(loadGuests).catch(function(e){ alert(e.message); });
      };
    });
  }).catch(function(e){ $("#guestList").innerHTML = '<p style="color:var(--red)">' + esc(e.message) + '</p>'; });
}
$("#addGuestBtn").onclick = function(){
  msg("#guestMsg", "");
  api("/api/admin/guests", {
    method: "POST",
    body: JSON.stringify({
      name: $("#gName").value.trim(),
      email: $("#gEmail").value.trim(),
      phone: $("#gPhone").value.trim(),
      notes: $("#gNotes").value.trim()
    })
  }).then(function(){
    $("#gName").value = ""; $("#gEmail").value = ""; $("#gPhone").value = ""; $("#gNotes").value = "";
    msg("#guestMsg", "Guest added.", "ok");
    loadGuests();
  }).catch(function(e){ msg("#guestMsg", e.message, "err"); });
};

/* Media */
function loadMedia(){
  api("/api/media").then(function(list){
    var el = $("#mediaGrid");
    el.innerHTML = "";
    list.forEach(function(m){
      var d = document.createElement("div");
      d.className = "media-item";
      if (m.type === "video") {
        var v = document.createElement("video"); v.src = m.url; v.preload = "metadata"; d.appendChild(v);
      } else {
        var im = document.createElement("img"); im.src = m.url; im.alt = ""; d.appendChild(im);
      }
      var acts = document.createElement("div"); acts.className = "actions";
      var feat = document.createElement("button");
      feat.className = "ghost small"; feat.textContent = m.is_featured ? "★ Featured" : "Feature";
      feat.onclick = function(){ api("/api/admin/media/" + m.id + "/feature", { method: "PATCH" }).then(loadMedia); };
      var del = document.createElement("button");
      del.className = "danger small"; del.textContent = "Delete";
      del.onclick = function(){
        if (!confirm("Delete this media permanently?")) return;
        api("/api/admin/media/" + m.id, { method: "DELETE" }).then(loadMedia).catch(function(e){ alert(e.message); });
      };
      acts.appendChild(feat); acts.appendChild(del); d.appendChild(acts);
      el.appendChild(d);
    });
  }).catch(function(e){ $("#mediaGrid").innerHTML = '<p style="color:var(--red)">' + esc(e.message) + '</p>'; });
}

$("#uploadMediaBtn").onclick = function(){
  var file = $("#mediaFile").files[0];
  if (!file) return msg("#mediaMsg", "Choose a file first.", "err");
  var fd = new FormData();
  fd.append("file", file);
  fd.append("caption", $("#mediaCaption").value.trim());
  $("#uploadMediaBtn").disabled = true;
  msg("#mediaMsg", "Uploading…");
  fetch("/api/admin/media", { method: "POST", body: fd, credentials: "same-origin" })
    .then(function(r){ return r.json().then(function(d){ if (!r.ok) throw new Error(d.error || "Upload failed"); return d; }); })
    .then(function(){
      $("#mediaFile").value = ""; $("#mediaCaption").value = "";
      msg("#mediaMsg", "Uploaded successfully.", "ok");
      loadMedia();
    })
    .catch(function(e){ msg("#mediaMsg", e.message, "err"); })
    .finally(function(){ $("#uploadMediaBtn").disabled = false; });
};

checkSession();
<\/script>
</body>
</html>`;

/* ============================================================================
   SERVE PAGES
   ============================================================================ */
app.get("/admin", (_req, res) => res.type("html").send(ADMIN_HTML));
app.get("*", (_req, res) => res.type("html").send(PUBLIC_HTML));

/* ============================================================================
   START
   ============================================================================ */
initDb().finally(() => {
  app.listen(PORT, () => console.log(`🚀 EDOM & YOHI running on :${PORT}`));
});