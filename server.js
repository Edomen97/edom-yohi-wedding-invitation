/* ============================================================================
   EDOM & YOHI — PREMIUM WEDDING WEBSITE
   Complete single-file Node.js application
   Stack: Express + PostgreSQL + Cloudinary + Resend
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

/* ============================================================================
   1. ENVIRONMENT VALIDATION — fail fast if critical vars are missing
   ============================================================================ */
const REQUIRED_ENV = ["DATABASE_URL", "JWT_SECRET", "ADMIN_PASSWORD_HASH"];
const missing = REQUIRED_ENV.filter(k => !process.env[k] || String(process.env[k]).trim() === "");
if (missing.length) {
  console.error("❌ Missing required environment variables:", missing.join(", "));
  process.exit(1);
}

/* Cloudinary: all three or none */
const CLD_KEYS = ["CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET"];
const cldSet = CLD_KEYS.filter(k => process.env[k] && process.env[k].trim());
const cloudinaryEnabled = cldSet.length === 3;
if (cldSet.length > 0 && cldSet.length < 3) {
  console.error("❌ Cloudinary: set all three CLOUDINARY_* variables or none of them.");
  process.exit(1);
}

/* Resend: requires all three for email to work */
const resendEnabled = !!(
  process.env.RESEND_API_KEY &&
  process.env.FROM_EMAIL &&
  process.env.ADMIN_EMAIL
);
if (process.env.RESEND_API_KEY && !resendEnabled) {
  console.warn("⚠️  Resend partially configured — RSVP email notifications disabled.");
}

/* ============================================================================
   2. DATABASE
   ============================================================================ */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },   // required for Render managed Postgres
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* Track readiness state explicitly so health checks tell the truth */
let dbReady = false;

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

CREATE TABLE IF NOT EXISTS settings (
  key VARCHAR(50) PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rsvps_created ON rsvps(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_featured ON media(is_featured, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_media_single_featured ON media(is_featured) WHERE is_featured = TRUE;
`;

const DEFAULT_SETTINGS = {
  wedding_date: "",
  wedding_time: "",
  wedding_tz_offset: "+03:00",
  venue_name: "",
  venue_address: "",
  venue_city: "",
  map_url: "",
  rsvp_deadline: "",
  story_how_met: "",
  story_journey: "",
  story_proposal: ""
};

const PUBLIC_SETTING_KEYS = Object.keys(DEFAULT_SETTINGS);

async function seedDefaultSettings(client) {
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    await client.query(
      "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
      [k, v]
    );
  }
}

async function initDb() {
  let attempt = 0;
  for (;;) {
    attempt++;
    try {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(SCHEMA);
        await seedDefaultSettings(client);
        await client.query("COMMIT");
      } catch (e) {
        try { await client.query("ROLLBACK"); } catch {}
        throw e;
      } finally {
        client.release();
      }
      dbReady = true;
      console.log("✅ Database ready (attempt " + attempt + ")");
      return;
    } catch (err) {
      const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(attempt, 5)));
      console.warn(`⚠️  DB attempt ${attempt} failed: ${err.message}. Retry in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
}

/* ============================================================================
   3. SERVICES
   ============================================================================ */
if (cloudinaryEnabled) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}

const resend = resendEnabled ? new Resend(process.env.RESEND_API_KEY) : null;

/* ============================================================================
   4. APP SETUP
   ============================================================================ */
const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/* Origin verification (defence-in-depth on top of SameSite=Strict) */
function verifyOrigin(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next();                 // non-browser: auth/rate-limit still applies
  try {
    const originHost = new URL(origin).host;
    if (originHost !== req.headers.host) {
      return res.status(403).json({ error: "Cross-origin request blocked" });
    }
  } catch {
    return res.status(403).json({ error: "Invalid origin" });
  }
  next();
}
app.use(verifyOrigin);

/* Rate limiting */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const rsvpLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const apiLimiter   = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api", apiLimiter);

/* ============================================================================
   5. HELPERS
   ============================================================================ */
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

/* Magic-byte detection prevents MIME spoofing */
function detectFileType(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return "image/jpeg";
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 &&
      buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A) return "image/png";
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return "image/gif";
  if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
      buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50) return "image/webp";
  if (buf[4] === 0x66 && buf[5] === 0x74 && buf[6] === 0x79 && buf[7] === 0x70) return "video/mp4";
  if (buf[0] === 0x1A && buf[1] === 0x45 && buf[2] === 0xDF && buf[3] === 0xA3) return "video/webm";
  return null;
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^\d{2}:\d{2}$/;
const TZ_RE   = /^[+-]\d{2}:\d{2}$/;

function vDate(s) {
  if (!s) return "";
  if (!DATE_RE.test(s)) throw new Error("Invalid date format (YYYY-MM-DD)");
  const d = new Date(s + "T00:00:00Z");
  if (isNaN(d.getTime())) throw new Error("Invalid date");
  return s;
}
function vTime(s) {
  if (!s) return "";
  if (!TIME_RE.test(s)) throw new Error("Invalid time format (HH:MM)");
  return s;
}
function vTz(s) {
  if (!s) return "+00:00";
  if (!TZ_RE.test(s)) throw new Error("Invalid timezone offset (e.g. +03:00)");
  return s;
}
function vUrl(s) {
  if (!s) return "";
  let u;
  try { u = new URL(s); } catch { throw new Error("Invalid URL"); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("URL must use http(s)");
  return s;
}

/* ============================================================================
   6. ADMIN AUTH
   ============================================================================ */
const ADMIN_COOKIE = "ey_admin";

function signAdminToken() {
  return jwt.sign({ role: "admin" }, process.env.JWT_SECRET, { expiresIn: "12h" });
}

function requireAdmin(req, res, next) {
  const token = req.cookies[ADMIN_COOKIE];
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  try {
    const p = jwt.verify(token, process.env.JWT_SECRET);
    if (p.role !== "admin") throw new Error("bad role");
    req.admin = true;
    next();
  } catch {
    res.status(401).json({ error: "Session expired" });
  }
}

/* ============================================================================
   7. MULTER
   ============================================================================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$|^video\/(mp4|webm|quicktime)$/.test(file.mimetype);
    cb(null, ok);
  }
});

/* ============================================================================
   8. HEALTH / READINESS
   ============================================================================ */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, uptime: process.uptime(), ts: Date.now() });
});

app.get("/api/ready", async (_req, res) => {
  if (!dbReady) return res.status(503).json({ ok: false, reason: "database not initialised" });
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: "reachable" });
  } catch (err) {
    res.status(503).json({ ok: false, reason: "database unreachable", detail: err.message });
  }
});

/* ============================================================================
   9. API — AUTH
   ============================================================================ */
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: "Password required" });

  const ok = await bcrypt.compare(String(password), process.env.ADMIN_PASSWORD_HASH);
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

/* ============================================================================
   10. API — SETTINGS
   ============================================================================ */
app.get("/api/settings", async (_req, res) => {
  if (!dbReady) return res.status(503).json({ error: "Service initialising" });
  const { rows } = await pool.query("SELECT key, value FROM settings");
  const out = {};
  for (const row of rows) {
    if (PUBLIC_SETTING_KEYS.includes(row.key)) out[row.key] = row.value;
  }
  res.json(out);
});

app.get("/api/admin/settings", requireAdmin, async (_req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings");
  const out = {};
  for (const row of rows) out[row.key] = row.value;
  res.json(out);
});

app.put("/api/admin/settings", requireAdmin, async (req, res) => {
  const body = req.body || {};
  let parsed;
  try {
    parsed = {
      wedding_date: vDate(body.wedding_date),
      wedding_time: vTime(body.wedding_time),
      wedding_tz_offset: vTz(body.wedding_tz_offset),
      venue_name: String(body.venue_name || "").slice(0, 200),
      venue_address: String(body.venue_address || "").slice(0, 500),
      venue_city: String(body.venue_city || "").slice(0, 100),
      map_url: vUrl(body.map_url),
      rsvp_deadline: vDate(body.rsvp_deadline),
      story_how_met: String(body.story_how_met || "").slice(0, 2000),
      story_journey: String(body.story_journey || "").slice(0, 2000),
      story_proposal: String(body.story_proposal || "").slice(0, 2000)
    };
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const [k, v] of Object.entries(parsed)) {
      await client.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [k, v]
      );
    }
    await client.query("COMMIT");
    res.json({ ok: true, settings: parsed });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Settings save error:", err);
    res.status(500).json({ error: "Could not save settings" });
  } finally {
    client.release();
  }
});

/* ============================================================================
   11. API — MEDIA
   ============================================================================ */
app.get("/api/media", async (_req, res) => {
  if (!dbReady) return res.status(503).json({ error: "Service initialising" });
  const { rows } = await pool.query(
    "SELECT id, type, url, caption, is_featured FROM media ORDER BY is_featured DESC, created_at DESC"
  );
  res.json(rows);
});

app.post("/api/admin/media", requireAdmin, upload.single("file"), async (req, res) => {
  if (!cloudinaryEnabled) {
    return res.status(503).json({ error: "Photo storage is not configured. Set CLOUDINARY_* variables." });
  }
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  if (!req.file.mimetype || !/^(image|video)\//.test(req.file.mimetype)) {
    return res.status(400).json({ error: "Only images or videos are accepted." });
  }

  const detected = detectFileType(req.file.buffer);
  if (!detected) {
    return res.status(400).json({ error: "Unrecognised file content — please use JPEG, PNG, WebP, GIF, MP4, or WebM." });
  }

  const mediaType = detected.startsWith("video/") ? "video" : "image";
  const caption = String(req.body?.caption || "").slice(0, 200);

  try {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: mediaType === "video" ? "video" : "image", folder: "edom-yohi-wedding" },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(req.file.buffer);
    });

    const { rows } = await pool.query(
      `INSERT INTO media (type, url, public_id, caption)
       VALUES ($1, $2, $3, $4)
       RETURNING id, type, url, caption, is_featured`,
      [mediaType, result.secure_url, result.public_id, caption]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Cloudinary upload error:", err.message);
    res.status(500).json({ error: "Upload failed. Please try again." });
  }
});

/* FIXED: never removes the existing featured media when a bad ID is sent */
app.patch("/api/admin/media/:id/feature", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { featured } = req.body || {};

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid media ID" });
  }
  if (typeof featured !== "boolean") {
    return res.status(400).json({ error: "Body must contain { featured: true | false }" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const check = await client.query("SELECT id FROM media WHERE id = $1", [id]);
    if (!check.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Media not found" });
    }

    if (featured) {
      await client.query("UPDATE media SET is_featured = FALSE WHERE is_featured = TRUE AND id != $1", [id]);
      await client.query("UPDATE media SET is_featured = TRUE WHERE id = $1", [id]);
    } else {
      await client.query("UPDATE media SET is_featured = FALSE WHERE id = $1", [id]);
    }

    await client.query("COMMIT");
    res.json({ ok: true, featured });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Feature toggle error:", err);
    res.status(500).json({ error: "Could not update featured status" });
  } finally {
    client.release();
  }
});

app.delete("/api/admin/media/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid media ID" });
  }

  const { rows } = await pool.query(
    "SELECT public_id, type FROM media WHERE id = $1",
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: "Media not found" });

  if (rows[0].public_id && cloudinaryEnabled) {
    try {
      await cloudinary.uploader.destroy(rows[0].public_id, {
        resource_type: rows[0].type === "video" ? "video" : "image"
      });
    } catch (e) {
      console.warn("Cloudinary destroy warning:", e.message);
    }
  }
  await pool.query("DELETE FROM media WHERE id = $1", [id]);
  res.json({ ok: true });
});

/* ============================================================================
   12. API — RSVP
   ============================================================================ */
app.post("/api/rsvp", rsvpLimiter, async (req, res) => {
  if (!dbReady) return res.status(503).json({ error: "Service initialising, please try again in a moment." });

  const { name, email, phone, attending, guests, message } = req.body || {};

  const cleanName    = String(name || "").trim().slice(0, 100);
  const cleanEmail   = String(email || "").trim().slice(0, 150);
  const cleanPhone   = String(phone || "").trim().slice(0, 30);
  const cleanMessage = String(message || "").trim().slice(0, 500);

  if (cleanName.length < 2) {
    return res.status(400).json({ error: "Please enter your full name." });
  }
  if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (typeof attending !== "boolean") {
    return res.status(400).json({ error: "Please tell us whether you will attend." });
  }

  const guestCount = Math.min(Math.max(parseInt(guests, 10) || 1, 1), 10);

  const { rows } = await pool.query(
    `INSERT INTO rsvps (name, email, phone, attending, guests, message)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, created_at`,
    [cleanName, cleanEmail || null, cleanPhone || null, attending, guestCount, cleanMessage || null]
  );

  if (resend) {
    resend.emails.send({
      from: process.env.FROM_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: `New RSVP from ${cleanName}`,
      html: `
        <div style="font-family:Georgia,serif;background:#0a0a0a;color:#EDE3D0;padding:32px;border-radius:12px;max-width:600px">
          <h2 style="color:#D4AF37;margin:0 0 16px">New RSVP for Edom &amp; Yohi</h2>
          <p><strong>Name:</strong> ${esc(cleanName)}</p>
          <p><strong>Email:</strong> ${cleanEmail ? esc(cleanEmail) : "—"}</p>
          <p><strong>Phone:</strong> ${cleanPhone ? esc(cleanPhone) : "—"}</p>
          <p><strong>Attending:</strong> ${attending ? "Yes" : "No"}</p>
          <p><strong>Guests:</strong> ${guestCount}</p>
          <p><strong>Received:</strong> ${new Date(rows[0].created_at).toUTCString()}</p>
          ${cleanMessage ? `<hr style="border-color:#333"><p style="white-space:pre-wrap">${esc(cleanMessage)}</p>` : ""}
        </div>`
    }).catch(err => console.warn("Resend email skipped:", err.message));
  }

  res.status(201).json({ ok: true });
});

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

/* ============================================================================
   13. API — GUEST LIST
   ============================================================================ */
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
    `INSERT INTO guests (name, email, phone, notes)
     VALUES ($1, $2, $3, $4)
     RETURNING id, name, email, phone, notes`,
    [
      cleanName,
      String(email || "").slice(0, 150) || null,
      String(phone || "").slice(0, 30) || null,
      String(notes || "").slice(0, 300) || null
    ]
  );
  res.status(201).json(rows[0]);
});

app.delete("/api/admin/guests/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM guests WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ============================================================================
   14. PUBLIC PAGE
   ============================================================================ */
const PUBLIC_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Edom &amp; Yohi — A Celebration of Forever</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Cormorant+Garamond:ital,wght@0,400;0,500;0,600;1,400&family=Montserrat:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{--black:#080808;--gold:#D4AF37;--gold2:#F3E3A8;--gold3:#B8912E;--text:#EDE3D0;--muted:#A89880;--line:rgba(212,175,55,.22);--champagne:#F7E7CE;--serif:"Cormorant Garamond",Georgia,serif;--script:"Great Vibes",cursive;--sans:"Montserrat",sans-serif}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth}
body{margin:0;background:var(--black);color:var(--text);font-family:var(--sans);font-weight:300;line-height:1.7;overflow-x:hidden;-webkit-font-smoothing:antialiased}
img{max-width:100%;display:block}
a{color:var(--gold);text-decoration:none}
.wrap{max-width:860px;margin:0 auto;padding:0 24px}
.sec{padding:96px 0;position:relative}
.sec+.sec{border-top:1px solid var(--line)}
.topbar{position:fixed;inset:0 0 auto 0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:16px 24px;padding-top:calc(16px + env(safe-area-inset-top,0px));background:linear-gradient(180deg,rgba(8,8,8,.94),transparent);backdrop-filter:blur(10px)}
.brand{font-family:var(--serif);font-size:20px;letter-spacing:5px;color:var(--gold)}
.hero{min-height:100vh;min-height:100svh;display:flex;align-items:center;justify-content:center;text-align:center;padding:140px 24px 90px;position:relative;overflow:hidden;background:radial-gradient(ellipse at 20% 10%,rgba(212,175,55,.10),transparent 55%),radial-gradient(ellipse at 80% 90%,rgba(212,175,55,.08),transparent 55%),var(--black)}
.hero-bg{position:absolute;inset:0;background-size:cover;background-position:center;opacity:0;transition:opacity 1.6s ease}
.hero-bg.on{opacity:.35}
.hero-bg::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(8,8,8,.6),rgba(8,8,8,.9))}
.rings{width:130px;height:130px;margin:0 auto 28px;filter:drop-shadow(0 0 22px rgba(212,175,55,.5));position:relative;z-index:1}
.rings svg{width:100%;height:100%;overflow:visible}
.rings .r{fill:none;stroke:url(#gg);stroke-width:2.2;stroke-linecap:round;stroke-dasharray:270;stroke-dashoffset:270;animation:draw 2.6s ease forwards}
.rings .r2{animation-delay:.6s}
@keyframes draw{to{stroke-dashoffset:0}}
.kicker{font-family:var(--serif);font-style:italic;font-size:16px;color:var(--gold);letter-spacing:.5px;margin:0 0 12px;position:relative;z-index:1}
.names{font-family:var(--script);font-size:clamp(60px,18vw,124px);line-height:.95;margin:0;color:var(--gold2);font-weight:400;letter-spacing:2px;position:relative;z-index:1}
.names .amp{font-family:var(--serif);font-style:italic;color:var(--gold);font-size:.55em;margin:0 8px;display:inline-block;transform:translateY(-.15em)}
.tagline{font-family:var(--serif);font-size:clamp(16px,4vw,21px);font-style:italic;color:var(--champagne);margin:24px auto 0;max-width:560px;line-height:1.6;position:relative;z-index:1}
.cta{display:inline-flex;align-items:center;gap:10px;margin-top:38px;padding:15px 34px;border:1px solid var(--gold);border-radius:999px;color:var(--gold);font-size:12px;letter-spacing:2.5px;text-transform:uppercase;transition:.3s;position:relative;z-index:1}
.cta:hover{background:var(--gold);color:#000}
.cd{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:540px;margin:44px auto 0;position:relative;z-index:1}
.cd div{border:1px solid var(--line);border-radius:14px;padding:18px 6px;background:rgba(255,255,255,.02)}
.cd b{display:block;font-family:var(--serif);font-size:clamp(28px,6.5vw,42px);font-weight:600;color:var(--gold2);line-height:1}
.cd span{display:block;font-size:9px;letter-spacing:2.5px;text-transform:uppercase;color:var(--muted);margin-top:8px}
@media(max-width:420px){.cd{grid-template-columns:repeat(2,1fr)}}
.sec-k{font-size:11px;letter-spacing:4px;text-transform:uppercase;color:var(--gold3);text-align:center;margin:0 0 8px;font-weight:500}
.sec-t{font-family:var(--script);font-size:clamp(40px,9vw,60px);color:var(--gold);text-align:center;margin:0 0 14px;font-weight:400;line-height:1.1}
.sec-s{font-family:var(--serif);font-size:18px;font-style:italic;text-align:center;color:var(--muted);margin:0 auto 42px;max-width:620px;line-height:1.7}
.prose{max-width:680px;margin:0 auto;border:1px solid var(--line);border-radius:20px;padding:44px 36px;background:linear-gradient(180deg,rgba(212,175,55,.05),rgba(212,175,55,.01));position:relative}
.prose::before{content:"❝";position:absolute;top:8px;left:24px;font-family:var(--serif);font-size:64px;color:var(--gold);opacity:.25;line-height:1}
.prose p{font-family:var(--serif);font-size:19px;line-height:1.9;margin:0 0 20px;color:var(--text);position:relative}
.prose .sig{font-family:var(--script);font-size:34px;color:var(--gold);margin-top:28px;text-align:right;line-height:1.2}
.prose.center{text-align:center}
.prose.center p{text-align:center}
.story{max-width:720px;margin:0 auto;display:grid;gap:24px}
.story-card{border:1px solid var(--line);border-radius:18px;padding:34px 32px;background:rgba(255,255,255,.02)}
.story-card .num{font-family:var(--script);font-size:48px;color:var(--gold);opacity:.7;line-height:1;margin-bottom:10px}
.story-card h3{font-family:var(--serif);font-size:26px;font-weight:500;color:var(--gold2);margin:0 0 14px;letter-spacing:.5px}
.story-card p{font-family:var(--serif);font-size:17px;line-height:1.85;color:var(--text);margin:0;white-space:pre-wrap}
.verse{max-width:680px;margin:0 auto 28px;text-align:center;padding:44px 32px;border:1px solid var(--line);border-radius:20px;background:radial-gradient(ellipse at top,rgba(212,175,55,.09),transparent 70%)}
.verse .ref{font-family:var(--sans);font-size:12px;letter-spacing:4px;text-transform:uppercase;color:var(--gold3);margin:0 0 18px;font-weight:500}
.verse blockquote{font-family:var(--serif);font-style:italic;font-size:clamp(18px,4.2vw,23px);line-height:1.85;color:var(--champagne);margin:0}
.details{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;max-width:720px;margin:0 auto}
@media(max-width:600px){.details{grid-template-columns:1fr}}
.detail-card{border:1px solid var(--line);border-radius:18px;padding:34px 26px;text-align:center;background:rgba(255,255,255,.02)}
.detail-card .icon{width:38px;height:38px;margin:0 auto 14px;color:var(--gold)}
.detail-card h3{font-family:var(--sans);font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--gold3);margin:0 0 12px;font-weight:500}
.detail-card .v{font-family:var(--serif);font-size:21px;color:var(--champagne);margin:0 0 6px;line-height:1.45;font-weight:500}
.detail-card .s{font-family:var(--serif);font-size:15px;font-style:italic;color:var(--muted);margin:6px 0 0;line-height:1.5}
.map-link{display:inline-flex;align-items:center;gap:6px;margin-top:16px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);border-bottom:1px solid var(--line);padding-bottom:3px}
.details-empty{text-align:center;font-family:var(--serif);font-style:italic;color:var(--muted);padding:48px 20px;border:1px dashed var(--line);border-radius:18px;max-width:620px;margin:0 auto}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;max-width:900px;margin:0 auto}
.gallery .item{border:1px solid var(--line);border-radius:16px;overflow:hidden;background:#101010}
.gallery .item img,.gallery .item video{width:100%;aspect-ratio:4/3;object-fit:cover;display:block;background:#000}
.gallery .item .cap{padding:12px 16px;font-family:var(--serif);font-size:15px;font-style:italic;color:var(--muted);text-align:center;line-height:1.5}
.gallery-empty{text-align:center;font-family:var(--serif);font-style:italic;color:var(--muted);padding:40px 20px;border:1px dashed var(--line);border-radius:16px;max-width:640px;margin:0 auto}
.rsvp-wrap{max-width:580px;margin:0 auto}
.rsvp-form{display:flex;flex-direction:column;gap:16px;padding:44px 34px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(180deg,rgba(212,175,55,.04),transparent)}
.rsvp-form label{display:block;font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:var(--gold3);margin-bottom:6px;font-weight:500}
.rsvp-form input,.rsvp-form textarea,.rsvp-form select{font-family:var(--serif);font-size:16px;color:var(--text);background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:12px;padding:14px 16px;width:100%;transition:.25s;font-weight:400}
.rsvp-form input:focus,.rsvp-form textarea:focus,.rsvp-form select:focus{outline:none;border-color:var(--gold);background:rgba(212,175,55,.05)}
.rsvp-form input::placeholder,.rsvp-form textarea::placeholder{color:var(--muted);font-style:italic}
.rsvp-form select option{background:#111;color:var(--text)}
.btn{font-family:var(--sans);font-size:12px;letter-spacing:2.5px;text-transform:uppercase;cursor:pointer;background:var(--gold);color:#000;border:1px solid var(--gold);border-radius:999px;padding:16px 32px;font-weight:600;transition:.3s}
.btn:hover{background:transparent;color:var(--gold)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.status{min-height:1.4em;text-align:center;font-family:var(--serif);font-size:15px;font-style:italic;margin:16px 0 0;color:var(--muted)}
.status.ok{color:#7dd3a0;font-style:normal}
.status.err{color:#e0796f;font-style:normal}
.foot{text-align:center;padding:80px 24px calc(60px + env(safe-area-inset-bottom,0px));border-top:1px solid var(--line);background:linear-gradient(180deg,transparent,rgba(212,175,55,.03))}
.foot .n{font-family:var(--script);font-size:52px;color:var(--gold);margin:0 0 12px;line-height:1}
.foot .n .amp{font-family:var(--serif);font-style:italic;font-size:.55em;color:var(--gold2);margin:0 6px}
.foot p{color:var(--muted);font-family:var(--serif);font-style:italic;font-size:15px;margin:8px 0 0}
.foot .sig{font-family:var(--script);font-size:28px;color:var(--gold);margin-top:24px}
.rv{opacity:0;transform:translateY(28px);transition:opacity 1s ease,transform 1s ease}
.rv.on{opacity:1;transform:none}
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
        <defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#F3E3A8"/><stop offset="50%" stop-color="#D4AF37"/><stop offset="100%" stop-color="#B8912E"/>
        </linearGradient></defs>
        <circle class="r" cx="46" cy="66" r="28"/>
        <circle class="r r2" cx="74" cy="66" r="28"/>
      </svg>
    </div>
    <p class="kicker">Together with our families</p>
    <h1 class="names">Edom<span class="amp">&amp;</span>Yohi</h1>
    <p class="tagline">A love written in quiet moments and grand dreams —<br>now bound forever in the promise of a lifetime.</p>
    <div class="cd" id="cdBox">
      <div><b id="d">00</b><span>Days</span></div>
      <div><b id="h">00</b><span>Hours</span></div>
      <div><b id="m">00</b><span>Minutes</span></div>
      <div><b id="s">00</b><span>Seconds</span></div>
    </div>
    <a class="cta" href="#rsvp">Reserve Your Seat</a>
  </div>
</section>

<section class="sec">
  <div class="wrap rv">
    <p class="sec-k">An Invitation of the Heart</p>
    <h2 class="sec-t">You Are Invited</h2>
    <p class="sec-s">To witness two hearts become one, and to celebrate a love that has found its home.</p>
    <div class="prose">
      <p>With hearts full of joy and hands held in gratitude, we invite you to share in the beginning of our forever. Your presence would mean more to us than we could ever put into words — for a celebration becomes truly beautiful only when it is shared with the people we love.</p>
      <p>Come stand with us as we promise our tomorrows to one another. Come laugh with us, pray with us, and lift a glass to the life we are about to build together.</p>
      <p class="sig">— Edom &amp; Yohi</p>
    </div>
  </div>
</section>

<section class="sec" id="storySection">
  <div class="wrap rv">
    <p class="sec-k">How It Began</p>
    <h2 class="sec-t">Our Love Story</h2>
    <p class="sec-s">Every love has a beginning. Ours is written in the small, sacred moments that turned two lives into one story.</p>
    <div class="story" id="storyCards">
      <div class="story-card" id="storyCard1">
        <div class="num">I</div>
        <h3>Where It All Began</h3>
        <p id="storyText1"></p>
      </div>
      <div class="story-card" id="storyCard2">
        <div class="num">II</div>
        <h3>The Journey Between</h3>
        <p id="storyText2"></p>
      </div>
      <div class="story-card" id="storyCard3">
        <div class="num">III</div>
        <h3>The Forever Yes</h3>
        <p id="storyText3"></p>
      </div>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap rv">
    <p class="sec-k">The Word That Guides Us</p>
    <h2 class="sec-t">Verses for Our Marriage</h2>
    <div class="verse">
      <p class="ref">1 Corinthians 13:4–7</p>
      <blockquote>“Love is patient, love is kind. It does not envy, it does not boast, it is not proud. It does not dishonor others, it is not self-seeking, it is not easily angered, it keeps no record of wrongs. Love does not delight in evil but rejoices with the truth. It always protects, always trusts, always hopes, always perseveres.”</blockquote>
    </div>
    <div class="verse">
      <p class="ref">Ecclesiastes 4:9</p>
      <blockquote>“Two are better than one, because they have a good return for their labor.”</blockquote>
    </div>
  </div>
</section>

<section class="sec" id="details">
  <div class="wrap rv">
    <p class="sec-k">The Celebration</p>
    <h2 class="sec-t">When &amp; Where</h2>
    <p class="sec-s">Save the date. We cannot wait to celebrate with you.</p>
    <div class="details" id="detailsGrid"></div>
  </div>
</section>

<section class="sec">
  <div class="wrap rv">
    <p class="sec-k">Cherished Moments</p>
    <h2 class="sec-t">Our Gallery</h2>
    <p class="sec-s">A collection of moments we hold closest to our hearts.</p>
    <div class="gallery" id="gallery">
      <div class="gallery-empty">Our photographs will appear here soon.</div>
    </div>
  </div>
</section>

<section class="sec" id="rsvp">
  <div class="wrap rv">
    <p class="sec-k">Your Response, Please</p>
    <h2 class="sec-t">RSVP</h2>
    <p class="sec-s" id="rsvpIntro">Kindly let us know if you will join us, so we may save a place in our celebration for you.</p>
    <div class="rsvp-wrap">
      <form class="rsvp-form" id="rsvpForm">
        <div><label for="rName">Full Name *</label><input type="text" id="rName" required maxlength="100" placeholder="How should we address you?"></div>
        <div><label for="rEmail">Email Address</label><input type="email" id="rEmail" maxlength="150" placeholder="you@example.com"></div>
        <div><label for="rPhone">Phone Number</label><input type="tel" id="rPhone" maxlength="30" placeholder="+251 ..."></div>
        <div><label for="rAttending">Will You Attend? *</label>
          <select id="rAttending" required>
            <option value="">Please select…</option>
            <option value="yes">Yes — I would not miss it</option>
            <option value="no">Sadly, I cannot attend</option>
          </select>
        </div>
        <div><label for="rGuests">Number of Guests (including you)</label><input type="number" id="rGuests" min="1" max="10" value="1"></div>
        <div><label for="rMsg">A Message for the Couple (optional)</label><textarea id="rMsg" maxlength="500" rows="4" placeholder="Share a wish, a memory, or a word of blessing…"></textarea></div>
        <button class="btn" type="submit" id="rsvpBtn">Send My RSVP</button>
      </form>
      <p class="status" id="rsvpStatus" role="status" aria-live="polite"></p>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap rv">
    <p class="sec-k">With All Our Hearts</p>
    <h2 class="sec-t">Thank You</h2>
    <div class="prose center">
      <p>To every friend, every family member, and every kind soul who has walked beside us — thank you. Thank you for the laughter you have shared, the prayers you have offered, and the love you have poured into our lives.</p>
      <p>Whether you are near or far, whether we see you often or only on the days that matter most — your presence in our lives has made us better, and your presence at our wedding will make the day truly complete.</p>
      <p>We cannot wait to celebrate with you.</p>
      <p class="sig">With love and gratitude,<br>Edom &amp; Yohi</p>
    </div>
  </div>
</section>

<footer class="foot">
  <p class="n">Edom<span class="amp">&amp;</span>Yohi</p>
  <p>Two hearts, one promise, one beautiful forever.</p>
  <p class="sig">— E &amp; Y</p>
</footer>

<script>
var $ = function(s){ return document.querySelector(s); };
var $$ = function(s){ return document.querySelectorAll(s); };

function fmtDate(s) {
  if (!s) return "";
  try {
    var d = new Date(s + "T00:00:00");
    if (isNaN(d.getTime())) return s;
    return d.toLocaleDateString("en-GB", { year: "numeric", month: "long", day: "numeric" });
  } catch { return s; }
}

function computeWeddingTimestamp(date, time, offset) {
  if (!date || !time) return null;
  try {
    var iso = date + "T" + time + ":00" + offset;
    var ts = new Date(iso).getTime();
    return isNaN(ts) ? null : ts;
  } catch { return null; }
}

function startCountdown(targetTs) {
  var box = $("#cdBox");
  if (!targetTs || targetTs <= Date.now()) {
    box.style.display = "none";
    return;
  }
  box.style.display = "";
  function tick() {
    var diff = targetTs - Date.now();
    if (diff < 0) diff = 0;
    var s = Math.floor(diff / 1000);
    $("#d").textContent = String(Math.floor(s / 86400)).padStart(2, "0");
    $("#h").textContent = String(Math.floor((s % 86400) / 3600)).padStart(2, "0");
    $("#m").textContent = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    $("#s").textContent = String(s % 60).padStart(2, "0");
  }
  tick();
  setInterval(tick, 1000);
}

function renderDetails(s) {
  var grid = $("#detailsGrid");
  var cards = [];

  if (s.wedding_date) {
    cards.push({
      icon: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>',
      h: "The Date",
      v: fmtDate(s.wedding_date),
      sub: s.wedding_time ? "Ceremony begins at " + s.wedding_time : ""
    });
  }

  if (s.venue_name) {
    var mapUrl = s.map_url || (s.venue_address
      ? "https://www.google.com/maps/search/?api=1&query=" + encodeURIComponent(s.venue_address)
      : "");
    cards.push({
      icon: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 21s-7-6.5-7-12a7 7 0 0 1 14 0c0 5.5-7 12-7 12z"/><circle cx="12" cy="9" r="2.5"/></svg>',
      h: "The Venue",
      v: s.venue_name,
      sub: s.venue_city || s.venue_address || "",
      link: mapUrl ? '<a class="map-link" href="' + mapUrl + '" target="_blank" rel="noopener">View on Map →</a>' : ""
    });
  }

  if (!cards.length) {
    grid.innerHTML = '<div class="details-empty">Wedding details will be announced soon.<br>Please check back or contact the couple.</div>';
    return;
  }

  grid.innerHTML = cards.map(function(c){
    return '<div class="detail-card">' + c.icon +
      '<h3>' + c.h + '</h3>' +
      '<p class="v">' + c.v + '</p>' +
      (c.sub ? '<p class="s">' + c.sub + '</p>' : "") +
      (c.link || "") +
      '</div>';
  }).join("");
}

function renderStory(s) {
  var filled = false;
  var parts = [
    { id: 1, text: s.story_how_met },
    { id: 2, text: s.story_journey },
    { id: 3, text: s.story_proposal }
  ];
  parts.forEach(function(p){
    var card = document.getElementById("storyCard" + p.id);
    var txt = document.getElementById("storyText" + p.id);
    if (p.text && p.text.trim()) {
      txt.textContent = p.text;
      card.style.display = "";
      filled = true;
    } else {
      card.style.display = "none";
    }
  });
  if (!filled) document.getElementById("storySection").style.display = "none";
}

function renderRsvpIntro(s) {
  var el = $("#rsvpIntro");
  if (s.rsvp_deadline) {
    el.innerHTML = 'Kindly let us know if you will join us, so we may save a place in our celebration for you. Please respond by <strong>' + fmtDate(s.rsvp_deadline) + '</strong>.';
  } else {
    el.textContent = "Kindly let us know if you will join us, so we may save a place in our celebration for you.";
  }
}

function loadSettings() {
  fetch("/api/settings").then(function(r){ return r.json(); }).then(function(s){
    var ts = computeWeddingTimestamp(s.wedding_date, s.wedding_time, s.wedding_tz_offset || "+00:00");
    startCountdown(ts);
    renderDetails(s);
    renderStory(s);
    renderRsvpIntro(s);
  }).catch(function(e){ console.warn("Settings unavailable", e); });
}

function loadMedia() {
  fetch("/api/media").then(function(r){ return r.json(); }).then(function(list){
    var featured = list.find(function(m){ return m.is_featured; });
    if (featured && featured.type === "image") {
      var bg = $("#heroBg");
      bg.style.backgroundImage = "url('" + featured.url + "')";
      bg.classList.add("on");
    }
    var gallery = $("#gallery");
    if (!list.length) {
      gallery.innerHTML = '<div class="gallery-empty">Our photographs will appear here soon.</div>';
      return;
    }
    gallery.innerHTML = "";
    list.forEach(function(m){
      var d = document.createElement("div");
      d.className = "item";
      if (m.type === "video") {
        var v = document.createElement("video");
        v.src = m.url; v.controls = true; v.preload = "metadata";
        d.appendChild(v);
      } else {
        var im = document.createElement("img");
        im.src = m.url;
        im.alt = m.caption || "Wedding photograph";
        im.loading = "lazy";
        d.appendChild(im);
      }
      if (m.caption) {
        var cap = document.createElement("div");
        cap.className = "cap";
        cap.textContent = m.caption;
        d.appendChild(cap);
      }
      gallery.appendChild(d);
    });
  }).catch(function(e){ console.warn("Media unavailable", e); });
}

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
  if (name.length < 2) { st.className = "status err"; st.textContent = "Please enter your full name."; return; }
  if (!attendingVal) { st.className = "status err"; st.textContent = "Please let us know if you will attend."; return; }

  btn.disabled = true;
  st.textContent = "Sending your response…";

  fetch("/api/rsvp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: name, email: email, phone: phone,
      attending: attendingVal === "yes",
      guests: guests, message: message
    })
  }).then(function(r){ return r.json().then(function(d){ return { ok: r.ok, data: d }; }); })
    .then(function(res){
      if (!res.ok) throw new Error(res.data.error || "Could not send.");
      st.className = "status ok";
      st.textContent = attendingVal === "yes"
        ? "Thank you — your seat is saved, and our hearts are fuller for it."
        : "Thank you for letting us know. You will be missed.";
      $("#rsvpForm").reset();
    })
    .catch(function(err){
      st.className = "status err";
      st.textContent = err.message || "Something went wrong. Please try again.";
    })
    .finally(function(){ btn.disabled = false; });
});

var io = new IntersectionObserver(function(entries){
  entries.forEach(function(e){ if (e.isIntersecting) { e.target.classList.add("on"); io.unobserve(e.target); } });
}, { threshold: 0.12 });
$$(".rv").forEach(function(el){ io.observe(el); });

loadSettings();
loadMedia();
</script>
</body>
</html>`;

/* ============================================================================
   15. ADMIN PAGE
   ============================================================================ */
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Edom &amp; Yohi</title>
<style>
:root{--black:#080808;--gold:#D4AF37;--gold2:#F3E3A8;--gold3:#B8912E;--line:rgba(212,175,55,.25);--text:#EDE3D0;--muted:#A89880;--red:#e0796f;--green:#7dd3a0}
*{box-sizing:border-box}
body{margin:0;background:var(--black);color:var(--text);font-family:Montserrat,system-ui,sans-serif;font-weight:300;min-height:100vh;padding:24px 16px;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto}
h1{font-family:Georgia,serif;color:var(--gold);font-weight:400;text-align:center;margin:0 0 6px}
.sub{text-align:center;color:var(--muted);font-size:13px;margin:0 0 24px}
.card{border:1px solid var(--line);border-radius:14px;padding:24px;background:rgba(255,255,255,.02);margin-bottom:18px}
input,button,textarea,select{font:inherit;font-size:14px}
input[type=password],input[type=file],input[type=text],input[type=email],input[type=tel],input[type=url],input[type=date],input[type=time],textarea,select{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#111;color:var(--text);margin-bottom:10px}
button{cursor:pointer;border-radius:999px;padding:10px 20px;border:1px solid var(--gold);background:var(--gold);color:#000;font-weight:600;transition:.25s}
button:hover{background:transparent;color:var(--gold)}
button:disabled{opacity:.5;cursor:not-allowed}
button.ghost{background:transparent;color:var(--gold)}
button.danger{border-color:var(--red);background:transparent;color:var(--red)}
button.danger:hover{background:var(--red);color:#000}
button.small{padding:6px 12px;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.tabs{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
.tabs button{flex:1;min-width:100px}
.tabs button.active{background:var(--gold);color:#000}
.hidden{display:none!important}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--gold3);font-weight:500;text-transform:uppercase;letter-spacing:1px;font-size:11px}
.msg{font-size:13px;margin:10px 0 0;min-height:1em}
.msg.err{color:var(--red)}.msg.ok{color:var(--green)}
.media-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:14px}
.media-item{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#111}
.media-item.featured{border-color:var(--gold);box-shadow:0 0 12px rgba(212,175,55,.35)}
.media-item img,.media-item video{width:100%;aspect-ratio:1;object-fit:cover;display:block}
.media-item .actions{padding:6px;display:flex;gap:4px;flex-wrap:wrap}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}}
.field-label{display:block;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--gold3);margin-bottom:4px;font-weight:500}
</style>
</head>
<body>
<div class="wrap">
  <h1>Edom &amp; Yohi — Admin</h1>
  <p class="sub">A private place for the two of you</p>

  <div id="loginView" class="card">
    <input id="pwd" type="password" placeholder="Admin password" autocomplete="current-password">
    <div class="row">
      <button id="loginBtn">Sign In</button>
      <button id="logoutBtn" class="ghost hidden">Sign Out</button>
    </div>
    <p id="loginMsg" class="msg"></p>
  </div>

  <div id="dashView" class="hidden">
    <div class="tabs">
      <button id="tabRsvp" class="active">RSVPs</button>
      <button id="tabGuests" class="ghost">Guest List</button>
      <button id="tabMedia" class="ghost">Gallery</button>
      <button id="tabSettings" class="ghost">Settings</button>
    </div>

    <div id="rsvpPane" class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2 style="margin:0;color:var(--gold);font-weight:400;font-size:18px">Guest Responses</h2>
        <button class="ghost small" id="refreshRsvp">Refresh</button>
      </div>
      <div id="rsvpList"></div>
    </div>

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

    <div id="mediaPane" class="card hidden">
      <h2 style="margin:0 0 10px;color:var(--gold);font-weight:400;font-size:18px">Upload Photograph or Video</h2>
      <input type="file" id="mediaFile" accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm">
      <input type="text" id="mediaCaption" placeholder="Caption (optional)" maxlength="200">
      <button id="uploadMediaBtn">Upload</button>
      <p id="mediaMsg" class="msg"></p>
      <div id="mediaGrid" class="media-grid"></div>
    </div>

    <div id="settingsPane" class="card hidden">
      <h2 style="margin:0 0 14px;color:var(--gold);font-weight:400;font-size:18px">Wedding Details</h2>
      <p style="color:var(--muted);font-size:13px;margin:0 0 18px">Leave any field empty to hide it from the public page. Nothing is invented — the site only shows what you fill in here.</p>

      <div class="form-grid">
        <div>
          <label class="field-label" for="sDate">Wedding Date</label>
          <input type="date" id="sDate">
        </div>
        <div>
          <label class="field-label" for="sTime">Wedding Time</label>
          <input type="time" id="sTime">
        </div>
        <div>
          <label class="field-label" for="sTz">Timezone Offset (e.g. +03:00)</label>
          <input type="text" id="sTz" placeholder="+03:00" pattern="[+-]\\d{2}:\\d{2}">
        </div>
        <div>
          <label class="field-label" for="sRsvp">RSVP Deadline</label>
          <input type="date" id="sRsvp">
        </div>
        <div>
          <label class="field-label" for="sVenue">Venue Name</label>
          <input type="text" id="sVenue" maxlength="200">
        </div>
        <div>
          <label class="field-label" for="sCity">Venue City</label>
          <input type="text" id="sCity" maxlength="100">
        </div>
        <div style="grid-column:1 / -1">
          <label class="field-label" for="sAddress">Venue Address (used for map search)</label>
          <input type="text" id="sAddress" maxlength="500">
        </div>
        <div style="grid-column:1 / -1">
          <label class="field-label" for="sMap">Custom Map URL (optional)</label>
          <input type="url" id="sMap" placeholder="https://maps.google.com/..." maxlength="500">
        </div>
      </div>

      <h2 style="margin:20px 0 14px;color:var(--gold);font-weight:400;font-size:18px">Our Story</h2>
      <label class="field-label" for="sStory1">Part I — Where It All Began</label>
      <textarea id="sStory1" rows="4" maxlength="2000"></textarea>
      <label class="field-label" for="sStory2">Part II — The Journey Between</label>
      <textarea id="sStory2" rows="4" maxlength="2000"></textarea>
      <label class="field-label" for="sStory3">Part III — The Forever Yes</label>
      <textarea id="sStory3" rows="4" maxlength="2000"></textarea>

      <div class="row" style="margin-top:16px">
        <button id="saveSettingsBtn">Save Settings</button>
      </div>
      <p id="settingsMsg" class="msg"></p>
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
  loadRsvps();
  loadGuests();
  loadMedia();
  loadSettings();
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

function setTab(name){
  ["rsvp","guests","media","settings"].forEach(function(n){
    var btn = $("#tab" + n.charAt(0).toUpperCase() + n.slice(1));
    var pane = $("#" + n + "Pane");
    if (!btn || !pane) return;
    if (n === name) { btn.classList.add("active"); btn.classList.remove("ghost"); pane.classList.remove("hidden"); }
    else { btn.classList.remove("active"); btn.classList.add("ghost"); pane.classList.add("hidden"); }
  });
}
$("#tabRsvp").onclick = function(){ setTab("rsvp"); };
$("#tabGuests").onclick = function(){ setTab("guests"); };
$("#tabMedia").onclick = function(){ setTab("media"); };
$("#tabSettings").onclick = function(){ setTab("settings"); };

/* ----- RSVPs ----- */
function loadRsvps(){
  api("/api/admin/rsvps").then(function(list){
    var el = $("#rsvpList");
    if (!list.length) { el.innerHTML = '<p style="color:var(--muted)">No responses yet.</p>'; return; }
    var html = '<table><thead><tr><th>Name</th><th>Email</th><th>Attending</th><th>Guests</th><th>Date</th><th></th></tr></thead><tbody>';
    list.forEach(function(r){
      html += '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.email || "—") + '</td><td>' + (r.attending ? "Yes" : "No") + '</td><td>' + r.guests + '</td><td>' + new Date(r.created_at).toLocaleDateString() + '</td><td><button class="danger small" data-del-rsvp="' + r.id + '">Delete</button></td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
    el.querySelectorAll("[data-del-rsvp]").forEach(function(b){
      b.onclick = function(){
        if (!confirm("Delete this response?")) return;
        api("/api/admin/rsvps/" + b.getAttribute("data-del-rsvp"), { method: "DELETE" }).then(loadRsvps).catch(function(e){ alert(e.message); });
      };
    });
  }).catch(function(e){ $("#rsvpList").innerHTML = '<p style="color:var(--red)">' + esc(e.message) + '</p>'; });
}
$("#refreshRsvp").onclick = loadRsvps;

/* ----- Guests ----- */
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

/* ----- Media ----- */
function loadMedia(){
  api("/api/media").then(function(list){
    var el = $("#mediaGrid");
    el.innerHTML = "";
    if (!list.length) { el.innerHTML = '<p style="color:var(--muted)">No media yet.</p>'; return; }
    list.forEach(function(m){
      var d = document.createElement("div");
      d.className = "media-item" + (m.is_featured ? " featured" : "");
      if (m.type === "video") {
        var v = document.createElement("video"); v.src = m.url; v.preload = "metadata"; d.appendChild(v);
      } else {
        var im = document.createElement("img"); im.src = m.url; im.alt = ""; d.appendChild(im);
      }
      var acts = document.createElement("div"); acts.className = "actions";
      var feat = document.createElement("button");
      feat.className = m.is_featured ? "small" : "ghost small";
      feat.textContent = m.is_featured ? "★ Featured" : "Feature";
      feat.onclick = function(){
        api("/api/admin/media/" + m.id + "/feature", {
          method: "PATCH",
          body: JSON.stringify({ featured: !m.is_featured })
        }).then(loadMedia).catch(function(e){ alert(e.message); });
      };
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

/* ----- Settings ----- */
function loadSettings(){
  api("/api/admin/settings").then(function(s){
    $("#sDate").value = s.wedding_date || "";
    $("#sTime").value = s.wedding_time || "";
    $("#sTz").value = s.wedding_tz_offset || "+03:00";
    $("#sRsvp").value = s.rsvp_deadline || "";
    $("#sVenue").value = s.venue_name || "";
    $("#sCity").value = s.venue_city || "";
    $("#sAddress").value = s.venue_address || "";
    $("#sMap").value = s.map_url || "";
    $("#sStory1").value = s.story_how_met || "";
    $("#sStory2").value = s.story_journey || "";
    $("#sStory3").value = s.story_proposal || "";
  }).catch(function(e){ msg("#settingsMsg", e.message, "err"); });
}

$("#saveSettingsBtn").onclick = function(){
  msg("#settingsMsg", "");
  var payload = {
    wedding_date: $("#sDate").value,
    wedding_time: $("#sTime").value,
    wedding_tz_offset: $("#sTz").value || "+03:00",
    rsvp_deadline: $("#sRsvp").value,
    venue_name: $("#sVenue").value,
    venue_city: $("#sCity").value,
    venue_address: $("#sAddress").value,
    map_url: $("#sMap").value,
    story_how_met: $("#sStory1").value,
    story_journey: $("#sStory2").value,
    story_proposal: $("#sStory3").value
  };
  $("#saveSettingsBtn").disabled = true;
  msg("#settingsMsg", "Saving…");
  api("/api/admin/settings", { method: "PUT", body: JSON.stringify(payload) })
    .then(function(){ msg("#settingsMsg", "Settings saved.", "ok"); })
    .catch(function(e){ msg("#settingsMsg", e.message, "err"); })
    .finally(function(){ $("#saveSettingsBtn").disabled = false; });
};

checkSession();
</script>
</body>
</html>`;

/* ============================================================================
   16. SERVE PAGES + 404 + ERROR HANDLER
   ============================================================================ */

/* API 404 (must run before SPA fallback) */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

/* Admin page (and any /admin sub-path) */
app.get(/^\/admin(\/.*)?$/, (_req, res) => res.type("html").send(ADMIN_HTML));

/* Public SPA fallback */
app.get("*", (_req, res) => res.type("html").send(PUBLIC_HTML));

/* Global error handler */
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  if (res.headersSent) return;
  res.status(500).json({ error: "Internal server error" });
});

/* ============================================================================
   17. START + GRACEFUL SHUTDOWN
   ============================================================================ */
let server;
let shuttingDown = false;

async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal} — shutting down...`);
  const t = setTimeout(() => {
    console.error("Forced exit after 15s timeout");
    process.exit(1);
  }, 15000);
  try {
    if (server) await new Promise(resolve => server.close(resolve));
    await pool.end();
    clearTimeout(t);
    console.log("Shutdown complete.");
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err.message);
    process.exit(1);
  }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => gracefulShutdown("SIGINT"));

server = app.listen(PORT, () => {
  console.log(`🚀 Server listening on :${PORT}`);
  console.log(`   Cloudinary: ${cloudinaryEnabled ? "enabled" : "disabled"}`);
  console.log(`   Resend:     ${resendEnabled ? "enabled" : "disabled"}`);
  initDb();
});