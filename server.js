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
    : { rejectUnauthorized: false },
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

/* ---------- MULTER ---------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$|^video\/(mp4|webm|quicktime)$/.test(file.mimetype);
    cb(ok ? null : new Error("Only images or videos allowed"), ok);
  }
});

/* ============================================================================
   API ROUTES
   ============================================================================ */

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

/* ---------- MEDIA ---------- */
app.get("/api/media", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, type, url, caption, is_featured FROM media ORDER BY is_featured DESC, created_at DESC"
  );
  res.json(rows);
});

app.post("/api/admin/media", requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const { caption } = req.body || {};
  const type = req.file.mimetype.startsWith("video") ? "video" : "image";

  try {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: type === "video" ? "video" : "image", folder: "edom-yohi-wedding" },
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

/* ---------- RSVP ---------- */
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
    return res.status(400).json({ error: "Please let us know if you will attend." });

  const guestCount = Math.min(Math.max(parseInt(guests, 10) || 1, 1), 10);

  const { rows } = await pool.query(
    `INSERT INTO rsvps (name, email, phone, attending, guests, message)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at`,
    [cleanName, cleanEmail || null, cleanPhone || null, attending, guestCount, cleanMsg || null]
  );

  if (resend && process.env.ADMIN_EMAIL && process.env.FROM_EMAIL) {
    resend.emails.send({
      from: process.env.FROM_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: `New RSVP from ${cleanName}`,
      html: `
        <div style="font-family:Georgia,serif;background:#0a0a0a;color:#EDE3D0;padding:32px;border-radius:12px">
          <h2 style="color:#D4AF37">A new RSVP has arrived</h2>
          <p><strong>Name:</strong> ${esc(cleanName)}</p>
          <p><strong>Email:</strong> ${cleanEmail ? esc(cleanEmail) : "—"}</p>
          <p><strong>Phone:</strong> ${cleanPhone ? esc(cleanPhone) : "—"}</p>
          <p><strong>Attending:</strong> ${attending ? "Yes" : "No"}</p>
          <p><strong>Guests:</strong> ${guestCount}</p>
          <p><strong>Received:</strong> ${new Date(rows[0].created_at).toUTCString()}</p>
          ${cleanMsg ? `<hr style="border-color:#333"><p style="white-space:pre-wrap">${esc(cleanMsg)}</p>` : ""}
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

/* ---------- GUEST LIST ---------- */
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
   PUBLIC FRONTEND
   ============================================================================ */
const PUBLIC_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Edom &amp; Yohi — A Celebration of Forever</title>
<meta name="description" content="With joyful hearts, Edom and Yohi invite you to share in the beginning of their forever.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Cormorant+Garamond:ital,wght@0,400;0,500;0,600;1,400;1,500&family=Montserrat:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --black:#080808;
  --gold:#D4AF37;
  --gold2:#F3E3A8;
  --gold3:#B8912E;
  --text:#EDE3D0;
  --muted:#A89880;
  --line:rgba(212,175,55,.22);
  --serif:"Cormorant Garamond",Georgia,serif;
  --script:"Great Vibes",cursive;
  --sans:"Montserrat",sans-serif;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth}
body{margin:0;background:var(--black);color:var(--text);font-family:var(--sans);font-weight:300;line-height:1.7;overflow-x:hidden;-webkit-font-smoothing:antialiased}
img{max-width:100%;display:block}
a{color:var(--gold);text-decoration:none}

.wrap{max-width:860px;margin:0 auto;padding:0 24px}
.sec{padding:96px 0;position:relative}
.sec+.sec{border-top:1px solid var(--line)}

/* Top bar */
.topbar{position:fixed;inset:0 0 auto 0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:16px 24px;padding-top:calc(16px + env(safe-area-inset-top,0px));background:linear-gradient(180deg,rgba(8,8,8,.94),transparent);backdrop-filter:blur(10px)}
.brand{font-family:var(--serif);font-size:20px;letter-spacing:5px;color:var(--gold)}

/* Hero */
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
.tagline{font-family:var(--serif);font-size:clamp(16px,4vw,21px);font-style:italic;color:var(--champagne,#F7E7CE);margin:24px auto 0;max-width:560px;line-height:1.6;position:relative;z-index:1}
.cta{display:inline-flex;align-items:center;gap:10px;margin-top:38px;padding:15px 34px;border:1px solid var(--gold);border-radius:999px;color:var(--gold);font-size:12px;letter-spacing:2.5px;text-transform:uppercase;transition:.3s;position:relative;z-index:1}
.cta:hover{background:var(--gold);color:#000}

/* Countdown */
.cd{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:540px;margin:44px auto 0;position:relative;z-index:1}
.cd div{border:1px solid var(--line);border-radius:14px;padding:18px 6px;background:rgba(255,255,255,.02)}
.cd b{display:block;font-family:var(--serif);font-size:clamp(28px,6.5vw,42px);font-weight:600;color:var(--gold2);line-height:1}
.cd span{display:block;font-size:9px;letter-spacing:2.5px;text-transform:uppercase;color:var(--muted);margin-top:8px}
@media(max-width:420px){.cd{grid-template-columns:repeat(2,1fr)}}

/* Section headings */
.sec-k{font-size:11px;letter-spacing:4px;text-transform:uppercase;color:var(--gold3);text-align:center;margin:0 0 8px;font-weight:500}
.sec-t{font-family:var(--script);font-size:clamp(40px,9vw,60px);color:var(--gold);text-align:center;margin:0 0 14px;font-weight:400;line-height:1.1}
.sec-s{font-family:var(--serif);font-size:18px;font-style:italic;text-align:center;color:var(--muted);margin:0 auto 42px;max-width:620px;line-height:1.7}

/* Prose card */
.prose{max-width:680px;margin:0 auto;border:1px solid var(--line);border-radius:20px;padding:44px 36px;background:linear-gradient(180deg,rgba(212,175,55,.05),rgba(212,175,55,.01));position:relative}
.prose::before{content:"❝";position:absolute;top:8px;left:24px;font-family:var(--serif);font-size:64px;color:var(--gold);opacity:.25;line-height:1}
.prose p{font-family:var(--serif);font-size:19px;line-height:1.9;margin:0 0 20px;color:var(--text);position:relative}
.prose p:last-of-type{margin-bottom:0}
.prose .sig{font-family:var(--script);font-size:34px;color:var(--gold);margin-top:28px;text-align:right;line-height:1.2}
.prose.center{text-align:center}
.prose.center p{text-align:center}

/* Story cards */
.story{max-width:720px;margin:0 auto;display:grid;gap:24px}
.story-card{border:1px solid var(--line);border-radius:18px;padding:34px 32px;background:rgba(255,255,255,.02);position:relative}
.story-card .num{font-family:var(--script);font-size:48px;color:var(--gold);opacity:.7;line-height:1;margin-bottom:10px}
.story-card h3{font-family:var(--serif);font-size:26px;font-weight:500;color:var(--gold2);margin:0 0 14px;letter-spacing:.5px}
.story-card p{font-family:var(--serif);font-size:17px;line-height:1.85;color:var(--text);margin:0 0 12px}
.story-card p:last-child{margin-bottom:0}
.placeholder{display:inline-block;background:rgba(212,175,55,.12);border:1px dashed var(--gold3);color:var(--gold2);padding:2px 10px;border-radius:6px;font-family:var(--sans);font-size:13px;font-style:normal;letter-spacing:.3px}

/* Verses */
.verse{max-width:680px;margin:0 auto 28px;text-align:center;padding:44px 32px;border:1px solid var(--line);border-radius:20px;background:radial-gradient(ellipse at top,rgba(212,175,55,.09),transparent 70%)}
.verse .ref{font-family:var(--sans);font-size:12px;letter-spacing:4px;text-transform:uppercase;color:var(--gold3);margin:0 0 18px;font-weight:500}
.verse blockquote{font-family:var(--serif);font-style:italic;font-size:clamp(18px,4.2vw,23px);line-height:1.85;color:#F7E7CE;margin:0}

/* Details grid */
.details{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;max-width:720px;margin:0 auto}
@media(max-width:600px){.details{grid-template-columns:1fr}}
.detail-card{border:1px solid var(--line);border-radius:18px;padding:34px 26px;text-align:center;background:rgba(255,255,255,.02);transition:.3s}
.detail-card:hover{border-color:var(--gold3);transform:translateY(-2px)}
.detail-card .icon{width:38px;height:38px;margin:0 auto 14px;color:var(--gold)}
.detail-card h3{font-family:var(--sans);font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--gold3);margin:0 0 12px;font-weight:500}
.detail-card .v{font-family:var(--serif);font-size:21px;color:#F7E7CE;margin:0 0 6px;line-height:1.45;font-weight:500}
.detail-card .s{font-family:var(--serif);font-size:15px;font-style:italic;color:var(--muted);margin:6px 0 0;line-height:1.5}
.map-link{display:inline-flex;align-items:center;gap:6px;margin-top:16px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);border-bottom:1px solid var(--line);padding-bottom:3px;transition:.2s}
.map-link:hover{border-color:var(--gold)}

/* Gallery */
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;max-width:900px;margin:0 auto}
.gallery .item{border:1px solid var(--line);border-radius:16px;overflow:hidden;background:#101010;transition:.3s}
.gallery .item:hover{border-color:var(--gold3);transform:translateY(-3px)}
.gallery .item img,.gallery .item video{width:100%;aspect-ratio:4/3;object-fit:cover;display:block;background:#000}
.gallery .item .cap{padding:12px 16px;font-family:var(--serif);font-size:15px;font-style:italic;color:var(--muted);text-align:center;line-height:1.5}
.gallery-empty{text-align:center;font-family:var(--serif);font-style:italic;color:var(--muted);padding:40px 20px;border:1px dashed var(--line);border-radius:16px;max-width:640px;margin:0 auto}

/* RSVP form */
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

/* Footer */
.foot{text-align:center;padding:80px 24px calc(60px + env(safe-area-inset-bottom,0px));border-top:1px solid var(--line);background:linear-gradient(180deg,transparent,rgba(212,175,55,.03))}
.foot .n{font-family:var(--script);font-size:52px;color:var(--gold);margin:0 0 12px;line-height:1}
.foot .n .amp{font-family:var(--serif);font-style:italic;font-size:.55em;color:var(--gold2);margin:0 6px}
.foot p{color:var(--muted);font-family:var(--serif);font-style:italic;font-size:15px;margin:8px 0 0;letter-spacing:.3px}
.foot .sig{font-family:var(--script);font-size:28px;color:var(--gold);margin-top:24px}

/* Reveal */
.rv{opacity:0;transform:translateY(28px);transition:opacity 1s ease,transform 1s ease}
.rv.on{opacity:1;transform:none}
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">E &amp; Y</div>
</header>

<!-- HERO -->
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
    <div class="cd">
      <div><b id="d">00</b><span>Days</span></div>
      <div><b id="h">00</b><span>Hours</span></div>
      <div><b id="m">00</b><span>Minutes</span></div>
      <div><b id="s">00</b><span>Seconds</span></div>
    </div>
    <a class="cta" href="#rsvp">Reserve Your Seat</a>
  </div>
</section>

<!-- WELCOME / INVITATION -->
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

<!-- OUR STORY -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k">How It Began</p>
    <h2 class="sec-t">Our Love Story</h2>
    <p class="sec-s">Every love has a beginning. Ours is written in the small, sacred moments that turned two lives into one story.</p>
    <div class="story">
      <div class="story-card">
        <div class="num">I</div>
        <h3>Where It All Began</h3>
        <p>Some stories begin with a spark. Ours began with something quieter — a conversation, a glance, a moment when the world seemed to slow just enough for two hearts to notice each other. <span class="placeholder">[EDIT: Describe briefly how you met — the place, the season, the feeling]</span></p>
        <p>What started as a simple hello grew, day by day, into something neither of us could have planned and neither of us would trade for anything.</p>
      </div>
      <div class="story-card">
        <div class="num">II</div>
        <h3>The Journey Between</h3>
        <p>In the seasons that followed, we learned each other the way you learn a favourite song — slowly, tenderly, until every note felt like home. We discovered that love is not only the grand gestures, but the quiet ones: the shared silence, the unexpected kindness, the hand reached for in a crowded room.</p>
        <p>We grew together — through laughter and through learning, through ordinary days and the ones we will never forget. <span class="placeholder">[EDIT: Add a short personal memory — a trip, a meaningful moment, a challenge you faced together]</span></p>
      </div>
      <div class="story-card">
        <div class="num">III</div>
        <h3>The Forever Yes</h3>
        <p>And then came the moment when a question was asked, and an answer was given — and everything changed, and nothing did. The love we had built was now a promise. The journey we had walked was now a road we would continue, side by side, for all the years ahead.</p>
        <p><span class="placeholder">[EDIT: Share a few lines about the proposal — where it happened, how it felt, what was said]</span></p>
      </div>
    </div>
  </div>
</section>

<!-- BIBLE VERSES -->
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

<!-- WHEN & WHERE -->
<section class="sec" id="details">
  <div class="wrap rv">
    <p class="sec-k">The Celebration</p>
    <h2 class="sec-t">When &amp; Where</h2>
    <p class="sec-s">Save the date. We cannot wait to celebrate with you.</p>
    <div class="details">
      <div class="detail-card">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>
        <h3>The Date</h3>
        <p class="v"><span class="placeholder">[EDIT: Wedding Date]</span></p>
        <p class="s"><span class="placeholder">[EDIT: Day of the week]</span></p>
      </div>
      <div class="detail-card">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        <h3>The Time</h3>
        <p class="v"><span class="placeholder">[EDIT: Ceremony Time]</span></p>
        <p class="s">Doors open thirty minutes before</p>
      </div>
      <div class="detail-card">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 21s-7-6.5-7-12a7 7 0 0 1 14 0c0 5.5-7 12-7 12z"/><circle cx="12" cy="9" r="2.5"/></svg>
        <h3>The Ceremony</h3>
        <p class="v"><span class="placeholder">[EDIT: Full Venue Name]</span></p>
        <p class="s"><span class="placeholder">[EDIT: City and Country]</span></p>
        <a class="map-link" href="#" id="mapLink" target="_blank" rel="noopener">View on Map →</a>
      </div>
      <div class="detail-card">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18M3 12h18M3 18h18"/></svg>
        <h3>Dress Code</h3>
        <p class="v">Elegant &amp; Formal</p>
        <p class="s">In tones of gold, ivory, and night</p>
      </div>
    </div>
  </div>
</section>

<!-- GALLERY -->
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

<!-- RSVP -->
<section class="sec" id="rsvp">
  <div class="wrap rv">
    <p class="sec-k">Your Response, Please</p>
    <h2 class="sec-t">RSVP</h2>
    <p class="sec-s">Kindly let us know if you will join us, so we may save a place in our celebration for you. Please respond by <span class="placeholder">[EDIT: RSVP Deadline]</span>.</p>
    <div class="rsvp-wrap">
      <form class="rsvp-form" id="rsvpForm">
        <div>
          <label for="rName">Full Name *</label>
          <input type="text" id="rName" required maxlength="100" placeholder="How should we address you?">
        </div>
        <div>
          <label for="rEmail">Email Address</label>
          <input type="email" id="rEmail" maxlength="150" placeholder="you@example.com">
        </div>
        <div>
          <label for="rPhone">Phone Number</label>
          <input type="tel" id="rPhone" maxlength="30" placeholder="+251 ...">
        </div>
        <div>
          <label for="rAttending">Will You Attend? *</label>
          <select id="rAttending" required>
            <option value="">Please select…</option>
            <option value="yes">Yes — I would not miss it</option>
            <option value="no">Sadly, I cannot attend</option>
          </select>
        </div>
        <div>
          <label for="rGuests">Number of Guests (including you)</label>
          <input type="number" id="rGuests" min="1" max="10" value="1">
        </div>
        <div>
          <label for="rMsg">A Message for the Couple (optional)</label>
          <textarea id="rMsg" maxlength="500" rows="4" placeholder="Share a wish, a memory, or a word of blessing…"></textarea>
        </div>
        <button class="btn" type="submit" id="rsvpBtn">Send My RSVP</button>
      </form>
      <p class="status" id="rsvpStatus" role="status" aria-live="polite"></p>
    </div>
  </div>
</section>

<!-- THANK YOU -->
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

/* ---------- Countdown ----------
   IMPORTANT: Set the real wedding date/time here.
   Format: "YYYY-MM-DDTHH:mm:ss+HH:MM" (e.g. "2025-03-15T15:00:00+03:00")
   This placeholder must be replaced with the actual wedding moment. */
var WEDDING_DATE = new Date("2030-01-01T15:00:00+03:00").getTime();

function tick(){
  var diff = WEDDING_DATE - Date.now();
  if (diff < 0) diff = 0;
  var s = Math.floor(diff / 1000);
  $("#d").textContent = String(Math.floor(s / 86400)).padStart(2, "0");
  $("#h").textContent = String(Math.floor((s % 86400) / 3600)).padStart(2, "0");
  $("#m").textContent = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  $("#s").textContent = String(s % 60).padStart(2, "0");
}
tick(); setInterval(tick, 1000);

/* ---------- Map link (edit href to match your venue) ---------- */
$("#mapLink").href = "https://www.google.com/maps/search/?api=1&query=" +
  encodeURIComponent("[EDIT: Venue Name and Address]");

/* ---------- Media ---------- */
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
    gallery.innerHTML = '<div class="gallery-empty">Our photographs will appear here soon.</div>';
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

/* ---------- RSVP ---------- */
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
  if (name.length < 2) {
    st.className = "status err";
    st.textContent = "Please enter your full name so we know who to thank.";
    return;
  }
  if (!attendingVal) {
    st.className = "status err";
    st.textContent = "Please let us know if you will be able to attend.";
    return;
  }

  btn.disabled = true;
  st.textContent = "Sending your response…";

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
  }).then(function(r){
    return r.json().then(function(d){ return { ok: r.ok, data: d }; });
  }).then(function(res){
    if (!res.ok) throw new Error(res.data.error || "Could not send.");
    st.className = "status ok";
    st.textContent = attendingVal === "yes"
      ? "Thank you — your seat is saved, and our hearts are fuller for it."
      : "Thank you for letting us know. You will be missed and remembered in our prayers.";
    $("#rsvpForm").reset();
  }).catch(function(err){
    st.className = "status err";
    st.textContent = err.message || "Something went wrong. Please try again.";
  }).finally(function(){
    btn.disabled = false;
  });
});

/* ---------- Reveal on scroll ---------- */
var io = new IntersectionObserver(function(entries){
  entries.forEach(function(e){
    if (e.isIntersecting) {
      e.target.classList.add("on");
      io.unobserve(e.target);
    }
  });
}, { threshold: 0.12 });
document.querySelectorAll(".rv").forEach(function(el){ io.observe(el); });
</script>
</body>
</html>`;

/* ============================================================================
   ADMIN FRONTEND
   ============================================================================ */
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Edom &amp; Yohi</title>
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
      <input type="file" id="mediaFile" accept="image/*,video/*">
      <input type="text" id="mediaCaption" placeholder="Caption (optional)" maxlength="200">
      <button id="uploadMediaBtn">Upload</button>
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
</script>
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
  app.listen(PORT, () => console.log(`🚀 Edom & Yohi wedding site running on :${PORT}`));
});