/* ============================================================================
   EDOM & YOHI — PREMIUM WEDDING WEBSITE
   Complete single-file Node.js application (server + frontend)
   ----------------------------------------------------------------------------
   Deployment: Render Web Service + External PostgreSQL (Neon) + Cloudinary
   Required environment variables (set in Render dashboard, never in this file):
     DATABASE_URL
     JWT_SECRET
     ADMIN_PASSWORD_HASH
     CLOUDINARY_CLOUD_NAME
     CLOUDINARY_API_KEY
     CLOUDINARY_API_SECRET
     RESEND_API_KEY
     ADMIN_EMAIL
     FROM_EMAIL
   ============================================================================ */

import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import pg from "pg";
import { v2 as cloudinary } from "cloudinary";
import { Resend } from "resend";

const app = express();
const PORT = process.env.PORT || 3000;

/* ============================================================================
   DATABASE
   ============================================================================ */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
  max: 5
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS photos (
  id         SERIAL PRIMARY KEY,
  url        TEXT NOT NULL,
  public_id  TEXT,
  is_hero    BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS wishes (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(80) NOT NULL,
  email      VARCHAR(160),
  message    TEXT NOT NULL,
  approved   BOOLEAN DEFAULT FALSE,
  dup_hash   VARCHAR(64) NOT NULL,
  ip_hash    VARCHAR(64),
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wishes_approved ON wishes(approved, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wishes_dup ON wishes(dup_hash, created_at DESC);
`;

async function initDb(retries = 6) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query(SCHEMA);
      console.log("✅ Database schema ready");
      return;
    } catch (err) {
      console.warn(`DB init attempt ${i + 1} failed:`, err.message);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error("❌ Could not initialise database after retries.");
}

/* ============================================================================
   EXTERNAL SERVICES
   ============================================================================ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

/* ============================================================================
   MIDDLEWARE
   ============================================================================ */
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

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

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const wishLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 5  });
const apiLimiter   = rateLimit({ windowMs: 60 * 1000, max: 120 });

app.use("/api", apiLimiter);

/* ============================================================================
   API ROUTES
   ============================================================================ */
app.get("/api/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

/* ---------- AUTH ---------- */
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: "Password required" });
  if (!process.env.ADMIN_PASSWORD_HASH) {
    return res.status(500).json({ error: "Admin password not configured" });
  }
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

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie(ADMIN_COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (_req, res) => res.json({ ok: true }));

/* ---------- PHOTOS (public read) ---------- */
app.get("/api/photos", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, url, is_hero FROM photos ORDER BY is_hero DESC, created_at DESC"
  );
  res.json(rows);
});

/* ---------- PHOTOS (admin write) ---------- */
app.post("/api/admin/cloudinary-signature", requireAdmin, (req, res) => {
  if (!process.env.CLOUDINARY_API_SECRET) {
    return res.status(500).json({ error: "Cloudinary not configured" });
  }
  const timestamp = Math.round(Date.now() / 1000);
  const folder = "edom-yohi-wedding";
  const toSign = `folder=${folder}&timestamp=${timestamp}`;
  const signature = crypto
    .createHash("sha1")
    .update(toSign + process.env.CLOUDINARY_API_SECRET)
    .digest("hex");

  res.json({
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
    apiKey: process.env.CLOUDINARY_API_KEY,
    timestamp,
    folder,
    signature
  });
});

app.post("/api/admin/photos", requireAdmin, async (req, res) => {
  const { url, publicId, isHero } = req.body || {};
  if (!url || !/^https:\/\/res\.cloudinary\.com\//.test(url)) {
    return res.status(400).json({ error: "Invalid image URL" });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (isHero) await client.query("UPDATE photos SET is_hero = FALSE");
    const { rows } = await client.query(
      "INSERT INTO photos (url, public_id, is_hero) VALUES ($1,$2,$3) RETURNING id, url, is_hero",
      [url, publicId || null, Boolean(isHero)]
    );
    await client.query("COMMIT");
    res.status(201).json(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Could not save photo" });
  } finally {
    client.release();
  }
});

app.patch("/api/admin/photos/:id/hero", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("UPDATE photos SET is_hero = FALSE");
    const { rowCount } = await client.query(
      "UPDATE photos SET is_hero = TRUE WHERE id = $1", [id]
    );
    await client.query("COMMIT");
    if (!rowCount) return res.status(404).json({ error: "Photo not found" });
    res.json({ ok: true });
  } catch {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Could not update hero photo" });
  } finally {
    client.release();
  }
});

app.delete("/api/admin/photos/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query(
    "SELECT public_id FROM photos WHERE id = $1", [id]
  );
  if (!rows.length) return res.status(404).json({ error: "Photo not found" });
  if (rows[0].public_id) {
    try { await cloudinary.uploader.destroy(rows[0].public_id); }
    catch (e) { console.warn("Cloudinary destroy failed:", e.message); }
  }
  await pool.query("DELETE FROM photos WHERE id = $1", [id]);
  res.json({ ok: true });
});

/* ---------- WISHES (public) ---------- */
app.get("/api/wishes", async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT name, message, created_at FROM wishes
     WHERE approved = TRUE ORDER BY created_at DESC LIMIT 200`
  );
  res.json(rows);
});

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

app.post("/api/wishes", wishLimiter, async (req, res) => {
  const { name, email, message, website } = req.body || {};

  // Honeypot: real users never fill a hidden field
  if (website) return res.status(400).json({ error: "Rejected" });

  const cleanName  = String(name    || "").trim().slice(0, 80);
  const cleanMsg   = String(message || "").trim().slice(0, 1000);
  const cleanEmail = String(email   || "").trim().slice(0, 160);

  if (cleanName.length < 2)  return res.status(400).json({ error: "Please enter your name." });
  if (cleanMsg.length < 3)   return res.status(400).json({ error: "Please write a message." });
  if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }

  const dupHash = sha256(`${cleanName.toLowerCase()}|${cleanMsg.toLowerCase()}`);
  const ipHash  = sha256((req.ip || "unknown") + process.env.JWT_SECRET);

  const dup = await pool.query(
    `SELECT 1 FROM wishes
     WHERE dup_hash = $1 AND created_at > NOW() - INTERVAL '10 minutes' LIMIT 1`,
    [dupHash]
  );
  if (dup.rowCount) return res.status(409).json({ error: "This message was already received." });

  const approve = String(process.env.AUTO_APPROVE_WISHES).toLowerCase() === "true";

  const { rows } = await pool.query(
    `INSERT INTO wishes (name, email, message, approved, dup_hash, ip_hash)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at`,
    [cleanName, cleanEmail || null, cleanMsg, approve, dupHash, ipHash]
  );

  // Fire-and-forget email — never blocks the guest's wish
  if (resend && process.env.ADMIN_EMAIL && process.env.FROM_EMAIL) {
    resend.emails.send({
      from: process.env.FROM_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: `💌 New wedding wish from ${cleanName}`,
      html: `
        <div style="font-family:Georgia,serif;background:#0a0a0a;color:#EDE3D0;padding:32px;border-radius:12px">
          <h2 style="color:#D4AF37;margin:0 0 16px">New wish for EDOM &amp; Yohi</h2>
          <p><strong style="color:#D4AF37">Name:</strong> ${cleanName}</p>
          <p><strong style="color:#D4AF37">Email:</strong> ${cleanEmail || "— not provided —"}</p>
          <p><strong style="color:#D4AF37">Date:</strong> ${new Date(rows[0].created_at).toUTCString()}</p>
          <hr style="border-color:#333;margin:20px 0">
          <p style="white-space:pre-wrap;line-height:1.7">${cleanMsg}</p>
          <p style="color:#888;font-size:12px;margin-top:24px">
            Wish #${rows[0].id} · ${approve ? "auto-approved" : "pending approval in /admin"}
          </p>
        </div>`
    }).catch(err => console.error("Resend error:", err.message));
  }

  res.status(201).json({ ok: true, pending: !approve });
});

/* ---------- WISHES (admin moderation) ---------- */
app.get("/api/admin/wishes", requireAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, email, message, approved, created_at
     FROM wishes ORDER BY created_at DESC LIMIT 500`
  );
  res.json(rows);
});

app.patch("/api/admin/wishes/:id/approve", requireAdmin, async (req, res) => {
  await pool.query("UPDATE wishes SET approved = TRUE WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

app.delete("/api/admin/wishes/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM wishes WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ============================================================================
   FRONTEND (served from memory — no separate HTML/CSS/JS files)
   ============================================================================ */
const PUBLIC_HTML = `<!DOCTYPE html>
<html lang="am">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>EDOM & Yohi — Wedding Invitation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Cormorant+Garamond:ital,wght@0,400;0,500;0,600;1,400&family=Montserrat:wght@300;400;500;600&family=Noto+Serif+Ethiopic:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"><\/script>
<style>
:root{
  --black:#080808; --black-2:#101010; --black-3:#181614;
  --gold:#D4AF37; --gold-2:#F3E3A8; --gold-3:#B8912E;
  --champagne:#F7E7CE; --text:#EDE3D0; --muted:#A89880;
  --line:rgba(212,175,55,.22);
  --serif:"Cormorant Garamond","Noto Serif Ethiopic",Georgia,serif;
  --script:"Great Vibes","Cormorant Garamond",cursive;
  --sans:"Montserrat","Noto Serif Ethiopic",sans-serif;
  --am:"Noto Serif Ethiopic","Cormorant Garamond",serif;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth}
body{margin:0;background:var(--black);color:var(--text);font-family:var(--sans);font-weight:300;line-height:1.65;overflow-x:hidden;-webkit-font-smoothing:antialiased}
html[lang="am"] .lang-en{display:none!important}
html[lang="en"] .lang-am{display:none!important}
html[lang="am"]{font-family:var(--am)}
img{max-width:100%;display:block}
a{color:var(--gold);text-decoration:none}
.wrap{max-width:820px;margin:0 auto;padding:0 22px}
.sec{padding:88px 0;position:relative}
.sec+.sec{border-top:1px solid var(--line)}

/* ---------- top bar ---------- */
.topbar{position:fixed;inset:0 0 auto 0;z-index:100;display:flex;align-items:center;justify-content:space-between;
  padding:14px 20px;padding-top:calc(14px + env(safe-area-inset-top,0px));
  background:linear-gradient(180deg,rgba(8,8,8,.92),rgba(8,8,8,0));backdrop-filter:blur(8px)}
.brand{font-family:var(--serif);font-size:19px;letter-spacing:4px;color:var(--gold)}
.lang{display:flex;border:1px solid var(--line);border-radius:999px;overflow:hidden}
.lang button{font:inherit;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;padding:7px 13px;border:0;cursor:pointer;background:transparent;color:var(--muted)}
.lang button[aria-pressed="true"]{background:var(--gold);color:#000;font-weight:600}

/* ---------- hero ---------- */
.hero{min-height:100vh;min-height:100svh;display:flex;align-items:center;justify-content:center;text-align:center;padding:120px 20px 70px;position:relative;overflow:hidden;
  background:
    radial-gradient(ellipse at 20% 10%,rgba(212,175,55,.10),transparent 55%),
    radial-gradient(ellipse at 80% 90%,rgba(212,175,55,.08),transparent 55%),
    var(--black)}
.hero-bg{position:absolute;inset:0;background-size:cover;background-position:center;opacity:0;transition:opacity 1.4s ease}
.hero-bg.on{opacity:.42}
.hero-bg::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(8,8,8,.55),rgba(8,8,8,.85))}
.rings{position:relative;width:120px;height:120px;margin:0 auto 22px;filter:drop-shadow(0 0 18px rgba(212,175,55,.55))}
.rings svg{width:100%;height:100%;overflow:visible}
.rings .r{fill:none;stroke:url(#gg);stroke-width:2.2;stroke-linecap:round;
  stroke-dasharray:270;stroke-dashoffset:270;animation:draw 2.4s ease forwards}
.rings .r2{animation-delay:.5s}
@keyframes draw{to{stroke-dashoffset:0}}
.rings .spin{transform-origin:60px 60px;animation:spin 18s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.spark{position:absolute;width:3px;height:3px;border-radius:50%;background:var(--gold-2);
  box-shadow:0 0 6px var(--gold);animation:tw 3s ease-in-out infinite}
@keyframes tw{0%,100%{opacity:.15;transform:scale(.6)}50%{opacity:1;transform:scale(1.25)}}
.kicker{font-family:var(--serif);font-style:italic;font-size:15px;color:var(--gold);letter-spacing:.5px;margin:0 0 8px}
.names{font-family:var(--script);font-size:clamp(56px,17vw,116px);line-height:.95;margin:0;color:var(--gold-2);font-weight:400;letter-spacing:1px}
.names .amp{font-family:var(--serif);font-style:italic;color:var(--gold);font-size:.55em;margin:0 6px;display:inline-block;transform:translateY(-.15em)}
.tag{font-family:var(--serif);font-size:clamp(15px,3.6vw,19px);color:var(--champagne);margin:18px auto 0;max-width:520px;line-height:1.6}
.tag-am{font-family:var(--am);font-size:clamp(13px,3.2vw,16px);color:var(--muted);margin:8px auto 0;max-width:520px}
.cta{display:inline-flex;align-items:center;gap:8px;margin-top:30px;padding:13px 30px;border:1px solid var(--gold);border-radius:999px;
  color:var(--gold);font-size:12px;letter-spacing:2px;text-transform:uppercase;transition:.3s}
.cta:hover{background:var(--gold);color:#000;box-shadow:0 0 26px rgba(212,175,55,.35)}

/* ---------- countdown ---------- */
.cd{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;max-width:520px;margin:36px auto 0}
.cd div{border:1px solid var(--line);border-radius:12px;padding:14px 4px;background:rgba(255,255,255,.02)}
.cd b{display:block;font-family:var(--serif);font-size:clamp(26px,6vw,38px);font-weight:600;color:var(--gold-2);line-height:1}
.cd span{display:block;font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-top:6px}
@media(max-width:420px){.cd{grid-template-columns:repeat(2,1fr)}}

/* ---------- section headings ---------- */
.sec-k{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--gold-3);text-align:center;margin:0 0 6px}
.sec-t{font-family:var(--script);font-size:clamp(38px,8vw,56px);color:var(--gold);text-align:center;margin:0 0 8px;font-weight:400}
.sec-s{font-family:var(--serif);font-style:italic;text-align:center;color:var(--muted);margin:0 auto 34px;max-width:560px}
.orn{display:flex;align-items:center;justify-content:center;gap:12px;margin:0 auto 26px;color:var(--gold)}
.orn::before,.orn::after{content:"";width:70px;height:1px;background:linear-gradient(90deg,transparent,var(--gold))}
.orn::after{background:linear-gradient(90deg,var(--gold),transparent)}
.orn svg{width:22px;height:22px}

/* ---------- love letter ---------- */
.letter{max-width:640px;margin:0 auto;border:1px solid var(--line);border-radius:18px;padding:32px 28px;
  background:linear-gradient(180deg,rgba(212,175,55,.05),rgba(212,175,55,.01));position:relative}
.letter::before{content:"❝";position:absolute;top:10px;left:20px;font-family:var(--serif);font-size:56px;color:var(--gold);opacity:.28;line-height:1}
.letter p{font-family:var(--serif);font-size:18px;line-height:1.85;margin:0 0 16px;color:var(--text);position:relative}
.letter p:last-child{margin-bottom:0}
.letter .sig{font-family:var(--script);font-size:30px;color:var(--gold);margin-top:20px;text-align:right}
html[lang="am"] .letter p{font-family:var(--am);font-size:16px;line-height:1.9}

/* ---------- verse ---------- */
.verse{max-width:640px;margin:0 auto 26px;text-align:center;padding:34px 26px;border:1px solid var(--line);border-radius:18px;
  background:radial-gradient(ellipse at top,rgba(212,175,55,.08),transparent 70%)}
.verse .ref{font-family:var(--serif);font-size:13px;letter-spacing:3px;text-transform:uppercase;color:var(--gold-3);margin:0 0 14px}
.verse blockquote{font-family:var(--serif);font-style:italic;font-size:clamp(17px,4vw,21px);line-height:1.8;color:var(--champagne);margin:0}
html[lang="am"] .verse blockquote{font-family:var(--am);font-style:normal;font-size:15px}

/* ---------- guest message ---------- */
.guest{max-width:640px;margin:0 auto;text-align:center;font-family:var(--serif);font-size:18px;line-height:1.85;color:var(--text)}
html[lang="am"] .guest{font-family:var(--am);font-size:16px;line-height:1.95}
.guest .sig{font-family:var(--script);font-size:34px;color:var(--gold);margin-top:18px}

/* ---------- details ---------- */
.details{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:620px;margin:0 auto}
@media(max-width:560px){.details{grid-template-columns:1fr}}
.card{border:1px solid var(--line);border-radius:16px;padding:26px 20px;text-align:center;background:rgba(255,255,255,.02)}
.card svg{width:34px;height:34px;margin:0 auto 10px;color:var(--gold)}
.card h3{font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:var(--gold-3);margin:0 0 8px;font-weight:500}
.card .v{font-family:var(--serif);font-size:19px;color:var(--champagne);margin:0;line-height:1.45}
.card .s{font-size:13px;color:var(--muted);margin:6px 0 0}
.map{display:inline-flex;align-items:center;gap:6px;margin-top:12px;font-size:12px;letter-spacing:1px;border-bottom:1px solid var(--line);padding-bottom:2px}

/* ---------- gallery ---------- */
.hero-frame{position:relative;max-width:520px;margin:0 auto;aspect-ratio:4/5;border-radius:20px;overflow:hidden;
  border:1px solid var(--gold-3);box-shadow:0 0 0 1px rgba(212,175,55,.15),0 30px 60px -30px rgba(0,0,0,.9);background:var(--black-2)}
.hero-frame img{width:100%;height:100%;object-fit:cover}
.hero-frame .ph{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--gold-3);font-family:var(--serif);font-style:italic}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;max-width:520px;margin:14px auto 0}
.grid .t{aspect-ratio:1;border-radius:12px;overflow:hidden;border:1px solid var(--line);background:var(--black-2);cursor:pointer;transition:.3s}
.grid .t:hover{transform:translateY(-3px);border-color:var(--gold)}
.grid .t img{width:100%;height:100%;object-fit:cover}

/* ---------- wishes ---------- */
.form{max-width:520px;margin:0 auto;display:flex;flex-direction:column;gap:12px}
.form input,.form textarea{font:inherit;font-size:15px;color:var(--text);background:rgba(255,255,255,.03);
  border:1px solid var(--line);border-radius:10px;padding:13px 15px;width:100%;transition:.25s}
.form input:focus,.form textarea:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(212,175,55,.12)}
.form textarea{resize:vertical;min-height:96px}
.form .hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
.btn{font:inherit;font-size:12px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;
  background:var(--gold);color:#000;border:1px solid var(--gold);border-radius:999px;padding:13px 28px;font-weight:600;transition:.3s}
.btn:hover{background:transparent;color:var(--gold)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn.ghost{background:transparent;color:var(--gold)}
.btn.ghost:hover{background:var(--gold);color:#000}
.status{min-height:1.2em;text-align:center;font-size:13px;margin:10px 0 0;color:var(--muted)}
.status.ok{color:#7dd3a0}.status.err{color:#e0796f}
.wishes{list-style:none;padding:0;max-width:620px;margin:28px auto 0;display:flex;flex-direction:column;gap:10px;max-height:420px;overflow-y:auto}
.wishes li{border:1px solid var(--line);border-left:2px solid var(--gold-3);border-radius:0 12px 12px 0;padding:14px 18px;background:rgba(255,255,255,.02)}
.wishes .n{font-family:var(--serif);font-weight:600;color:var(--gold);margin:0 0 4px;font-size:15px}
.wishes .m{margin:0;font-family:var(--serif);font-size:15px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.wishes .d{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);margin:6px 0 0}
.wishes .empty{text-align:center;border:0;color:var(--muted);font-style:italic}

/* ---------- qr ---------- */
.qr{max-width:380px;margin:0 auto;text-align:center;border:1px solid var(--line);border-radius:18px;padding:28px 22px;background:rgba(255,255,255,.02)}
.qr img{width:180px;height:180px;margin:0 auto;padding:10px;background:#fff;border-radius:12px}
.qr .acts{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:16px}
.qr .acts .btn{font-size:10px;padding:10px 16px}

/* ---------- footer ---------- */
.foot{text-align:center;padding:60px 20px calc(50px + env(safe-area-inset-bottom,0px));border-top:1px solid var(--line)}
.foot .n{font-family:var(--script);font-size:40px;color:var(--gold);margin:0}
.foot .n .amp{font-family:var(--serif);font-style:italic;font-size:.55em;color:var(--gold-2)}
.foot p{color:var(--muted);font-size:12px;letter-spacing:1px;margin:8px 0 0}

/* ---------- reveal ---------- */
.rv{opacity:0;transform:translateY(26px);transition:opacity .9s ease,transform .9s ease}
.rv.on{opacity:1;transform:none}

/* ---------- toast ---------- */
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(140%);background:var(--gold);color:#000;
  padding:12px 22px;border-radius:999px;font-size:13px;font-weight:500;transition:transform .35s;z-index:999;max-width:90vw;text-align:center}
.toast.on{transform:translateX(-50%) translateY(0)}
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">E &amp; Y</div>
  <div class="lang" role="group" aria-label="Language">
    <button id="bEN" type="button" aria-pressed="false">EN</button>
    <button id="bAM" type="button" aria-pressed="true">አማ</button>
  </div>
</header>

<!-- HERO -->
<section class="hero">
  <div class="hero-bg" id="heroBg"></div>
  <span class="spark" style="top:18%;left:12%"></span>
  <span class="spark" style="top:30%;right:14%;animation-delay:1.2s"></span>
  <span class="spark" style="bottom:26%;left:18%;animation-delay:2s"></span>
  <span class="spark" style="bottom:34%;right:10%;animation-delay:.6s"></span>

  <div style="position:relative;z-index:2;text-align:center">
    <div class="rings">
      <svg viewBox="0 0 120 120">
        <defs>
          <linearGradient id="gg" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#F3E3A8"/><stop offset="50%" stop-color="#D4AF37"/><stop offset="100%" stop-color="#B8912E"/>
          </linearGradient>
        </defs>
        <g class="spin">
          <circle class="r" cx="46" cy="66" r="28"/>
          <circle class="r r2" cx="74" cy="66" r="28"/>
        </g>
      </svg>
    </div>

    <p class="kicker lang-en">The Wedding Celebration Of</p>
    <p class="kicker lang-am">የሠርግ ሥነ ሥርዓት</p>

    <h1 class="names">Edom<span class="amp">&amp;</span>Yohi</h1>

    <p class="tag lang-en">Two Hearts. One Promise. One Beautiful Forever.</p>
    <p class="tag-am lang-am">ሁለት ልቦች፣ አንድ ቃል ኪዳን፣ አንድ የዘላለም ጉዞ።</p>

    <div class="cd" id="cd">
      <div><b id="d">00</b><span class="lang-en">Days</span><span class="lang-am">ቀናት</span></div>
      <div><b id="h">00</b><span class="lang-en">Hours</span><span class="lang-am">ሰዓት</span></div>
      <div><b id="m">00</b><span class="lang-en">Minutes</span><span class="lang-am">ደቂቃ</span></div>
      <div><b id="s">00</b><span class="lang-en">Seconds</span><span class="lang-am">ሰከንድ</span></div>
    </div>

    <a class="cta" href="#details">
      <span class="lang-en">View Invitation</span><span class="lang-am">ግብዣውን ይመልከቱ</span>
    </a>
  </div>
</section>

<!-- LOVE STORY -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">From Edom to Yohi</p>
    <p class="sec-k lang-am">ከኤዶም ለዮሂ</p>
    <h2 class="sec-t lang-en">Our Love Story</h2>
    <h2 class="sec-t lang-am">የፍቅራችን ታሪክ</h2>
    <div class="orn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 21s-8-5.5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 5.5-8 11-8 11z"/></svg></div>

    <div class="letter">
      <div class="lang-en">
        <p>Yohi, you are not just someone I chose to walk beside. You are the woman who makes my future feel beautiful and my heart feel at home. Your smile is a blessing in my life, your presence is my happiness, and your place in my heart is one that nobody else could ever take.</p>
        <p>I do not promise a perfect life, but I promise to stand beside you, respect you, protect our dreams, pray with you, and choose you through every season of life.</p>
        <p>You are my Yohi, my special person, my future wife, and the woman with whom I want to build a beautiful family.</p>
        <p class="sig">— Edom</p>
      </div>
      <div class="lang-am">
        <p>ዮሂዬ፣ አንቺ በሕይወቴ ውስጥ የመጣሽ ተራ ሰው አይደለሽም። ለወደፊት ሕይወቴ ውበትን፣ ለልቤም የእረፍት ቦታን የሰጠሽኝ ልዩ ሰው ነሽ። ፈገግታሽ የደስታዬ ምንጭ፣ መኖርሽ ደግሞ በሕይወቴ ያለ በረከት ነው።</p>
        <p>ፍጹም ሕይወት እንደምሰጥሽ ቃል አልገባም፤ ነገር ግን በደስታም በፈተናም ከጎንሽ እንደምቆም፣ እንደማከብርሽ፣ ሕልማችንን አብረን እንደምንገነባ፣ በጸሎትም እንደምንተባበር ቃል እገባለሁ።</p>
        <p>ዮሂዬ፣ ለእኔ ልዩ ነሽ። ከአንቺ ጋር ቤተሰብ መመሥረትና የሕይወት ጉዟችንን አብረን መቀጠል የልቤ ትልቁ ምኞት ነው።</p>
        <p class="sig">— ኤዶም</p>
      </div>
    </div>
  </div>
</section>

<!-- BIBLE VERSES -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">The Word That Guides Us</p>
    <p class="sec-k lang-am">የሚመራን ቃል</p>
    <h2 class="sec-t lang-en">Our Bible Verse</h2>
    <h2 class="sec-t lang-am">የመጽሐፍ ቅዱስ ቃል</h2>
    <div class="orn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.6 6.9L22 9.5l-5.4 4.7 1.7 7L12 17.6 5.7 21.2l1.7-7L2 9.5l7.4-.6z"/></svg></div>

    <div class="verse">
      <p class="ref">1 Corinthians 13:4–7</p>
      <blockquote class="lang-en">“Love is patient, love is kind. It does not envy, it does not boast, it is not proud. It does not dishonor others, it is not self-seeking, it is not easily angered, it keeps no record of wrongs. Love does not delight in evil but rejoices with the truth. It always protects, always trusts, always hopes, always perseveres.”</blockquote>
      <blockquote class="lang-am">“ፍቅር ይታገሣል፤ ፍቅር ቸር ነው። ፍቅር አይቀናም፤ አይመካም፤ አይታበይም፤ አይዘባበትም፤ የራሱን አይፈልግም፤ አይበደልም፤ በደልን አያስብም፤ በክፋት አይደሰትም፤ ነገር ግን ከእውነት ጋር ደስ ይለዋል። ሁሉን ይታገሣል፤ ሁሉን ያምናል፤ ሁሉን ተስፋ ያደርጋል፤ ሁሉን ይጸናል።”</blockquote>
    </div>

    <div class="verse">
      <p class="ref">Ecclesiastes 4:9</p>
      <blockquote class="lang-en">“Two are better than one, because they have a good return for their labor.”</blockquote>
      <blockquote class="lang-am">“ሁለት ከአንድ ይሻላሉ፤ ሥራቸው መልካም ዋጋ አለው።”</blockquote>
    </div>
  </div>
</section>

<!-- GUEST MESSAGE -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">A Word For Our Guests</p>
    <p class="sec-k lang-am">ለእንግዶቻችን መልእክት</p>
    <h2 class="sec-t lang-en">To Our Family &amp; Friends</h2>
    <h2 class="sec-t lang-am">ለቤተሰቦቻችንና ለወዳጆቻችን</h2>
    <div class="orn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3a4 4 0 0 1 4 4c0 1.6-1 3-2.4 3.6A4 4 0 0 1 16 14a4 4 0 0 1-4 4 4 4 0 0 1-4-4 4 4 0 0 1 2.4-3.4A4 4 0 0 1 8 7a4 4 0 0 1 4-4z"/></svg></div>

    <div class="guest">
      <div class="lang-en">
        <p>Dear Family and Friends,</p>
        <p>Your presence is one of the greatest gifts we could receive. Thank you for celebrating this special chapter of our lives with us. May the joy you share with us today remain in your hearts for years to come.</p>
        <p>May God bless you, guide your journeys, and fill your homes with peace and happiness.</p>
        <p class="sig">With love and gratitude,<br>Edom &amp; Yohi</p>
      </div>
      <div class="lang-am">
        <p>ውድ ቤተሰቦቻችንና ወዳጆቻችን፣</p>
        <p>በዚህ ልዩ የሕይወታችን ቀን ከእኛ ጋር በመሆናችሁ ከልባችን እናመሰግናለን። መገኘታችሁ ለእኛ ትልቅ ስጦታ ነው። ዛሬ ከእኛ ጋር የምትጋሩት ደስታ በልባችሁ ውስጥ ለዘላለም የሚቆይ ትዝታ ይሁን።</p>
        <p>እግዚአብሔር ይባርካችሁ፣ መንገዳችሁን ይምራላችሁ፣ ቤታችሁንም በሰላምና በደስታ ይሙላላችሁ።</p>
        <p class="sig">በምስጋናና በአክብሮት፣<br>ኤዶም &amp; ዮሂ</p>
      </div>
    </div>
  </div>
</section>

<!-- DETAILS -->
<section class="sec" id="details">
  <div class="wrap rv">
    <p class="sec-k lang-en">The Celebration</p>
    <p class="sec-k lang-am">ሥነ ሥርዓቱ</p>
    <h2 class="sec-t lang-en">When &amp; Where</h2>
    <h2 class="sec-t lang-am">መቼ እና የት</h2>
    <div class="orn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a7 7 0 0 1 7 7c0 5-7 13-7 13S5 14 5 9a7 7 0 0 1 7-7zm0 9.5A2.5 2.5 0 1 0 12 6.5a2.5 2.5 0 0 0 0 5z"/></svg></div>

    <div class="details">
      <div class="card">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>
        <h3 class="lang-en">Date</h3><h3 class="lang-am">ቀን</h3>
        <p class="v lang-en">28 Ginbot 2029</p><p class="v lang-am">28 ግንቦት 2029</p>
        <p class="s lang-en">Monday · Ceremony at 10:00 AM</p><p class="s lang-am">ሰኞ · ሥነ ሥርዓት ከጠዋቱ 10:00</p>
      </div>
      <div class="card">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 21s-7-6.5-7-12a7 7 0 0 1 14 0c0 5.5-7 12-7 12z"/><circle cx="12" cy="9" r="2.5"/></svg>
        <h3 class="lang-en">Venue</h3><h3 class="lang-am">ቦታ</h3>
        <p class="v lang-en">Hawassa Apostolic Church</p><p class="v lang-am">ሀዋሳ አፖስቶሊክ ቤተ ክርስቲያን</p>
        <p class="s lang-en">Hawassa, Ethiopia</p><p class="s lang-am">ሀዋሳ፣ ኢትዮጵያ</p>
        <a class="map" target="_blank" rel="noopener"
           href="https://www.google.com/maps/search/?api=1&query=Hawassa%20Apostolic%20Church%2C%20Ethiopia">
          <span class="lang-en">Open in Maps →</span><span class="lang-am">በካርታ ክፈት →</span>
        </a>
      </div>
    </div>
  </div>
</section>

<!-- GALLERY -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">Our Moments</p>
    <p class="sec-k lang-am">ትዝታዎቻችን</p>
    <h2 class="sec-t lang-en">Photo Gallery</h2>
    <h2 class="sec-t lang-am">የፎቶ ማህደር</h2>
    <div class="orn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm8 4a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg></div>

    <div class="hero-frame" id="heroFrame">
      <div class="ph" id="heroPh">
        <span class="lang-en">Photos coming soon</span><span class="lang-am">ፎቶዎች በቅርቡ</span>
      </div>
      <img id="heroImg" alt="Edom and Yohi" style="display:none">
    </div>
    <div class="grid" id="grid"></div>
  </div>
</section>

<!-- WISHES -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">With Love</p>
    <p class="sec-k lang-am">በፍቅር</p>
    <h2 class="sec-t lang-en">Wishes &amp; Blessings</h2>
    <h2 class="sec-t lang-am">ምኞቶች እና ቡራኬዎች</h2>
    <p class="sec-s lang-en">Leave a message for the couple</p>
    <p class="sec-s lang-am">ለጥንዶቹ መልእክት ይተዉ</p>

    <form class="form" id="wishForm" novalidate>
      <input type="text" id="wn" maxlength="80" required
             placeholder="Your full name" data-ph-en="Your full name" data-ph-am="ሙሉ ስምዎ">
      <input type="email" id="we" maxlength="160"
             placeholder="Email (optional)" data-ph-en="Email (optional)" data-ph-am="ኢሜይል (አማራጭ)">
      <textarea id="wm" maxlength="1000" rows="4" required
                placeholder="Your congratulations and blessings…"
                data-ph-en="Your congratulations and blessings…"
                data-ph-am="ምስጋናዎንና ቡራኬዎን ይጻፉ…"></textarea>
      <input class="hp" id="wh" type="text" tabindex="-1" autocomplete="off" aria-hidden="true">
      <button class="btn" type="submit" id="wishBtn">
        <span class="lang-en">Send Wish</span><span class="lang-am">ምኞት ላክ</span>
      </button>
    </form>
    <p class="status" id="wishStatus" role="status" aria-live="polite"></p>
    <ul class="wishes" id="wishList"></ul>
  </div>
</section>

<!-- QR -->
<section class="sec">
  <div class="wrap rv">
    <p class="sec-k lang-en">Share The Joy</p>
    <p class="sec-k lang-am">ደስታውን ያጋሩ</p>
    <h2 class="sec-t lang-en">Invitation QR</h2>
    <h2 class="sec-t lang-am">የግብዣ QR</h2>
    <p class="sec-s lang-en">Scan to open this invitation on any phone</p>
    <p class="sec-s lang-am">በማንኛውም ስልክ ለመክፈት ስካን ያድርጉ</p>

    <div class="qr">
      <div id="qrBox"></div>
      <div class="acts">
        <button class="btn ghost" id="copyLink" type="button">
          <span class="lang-en">Copy Link</span><span class="lang-am">ሊንክ ገልብጥ</span>
        </button>
        <button class="btn" id="shareBtn" type="button">
          <span class="lang-en">Share</span><span class="lang-am">አጋራ</span>
        </button>
      </div>
    </div>
  </div>
</section>

<footer class="foot">
  <p class="n">Edom<span class="amp">&amp;</span>Yohi</p>
  <p class="lang-en">With love — 28 Ginbot 2029 · Hawassa</p>
  <p class="lang-am">በፍቅር — 28 ግንቦት 2029 · ሀዋሳ</p>
</footer>

<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const toast = (msg) => {
  const t = $("#toast"); t.textContent = msg; t.classList.add("on");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("on"), 3200);
};

/* ---------- language ---------- */
function setLang(lang) {
  document.documentElement.lang = lang;
  $("#bEN").setAttribute("aria-pressed", String(lang === "en"));
  $("#bAM").setAttribute("aria-pressed", String(lang === "am"));
  try { localStorage.setItem("ey_lang", lang); } catch {}
  $$("[data-ph-en]").forEach(el => {
    el.placeholder = lang === "en" ? el.dataset.phEn : el.dataset.phAm;
  });
}
$("#bEN").onclick = () => setLang("en");
$("#bAM").onclick = () => setLang("am");
let saved = "am";
try { saved = localStorage.getItem("ey_lang") || "am"; } catch {}
setLang(saved);

/* ---------- countdown ---------- */
const target = new Date("2029-05-28T10:00:00+03:00").getTime();
function tick() {
  let diff = target - Date.now();
  if (diff < 0) diff = 0;
  const s = Math.floor(diff / 1000);
  $("#d").textContent = String(Math.floor(s / 86400)).padStart(2, "0");
  $("#h").textContent = String(Math.floor((s % 86400) / 3600)).padStart(2, "0");
  $("#m").textContent = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  $("#s").textContent = String(s % 60).padStart(2, "0");
}
tick(); setInterval(tick, 1000);

/* ---------- photos ---------- */
async function loadPhotos() {
  try {
    const res = await fetch("/api/photos");
    const photos = await res.json();
    const hero = photos.find(p => p.is_hero);
    if (hero) {
      const bg = $("#heroBg");
      bg.style.backgroundImage = `url("${hero.url}")`;
      bg.classList.add("on");
      $("#heroImg").src = hero.url;
      $("#heroImg").style.display = "block";
      $("#heroPh").style.display = "none";
    } else {
      $("#heroImg").style.display = "none";
      $("#heroPh").style.display = "flex";
    }
    const grid = $("#grid"); grid.innerHTML = "";
    photos.filter(p => !p.is_hero).slice(0, 9).forEach(p => {
      const d = document.createElement("div");
      d.className = "t";
      d.innerHTML = `<img src="${p.url}" alt="Wedding photo" loading="lazy">`;
      grid.appendChild(d);
    });
  } catch (e) { console.warn("Photos unavailable", e); }
}
loadPhotos();

/* ---------- wishes ---------- */
async function loadWishes() {
  try {
    const res = await fetch("/api/wishes");
    const list = await res.json();
    const ul = $("#wishList"); ul.innerHTML = "";
    if (!list.length) {
      ul.innerHTML = `<li class="empty"><span class="lang-en">No wishes yet — be the first!</span><span class="lang-am">እስካሁን ምኞት አልተጻፈም — የመጀመሪያው ይሁኑ!</span></li>`;
      return;
    }
    list.forEach(w => {
      const li = document.createElement("li");
      li.innerHTML = `<p class="n"></p><p class="m"></p><p class="d"></p>`;
      li.querySelector(".n").textContent = w.name;
      li.querySelector(".m").textContent = w.message;
      li.querySelector(".d").textContent = new Date(w.created_at).toLocaleDateString(
        document.documentElement.lang === "am" ? "am-ET" : "en-GB",
        { year: "numeric", month: "short", day: "numeric" }
      );
      ul.appendChild(li);
    });
  } catch (e) { console.warn("Wishes unavailable", e); }
}
loadWishes();

$("#wishForm").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = $("#wishBtn"), st = $("#wishStatus");
  const name = $("#wn").value.trim();
  const email = $("#we").value.trim();
  const message = $("#wm").value.trim();
  const website = $("#wh").value;

  st.className = "status"; st.textContent = "";
  if (name.length < 2 || message.length < 3) {
    st.className = "status err";
    st.textContent = document.documentElement.lang === "am"
      ? "እባክዎ ስምዎንና መልእክትዎን ይሙሉ።"
      : "Please enter your name and a message.";
    return;
  }
  btn.disabled = true;
  st.textContent = document.documentElement.lang === "am" ? "በመላክ ላይ…" : "Sending…";

  try {
    const res = await fetch("/api/wishes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, message, website })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed");

    $("#wishForm").reset();
    st.className = "status ok";
    st.textContent = data.pending
      ? (document.documentElement.lang === "am"
          ? "አመሰግናለሁ! መልእክትዎ ተቀብለናል። ከተረጋገጠ በኋላ ይታያል።"
          : "Thank you! Your message was received and will appear after approval.")
      : (document.documentElement.lang === "am"
          ? "አመሰግናለሁ! ምኞትዎ ታይቷል።"
          : "Thank you! Your wish is now live.");
    loadWishes();
  } catch (err) {
    st.className = "status err";
    st.textContent = err.message === "This message was already received."
      ? (document.documentElement.lang === "am"
          ? "ይህ መልእክት አስቀድሞ ተልኳል።"
          : "This message was already received.")
      : (document.documentElement.lang === "am"
          ? "መላክ አልተቻለም። እባክዎ በድጋሚ ይሞክሩ።"
          : "Could not send. Please try again.");
  } finally {
    btn.disabled = false;
  }
});

/* ---------- QR ---------- */
const publicUrl = window.location.origin + "/";
try {
  const qr = qrcode(0, "M");
  qr.addData(publicUrl);
  qr.make();
  $("#qrBox").innerHTML = `<img src="${qr.createDataURL(8, 4)}" alt="QR code to invitation">`;
} catch (e) { console.warn("QR failed", e); }

$("#copyLink").onclick = async () => {
  try {
    await navigator.clipboard.writeText(publicUrl);
    toast(document.documentElement.lang === "am" ? "ሊንክ ተገልብጧል" : "Link copied");
  } catch { toast("Copy failed"); }
};
$("#shareBtn").onclick = async () => {
  const shareData = {
    title: "EDOM & Yohi — Wedding Invitation",
    text: "You are warmly invited to the wedding of Edom & Yohi.",
    url: publicUrl
  };
  if (navigator.share) {
    try { await navigator.share(shareData); } catch {}
  } else {
    try { await navigator.clipboard.writeText(publicUrl); toast("Link copied"); }
    catch { toast("Share not supported"); }
  }
};

/* ---------- reveal ---------- */
const io = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("on"); io.unobserve(e.target); } });
}, { threshold: 0.12 });
$$(".rv").forEach(el => io.observe(el));
<\/script>
</body>
</html>`;

/* Admin panel HTML */
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — EDOM & Yohi</title>
<style>
:root{--black:#080808;--gold:#D4AF37;--gold2:#F3E3A8;--line:rgba(212,175,55,.25);--text:#EDE3D0;--muted:#A89880;--red:#e0796f;--green:#7dd3a0}
*{box-sizing:border-box}
body{margin:0;background:var(--black);color:var(--text);font-family:Montserrat,system-ui,sans-serif;font-weight:300;min-height:100vh;padding:24px 16px}
.wrap{max-width:900px;margin:0 auto}
h1{font-family:Georgia,serif;color:var(--gold);font-weight:400;text-align:center;margin:0 0 6px}
.sub{text-align:center;color:var(--muted);font-size:13px;margin:0 0 24px}
.card{border:1px solid var(--line);border-radius:14px;padding:24px;background:rgba(255,255,255,.02);margin-bottom:18px}
input,button,textarea{font:inherit;font-size:14px}
input[type=password],input[type=file]{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#111;color:var(--text);margin-bottom:10px}
button{cursor:pointer;border-radius:999px;padding:10px 20px;border:1px solid var(--gold);background:var(--gold);color:#000;font-weight:600;letter-spacing:.5px;transition:.25s}
button:hover{background:transparent;color:var(--gold)}
button.ghost{background:transparent;color:var(--gold)}
button.ghost:hover{background:var(--gold);color:#000}
button.danger{border-color:var(--red);background:transparent;color:var(--red)}
button.danger:hover{background:var(--red);color:#000}
button.small{padding:6px 12px;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.tabs{display:flex;gap:8px;margin-bottom:18px}
.tabs button{flex:1}
.tabs button.active{background:var(--gold);color:#000}
.hidden{display:none!important}
.photo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-top:14px}
.photo{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#111}
.photo img{width:100%;aspect-ratio:1;object-fit:cover;display:block}
.photo .info{padding:10px;display:flex;flex-direction:column;gap:6px}
.photo .hero-tag{font-size:10px;letter-spacing:1px;color:var(--gold);text-transform:uppercase}
.wish{border-left:2px solid var(--gold);padding:12px 16px;border-radius:0 10px 10px 0;background:rgba(255,255,255,.02);margin-bottom:10px}
.wish .n{color:var(--gold);font-weight:600;margin:0 0 4px}
.wish .e{color:var(--muted);font-size:12px;margin:0 0 6px}
.wish .m{margin:0 0 8px;white-space:pre-wrap;line-height:1.55}
.wish .meta{font-size:11px;color:var(--muted);margin-bottom:8px}
.wish .badge{display:inline-block;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:3px 8px;border-radius:999px;margin-left:6px}
.wish .badge.ok{background:rgba(125,211,160,.15);color:var(--green)}
.wish .badge.pending{background:rgba(212,175,55,.15);color:var(--gold)}
.msg{font-size:13px;margin:10px 0 0;min-height:1em}
.msg.err{color:var(--red)}.msg.ok{color:var(--green)}
</style>
</head>
<body>
<div class="wrap">
  <h1>EDOM &amp; Yohi — Admin</h1>
  <p class="sub">Private control panel. Not linked from the public invitation.</p>

  <!-- LOGIN -->
  <div id="loginView" class="card">
    <input id="pwd" type="password" placeholder="Admin password" autocomplete="current-password">
    <div class="row">
      <button id="loginBtn">Sign in</button>
      <button id="logoutBtn" class="ghost hidden">Sign out</button>
    </div>
    <p id="loginMsg" class="msg"></p>
  </div>

  <!-- DASHBOARD -->
  <div id="dashView" class="hidden">
    <div class="tabs">
      <button id="tabPhotos" class="active">Photos</button>
      <button id="tabWishes" class="ghost">Wishes</button>
    </div>

    <div id="photosPane" class="card">
      <h2 style="margin:0 0 10px;color:var(--gold);font-weight:400">Upload a photo</h2>
      <input type="file" id="file" accept="image/*">
      <div class="row">
        <button id="uploadBtn">Upload</button>
        <label style="display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px">
          <input type="checkbox" id="asHero"> Set as hero
        </label>
      </div>
      <p id="photoMsg" class="msg"></p>
      <div id="photoGrid" class="photo-grid"></div>
    </div>

    <div id="wishesPane" class="card hidden">
      <div class="row" style="justify-content:space-between;margin-bottom:12px">
        <h2 style="margin:0;color:var(--gold);font-weight:400">Guest wishes</h2>
        <button class="ghost small" id="refreshWishes">Refresh</button>
      </div>
      <div id="wishList"></div>
    </div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const msg = (el, text, type = "") => {
  const e = $(el); e.textContent = text; e.className = "msg " + type;
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ---------- session ---------- */
async function checkSession() {
  try {
    await api("/api/admin/me");
    showDash();
  } catch {
    $("#dashView").classList.add("hidden");
    $("#loginView").classList.remove("hidden");
  }
}

function showDash() {
  $("#loginView").classList.add("hidden");
  $("#dashView").classList.remove("hidden");
  loadPhotos();
  loadWishes();
}

$("#loginBtn").onclick = async () => {
  msg("#loginMsg", "");
  try {
    await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ password: $("#pwd").value })
    });
    $("#pwd").value = "";
    showDash();
  } catch (e) { msg("#loginMsg", e.message, "err"); }
};

$("#pwd").addEventListener("keydown", e => {
  if (e.key === "Enter") $("#loginBtn").click();
});

$("#logoutBtn").onclick = async () => {
  await api("/api/admin/logout", { method: "POST" });
  $("#dashView").classList.add("hidden");
  $("#loginView").classList.remove("hidden");
};

/* ---------- tabs ---------- */
$("#tabPhotos").onclick = () => {
  $("#tabPhotos").classList.add("active"); $("#tabPhotos").classList.remove("ghost");
  $("#tabWishes").classList.remove("active"); $("#tabWishes").classList.add("ghost");
  $("#photosPane").classList.remove("hidden"); $("#wishesPane").classList.add("hidden");
};
$("#tabWishes").onclick = () => {
  $("#tabWishes").classList.add("active"); $("#tabWishes").classList.remove("ghost");
  $("#tabPhotos").classList.remove("active"); $("#tabPhotos").classList.add("ghost");
  $("#wishesPane").classList.remove("hidden"); $("#photosPane").classList.add("hidden");
};

/* ---------- photos ---------- */
async function loadPhotos() {
  try {
    const photos = await api("/api/photos");
    const grid = $("#photoGrid"); grid.innerHTML = "";
    if (!photos.length) {
      grid.innerHTML = `<p style="color:var(--muted);font-size:13px">No photos yet.</p>`;
      return;
    }
    photos.forEach(p => {
      const card = document.createElement("div");
      card.className = "photo";
      card.innerHTML = `
        <img src="${p.url}" alt="">
        <div class="info">
          ${p.is_hero ? '<span class="hero-tag">★ Hero photo</span>' : ""}
          <div class="row">
            ${!p.is_hero ? '<button class="ghost small" data-hero>Set hero</button>' : ""}
            <button class="danger small" data-del>Delete</button>
          </div>
        </div>`;
      card.querySelector("[data-hero]")?.addEventListener("click", async () => {
        try { await api(\`/api/admin/photos/\${p.id}/hero\`, { method: "PATCH" }); loadPhotos(); }
        catch (e) { alert(e.message); }
      });
      card.querySelector("[data-del]").addEventListener("click", async () => {
        if (!confirm("Delete this photo permanently?")) return;
        try { await api(\`/api/admin/photos/\${p.id}\`, { method: "DELETE" }); loadPhotos(); }
        catch (e) { alert(e.message); }
      });
      grid.appendChild(card);
    });
  } catch (e) { console.warn(e); }
}

$("#uploadBtn").onclick = async () => {
  const file = $("#file").files[0];
  if (!file) return msg("#photoMsg", "Choose a file first.", "err");
  if (!file.type.startsWith("image/")) return msg("#photoMsg", "Only image files are allowed.", "err");
  if (file.size > 10 * 1024 * 1024) return msg("#photoMsg", "Maximum file size is 10 MB.", "err");

  $("#uploadBtn").disabled = true;
  msg("#photoMsg", "Uploading…");

  try {
    const sig = await api("/api/admin/cloudinary-signature", { method: "POST" });

    const fd = new FormData();
    fd.append("file", file);
    fd.append("api_key", sig.apiKey);
    fd.append("timestamp", sig.timestamp);
    fd.append("signature", sig.signature);
    fd.append("folder", sig.folder);

    const up = await fetch(\`https://api.cloudinary.com/v1_1/\${sig.cloudName}/image/upload\`, {
      method: "POST",
      body: fd
    });
    const data = await up.json();
    if (!up.ok) throw new Error(data.error?.message || "Cloudinary upload failed");

    await api("/api/admin/photos", {
      method: "POST",
      body: JSON.stringify({
        url: data.secure_url,
        publicId: data.public_id,
        isHero: $("#asHero").checked
      })
    });

    $("#file").value = "";
    $("#asHero").checked = false;
    msg("#photoMsg", "Photo uploaded successfully.", "ok");
    loadPhotos();
  } catch (e) {
    msg("#photoMsg", e.message, "err");
  } finally {
    $("#uploadBtn").disabled = false;
  }
};

/* ---------- wishes ---------- */
async function loadWishes() {
  try {
    const wishes = await api("/api/admin/wishes");
    const list = $("#wishList"); list.innerHTML = "";
    if (!wishes.length) {
      list.innerHTML = `<p style="color:var(--muted);font-size:13px">No wishes yet.</p>`;
      return;
    }
    wishes.forEach(w => {
      const card = document.createElement("div");
      card.className = "wish";
      card.innerHTML = `
        <p class="n">\${escapeHtml(w.name)}
          <span class="badge \${w.approved ? "ok" : "pending"}">\${w.approved ? "Approved" : "Pending"}</span>
        </p>
        \${w.email ? \`<p class="e">\${escapeHtml(w.email)}</p>\` : ""}
        <p class="m">\${escapeHtml(w.message)}</p>
        <p class="meta">\${new Date(w.created_at).toUTCString()} · #\${w.id}</p>
        <div class="row">
          \${!w.approved ? '<button class="small" data-approve>Approve</button>' : ""}
          <button class="danger small" data-del>Delete</button>
        </div>`;
      card.querySelector("[data-approve]")?.addEventListener("click", async () => {
        try { await api(\`/api/admin/wishes/\${w.id}/approve\`, { method: "PATCH" }); loadWishes(); }
        catch (e) { alert(e.message); }
      });
      card.querySelector("[data-del]").addEventListener("click", async () => {
        if (!confirm("Delete this wish permanently?")) return;
        try { await api(\`/api/admin/wishes/\${w.id}\`, { method: "DELETE" }); loadWishes(); }
        catch (e) { alert(e.message); }
      });
      list.appendChild(card);
    });
  } catch (e) { console.warn(e); }
}

$("#refreshWishes").onclick = loadWishes;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

checkSession();
<\/script>
</body>
</html>`;

/* ============================================================================
   ROUTES
   ============================================================================ */
app.get("/admin", (_req, res) => res.type("html").send(ADMIN_HTML));
app.get("*", (_req, res) => res.type("html").send(PUBLIC_HTML));

/* ============================================================================
   START
   ============================================================================ */
initDb().finally(() => {
  app.listen(PORT, () => console.log(`EDOM & YOHI listening on :${PORT}`));
});