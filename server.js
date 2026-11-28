/* ============================================================================
   EDOM & YOHI — WEDDING SIGNBOARD & INVITATION
   Native Node.js server (http + fs) — no dependencies
   ============================================================================ */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

/* ---------- MIME types ---------- */
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":  "image/gif",
  ".svg":  "image/svg+xml",
  ".ico":  "image/x-icon",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2":"font/woff2"
};

/* ---------- File serving with proper error handling ---------- */
function serveFile(res, filePath, statusCode = 200) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || "application/octet-stream";

  fs.readFile(filePath, (err, data) => {
    if (err) return sendError(res, 404, "Page not found");

    const cacheControl = ext === ".html"
      ? "no-cache"
      : "public, max-age=86400";

    res.writeHead(statusCode, {
      "Content-Type": contentType,
      "Cache-Control": cacheControl,
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN"
    });
    res.end(data);
  });
}

function sendError(res, code, message) {
  res.writeHead(code, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${code} — Not Found</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0B132B;color:#EDE3D0;font-family:Georgia,serif;text-align:center;padding:24px}
  h1{font-size:80px;color:#C5A059;margin:0}
  p{font-size:18px;color:#A89880}
  a{color:#C5A059;text-decoration:none;border-bottom:1px solid #C5A059;padding-bottom:2px}
</style></head>
<body><div><h1>${code}</h1><p>${message}</p>
<a href="/">Return home</a></div></body></html>`);
}

/* ---------- Request handler ---------- */
const server = http.createServer((req, res) => {
  /* Log every request (useful for debugging on Render) */
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url}`);

  /* Only allow GET and HEAD */
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD" });
    return res.end("Method Not Allowed");
  }

  /* Parse and clean URL */
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    return sendError(res, 400, "Invalid URL");
  }

  /* Default route */
  if (pathname === "/" || pathname === "") {
    pathname = "/index.html";
  }

  /* Prevent directory traversal */
  const requestedPath = path.normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, requestedPath);
  const resolvedPath = path.resolve(filePath);

  if (!resolvedPath.startsWith(path.resolve(PUBLIC_DIR))) {
    return sendError(res, 403, "Forbidden");
  }

  /* Try to serve the file */
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      /* Try /index.html for SPA-style routes */
      const fallback = path.join(PUBLIC_DIR, "index.html");
      fs.stat(fallback, (err2, stats2) => {
        if (!err2 && stats2.isFile()) return serveFile(res, fallback);
        return sendError(res, 404, "Page not found");
      });
      return;
    }
    serveFile(res, filePath);
  });
});

/* ---------- Startup ---------- */
server.listen(PORT, "0.0.0.0", () => {
  console.log(`✨ Edom & Yohi wedding site running on port ${PORT}`);
  console.log(`   Serving files from: ${PUBLIC_DIR}`);
});

/* ---------- Graceful shutdown ---------- */
function shutdown(signal) {
  console.log(`${signal} received — shutting down...`);
  server.close(() => {
    console.log("Shutdown complete.");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

/* ---------- Safety net ---------- */
process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});