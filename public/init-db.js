import "dotenv/config";
import pg from "pg";

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false }
});

const SQL = `
CREATE TABLE IF NOT EXISTS photos (
  id          SERIAL PRIMARY KEY,
  url         TEXT NOT NULL,
  public_id   TEXT,
  is_hero     BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wishes (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(80) NOT NULL,
  email       VARCHAR(160),
  message     TEXT NOT NULL,
  approved    BOOLEAN DEFAULT FALSE,
  dup_hash    VARCHAR(64) NOT NULL,
  ip_hash     VARCHAR(64),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wishes_approved ON wishes(approved, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wishes_dup ON wishes(dup_hash, created_at DESC);
`;

try {
  await pool.query(SQL);
  console.log("✅ Database schema ready.");
  process.exit(0);
} catch (err) {
  console.error("❌ Schema init failed:", err.message);
  process.exit(1);
}