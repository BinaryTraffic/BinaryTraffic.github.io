-- Add email column to users (nullable for existing users).
-- SQLite cannot ADD COLUMN with UNIQUE; uniqueness is enforced by the index below.
ALTER TABLE users ADD COLUMN email TEXT;

-- Create verification codes table (supports email/SMS channels)
CREATE TABLE IF NOT EXISTS verification_codes (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL,           -- 'email' or 'sms' (future)
  recipient TEXT NOT NULL,         -- email address or phone number
  code_hash TEXT NOT NULL,         -- SHA-256 hash of the code
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  user_id TEXT,                    -- NULL for signup, set for recovery
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Rate limiting: track recent sends per recipient
CREATE TABLE IF NOT EXISTS verification_sends (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL,
  recipient TEXT NOT NULL,
  ip_address TEXT,
  sent_at INTEGER NOT NULL
);

-- Indexes for performance and cleanup
CREATE INDEX IF NOT EXISTS idx_verification_codes_recipient ON verification_codes(recipient, channel);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires ON verification_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_verification_sends_recipient ON verification_sends(recipient, channel, sent_at);
CREATE INDEX IF NOT EXISTS idx_verification_sends_ip ON verification_sends(ip_address, sent_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
