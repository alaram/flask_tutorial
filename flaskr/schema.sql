DROP TABLE IF EXISTS user;

-- User table
CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  algo TEXT NOT NULL,
  mfa_metadata TEXT
);

-- MFA metadata
CREATE TABLE IF NOT EXISTS webauthn_credential (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,     -- base64url
    public_key TEXT NOT NULL,               -- base64 (COSE) or PEM encoded
    sign_count INTEGER DEFAULT 0,
    transports TEXT,                        -- JSON array string (optional)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
);
