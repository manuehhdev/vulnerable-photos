-- VulnerablePhotos schema.
-- Passwords are stored in PLAINTEXT on purpose (CWE-256) so SQL injection /
-- prototype-pollution dumps yield directly usable credentials for the lab.

DROP TABLE IF EXISTS photos;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  email TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  avatar TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  filename TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
