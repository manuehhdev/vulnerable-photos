const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// NOTE: no foreign_keys / WAL hardening — kept minimal on purpose for this lab.
const DB_PATH = path.join(__dirname, '..', 'db', 'gallery.db');
const db = new sqlite3.Database(DB_PATH);

module.exports = db;
