const fs = require('fs');
const path = require('path');
const db = require('../lib/db');

const SCHEMA_PATH = path.join(__dirname, 'schema.sql');
const SAMPLE_DIR = path.join(__dirname, '..', 'sample-images');
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');

const USERS = [
  { username: 'alice', password: 'alice123', email: 'alice@example.com', is_admin: 0 },
  { username: 'bob', password: 'bob123', email: 'bob@example.com', is_admin: 0 },
  { username: 'admin', password: 'admin123', email: 'admin@vulnerablephotos.local', is_admin: 1 },
];

// owner index refers to USERS array above
const PHOTOS = [
  { owner: 0, title: 'Beach Sunset', description: 'Golden hour at the coast.', file: 'beach-01.svg' },
  { owner: 0, title: 'Mountain Hike', description: 'Weekend trail with the dog.', file: 'hike-02.svg' },
  { owner: 0, title: 'My Cat', description: 'She knocked the vase over again.', file: 'cat-03.svg' },
  { owner: 1, title: 'Family BBQ', description: 'Fourth of July cookout.', file: 'family-04.svg' },
  { owner: 1, title: 'City Lights', description: 'Downtown at night.', file: 'city-05.svg' },
  { owner: 2, title: 'Server Room', description: 'Definitely not a photo of the racks (internal).', file: 'admin-06.svg' },
];

function run() {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

  const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
  db.exec(schema, (err) => {
    if (err) throw err;

    const insertUser = db.prepare(
      'INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)'
    );
    const userIds = [];
    USERS.forEach((u, i) => {
      insertUser.run(u.username, u.password, u.email, u.is_admin, function (err) {
        if (err) throw err;
        userIds[i] = this.lastID;
        if (i === USERS.length - 1) seedPhotos(userIds);
      });
    });
    insertUser.finalize();
  });
}

function seedPhotos(userIds) {
  const insertPhoto = db.prepare(
    'INSERT INTO photos (owner_id, title, description, filename) VALUES (?, ?, ?, ?)'
  );

  PHOTOS.forEach((p) => {
    const destName = `${Date.now()}-${p.file}`;
    fs.copyFileSync(path.join(SAMPLE_DIR, p.file), path.join(UPLOAD_DIR, destName));
    insertPhoto.run(userIds[p.owner], p.title, p.description, destName);
  });

  insertPhoto.finalize(() => {
    console.log('Seeded database:');
    console.log('  users: alice/alice123, bob/bob123, admin/admin123 (admin)');
    console.log(`  photos: ${PHOTOS.length} seeded into uploads/`);
    db.close();
  });
}

run();
