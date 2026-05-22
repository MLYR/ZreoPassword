const path = require("path");
const Database = require("better-sqlite3");

const DB_FILE_NAME = "vault.sqlite3";
const SCHEMA_VERSION = 1;

let db = null;

function getDb(app) {
  if (db) return db;
  const dbPath = path.join(app.getPath("userData"), DB_FILE_NAME);
  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  initSchema(db);
  return db;
}

function initSchema(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS vault_meta (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL,
      salt TEXT NOT NULL,
      iterations INTEGER NOT NULL,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS records (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      url TEXT NOT NULL DEFAULT '',
      host TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL,
      accountTag TEXT NOT NULL DEFAULT '',
      loginMethod TEXT NOT NULL DEFAULT 'password',
      usernameIndex TEXT NOT NULL DEFAULT '',
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL,
      iv TEXT NOT NULL,
      encryptedContent TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_records_category ON records(category);
    CREATE INDEX IF NOT EXISTS idx_records_host ON records(host);
    CREATE INDEX IF NOT EXISTS idx_records_updated ON records(updatedAt);

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );
  `);
}

function getMeta(app) {
  return getDb(app).prepare("SELECT * FROM vault_meta WHERE id = 1").get() || null;
}

function initializeVault(app, meta) {
  const database = getDb(app);
  const now = new Date().toISOString();
  const existing = getMeta(app);
  if (existing) return existing;

  const row = {
    version: SCHEMA_VERSION,
    salt: String(meta.salt || ""),
    iterations: Number(meta.iterations || 210000),
    createdAt: meta.createdAt || now,
    updatedAt: meta.updatedAt || now
  };

  database.prepare(`
    INSERT INTO vault_meta (id, version, salt, iterations, createdAt, updatedAt)
    VALUES (1, @version, @salt, @iterations, @createdAt, @updatedAt)
  `).run(row);
  return getMeta(app);
}

function updateMeta(app, meta) {
  const database = getDb(app);
  const existing = getMeta(app);
  if (!existing) {
    return initializeVault(app, meta);
  }

  database.prepare(`
    UPDATE vault_meta
    SET salt = @salt, iterations = @iterations, updatedAt = @updatedAt
    WHERE id = 1
  `).run({
    salt: String(meta.salt || existing.salt),
    iterations: Number(meta.iterations || existing.iterations),
    updatedAt: meta.updatedAt || new Date().toISOString()
  });
  return getMeta(app);
}

function hasRecords(app) {
  const row = getDb(app).prepare("SELECT COUNT(*) AS count FROM records").get();
  return Number(row.count) > 0;
}

function listRecords(app) {
  return getDb(app).prepare(`
    SELECT id, title, url, host, category, accountTag, loginMethod, usernameIndex, createdAt, updatedAt, iv, encryptedContent
    FROM records
    ORDER BY datetime(updatedAt) DESC, title COLLATE NOCASE ASC
  `).all();
}

function replaceAllRecords(app, records) {
  const database = getDb(app);
  const tx = database.transaction((items) => {
    database.prepare("DELETE FROM records").run();
    const insert = prepareRecordUpsert(database);
    items.forEach((record) => insert.run(normalizeRecordRow(record)));
    touchMeta(database);
  });
  tx(Array.isArray(records) ? records : []);
  return listRecords(app);
}

function upsertRecords(app, records) {
  const database = getDb(app);
  const tx = database.transaction((items) => {
    const insert = prepareRecordUpsert(database);
    items.forEach((record) => insert.run(normalizeRecordRow(record)));
    touchMeta(database);
  });
  tx(Array.isArray(records) ? records : []);
  return listRecords(app);
}

function deleteRecords(app, ids) {
  const database = getDb(app);
  const tx = database.transaction((recordIds) => {
    const stmt = database.prepare("DELETE FROM records WHERE id = ?");
    recordIds.forEach((id) => stmt.run(String(id)));
    touchMeta(database);
  });
  tx(Array.isArray(ids) ? ids : []);
  return listRecords(app);
}

function getSetting(app, key) {
  const row = getDb(app).prepare("SELECT value FROM settings WHERE key = ?").get(String(key));
  return row ? row.value : null;
}

function setSetting(app, key, value) {
  const now = new Date().toISOString();
  getDb(app).prepare(`
    INSERT INTO settings (key, value, updatedAt)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = excluded.updatedAt
  `).run(String(key), String(value), now);
  return { key: String(key), value: String(value) };
}

function prepareRecordUpsert(database) {
  return database.prepare(`
    INSERT INTO records (
      id, title, url, host, category, accountTag, loginMethod, usernameIndex,
      createdAt, updatedAt, iv, encryptedContent
    ) VALUES (
      @id, @title, @url, @host, @category, @accountTag, @loginMethod, @usernameIndex,
      @createdAt, @updatedAt, @iv, @encryptedContent
    )
    ON CONFLICT(id) DO UPDATE SET
      title = excluded.title,
      url = excluded.url,
      host = excluded.host,
      category = excluded.category,
      accountTag = excluded.accountTag,
      loginMethod = excluded.loginMethod,
      usernameIndex = excluded.usernameIndex,
      createdAt = excluded.createdAt,
      updatedAt = excluded.updatedAt,
      iv = excluded.iv,
      encryptedContent = excluded.encryptedContent
  `);
}

function normalizeRecordRow(record) {
  return {
    id: String(record.id || ""),
    title: String(record.title || "未命名"),
    url: String(record.url || ""),
    host: String(record.host || ""),
    category: String(record.category || "未分类"),
    accountTag: String(record.accountTag || ""),
    loginMethod: String(record.loginMethod || "password"),
    usernameIndex: String(record.usernameIndex || ""),
    createdAt: String(record.createdAt || new Date().toISOString()),
    updatedAt: String(record.updatedAt || new Date().toISOString()),
    iv: String(record.iv || ""),
    encryptedContent: String(record.encryptedContent || "")
  };
}

function touchMeta(database) {
  database.prepare("UPDATE vault_meta SET updatedAt = ? WHERE id = 1").run(new Date().toISOString());
}

module.exports = {
  getMeta,
  initializeVault,
  updateMeta,
  hasRecords,
  listRecords,
  replaceAllRecords,
  upsertRecords,
  deleteRecords,
  getSetting,
  setSetting
};
