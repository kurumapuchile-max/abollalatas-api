const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = process.env.DB_FILE || './abollalatas.db';

let db;

async function getDB() {
  if (db) return db;

  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre      TEXT    NOT NULL,
      email       TEXT    NOT NULL UNIQUE,
      password    TEXT    NOT NULL,
      condominio  TEXT    NOT NULL,
      sector      TEXT    NOT NULL,
      rol         TEXT    NOT NULL DEFAULT 'usuario',
      creado_en   TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sesiones (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id   TEXT    NOT NULL,
      usuario_id  INTEGER NOT NULL,
      condominio  TEXT    NOT NULL,
      sector      TEXT    NOT NULL,
      cant_latas  INTEGER NOT NULL DEFAULT 0,
      bat_pct     INTEGER,
      fecha       TEXT    NOT NULL,
      creado_en   TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS dispositivos (
      device_id          TEXT    PRIMARY KEY,
      nombre             TEXT,
      condominio         TEXT    NOT NULL,
      sector             TEXT    NOT NULL,
      sector_geografico  TEXT    NOT NULL,
      piso               TEXT,
      lat                REAL,
      lng                REAL,
      creado_en          TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Migracion suave: agregar columnas nuevas a sesiones si la DB ya existia
  // (sql.js no soporta "ADD COLUMN IF NOT EXISTS", por eso el try/catch)
  const migraciones = [
    `ALTER TABLE sesiones ADD COLUMN sector_geografico TEXT`,
    `ALTER TABLE sesiones ADD COLUMN piso TEXT`,
    `ALTER TABLE dispositivos ADD COLUMN nombre TEXT`,
    `ALTER TABLE dispositivos ADD COLUMN sector_geografico TEXT`,
    `ALTER TABLE dispositivos ADD COLUMN piso TEXT`,
    `ALTER TABLE dispositivos ADD COLUMN lat REAL`,
    `ALTER TABLE dispositivos ADD COLUMN lng REAL`
  ];
  for (const sql of migraciones) {
    try { db.run(sql); } catch (e) { /* columna ya existe, ignorar */ }
  }

  saveDB();
  console.log('Base de datos inicializada');
  return db;
}

function saveDB() {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

let lastId = null;

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();

  // Capturar el ultimo id insertado ANTES de exportar/guardar,
  // porque db.export() resetea last_insert_rowid().
  const idStmt = db.prepare('SELECT last_insert_rowid() as id');
  idStmt.bind([]);
  idStmt.step();
  lastId = idStmt.getAsObject().id;
  idStmt.free();

  saveDB();
}

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

function lastInsertId() {
  return lastId;
}

function getDispositivo(device_id) {
  return get('SELECT * FROM dispositivos WHERE device_id = ?', [device_id]);
}

module.exports = { getDB, run, get, all, lastInsertId, saveDB, getDispositivo };
