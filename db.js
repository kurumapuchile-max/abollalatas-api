const knex = require('knex');
const path = require('path');

const db = knex({
  client: 'sqlite3',
  connection: {
    filename: process.env.DB_FILE || './abollalatas.db'
  },
  useNullAsDefault: true
});

async function initDB() {
  // Usuarios
  const hasUsuarios = await db.schema.hasTable('usuarios');
  if (!hasUsuarios) {
    await db.schema.createTable('usuarios', t => {
      t.increments('id').primary();
      t.string('nombre').notNullable();
      t.string('email').notNullable().unique();
      t.string('password').notNullable();
      t.string('condominio').notNullable();
      t.string('sector').notNullable();
      t.string('rol').notNullable().defaultTo('usuario');
      t.timestamp('creado_en').defaultTo(db.fn.now());
    });
    console.log('Tabla usuarios creada');
  }

  // Dispositivos
  const hasDispositivos = await db.schema.hasTable('dispositivos');
  if (!hasDispositivos) {
    await db.schema.createTable('dispositivos', t => {
      t.increments('id').primary();
      t.string('device_id').notNullable().unique();
      t.string('condominio').notNullable();
      t.string('sector').notNullable();
      t.integer('activo').notNullable().defaultTo(1);
      t.timestamp('creado_en').defaultTo(db.fn.now());
    });
    console.log('Tabla dispositivos creada');
  }

  // Sesiones
  const hasSesiones = await db.schema.hasTable('sesiones');
  if (!hasSesiones) {
    await db.schema.createTable('sesiones', t => {
      t.increments('id').primary();
      t.string('device_id').notNullable();
      t.integer('usuario_id').notNullable().references('id').inTable('usuarios');
      t.string('condominio').notNullable();
      t.string('sector').notNullable();
      t.integer('cant_latas').notNullable().defaultTo(0);
      t.integer('bat_pct');
      t.string('fecha').notNullable();
      t.timestamp('creado_en').defaultTo(db.fn.now());
    });
    console.log('Tabla sesiones creada');
  }
}

module.exports = { db, initDB };
