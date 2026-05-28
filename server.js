require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const { db, initDB } = require('./db');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev_secret_cambiar';

app.use(cors());
app.use(express.json());

// ── Middleware JWT ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  try {
    req.user = jwt.verify(header.slice(7), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

// ── AUTH ────────────────────────────────────────────────────

// POST /api/auth/registro
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, condominio, sector } = req.body;
    if (!nombre || !email || !password || !condominio || !sector) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }
    const hash = bcrypt.hashSync(password, 10);
    const [id] = await db('usuarios').insert({ nombre, email, password: hash, condominio, sector });
    const token = jwt.sign({ id, nombre, email, condominio, sector, rol: 'usuario' }, SECRET, { expiresIn: '30d' });
    res.json({ token, nombre, condominio, sector });
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email ya registrado' });
    }
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db('usuarios').where({ email }).first();
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, email: user.email,
        condominio: user.condominio, sector: user.sector, rol: user.rol },
      SECRET, { expiresIn: '30d' }
    );
    res.json({ token, nombre: user.nombre, condominio: user.condominio, sector: user.sector });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// ── SESIONES ────────────────────────────────────────────────

// POST /api/sesiones — recibe datos del ESP32
app.post('/api/sesiones', async (req, res) => {
  try {
    const { device_id, user_token, condominio, sector, fecha, cant_latas, bat_pct } = req.body;
    if (!device_id || !user_token || !cant_latas) {
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    let userPayload;
    try {
      userPayload = jwt.verify(user_token, SECRET);
    } catch {
      return res.status(401).json({ error: 'Token de usuario invalido' });
    }
    const [id] = await db('sesiones').insert({
      device_id,
      usuario_id:  userPayload.id,
      condominio:  condominio || userPayload.condominio,
      sector:      sector     || userPayload.sector,
      cant_latas,
      bat_pct:     bat_pct || null,
      fecha:       fecha || new Date().toISOString()
    });
    res.json({ ok: true, sesion_id: id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/sesiones/mias
app.get('/api/sesiones/mias', authMiddleware, async (req, res) => {
  try {
    const rows = await db('sesiones')
      .where({ usuario_id: req.user.id })
      .orderBy('fecha', 'desc')
      .limit(100)
      .select('id', 'fecha', 'cant_latas', 'condominio', 'sector', 'device_id');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/stats/mensual?anio=2026&mes=5
app.get('/api/stats/mensual', authMiddleware, async (req, res) => {
  try {
    const { anio, mes } = req.query;
    if (!anio || !mes) return res.status(400).json({ error: 'anio y mes requeridos' });
    const prefijo = `${anio}-${String(mes).padStart(2,'0')}`;

    const ranking = await db('sesiones')
      .where('fecha', 'like', `${prefijo}%`)
      .groupBy('sector', 'condominio')
      .select('sector', 'condominio')
      .sum('cant_latas as total_latas')
      .count('* as total_sesiones')
      .orderBy('total_latas', 'desc');

    const totales = await db('sesiones')
      .where('fecha', 'like', `${prefijo}%`)
      .sum('cant_latas as total_latas')
      .count('* as total_sesiones')
      .first();

    res.json({ anio, mes, ranking, totales });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/stats/mi-sector
app.get('/api/stats/mi-sector', authMiddleware, async (req, res) => {
  try {
    const ahora   = new Date();
    const prefijo = `${ahora.getFullYear()}-${String(ahora.getMonth()+1).padStart(2,'0')}`;

    const stats = await db('sesiones')
      .where({ usuario_id: req.user.id })
      .where('fecha', 'like', `${prefijo}%`)
      .sum('cant_latas as mis_latas')
      .count('* as mis_sesiones')
      .first();

    const sector = await db('sesiones')
      .where({ sector: req.user.sector, condominio: req.user.condominio })
      .where('fecha', 'like', `${prefijo}%`)
      .sum('cant_latas as latas_sector')
      .first();

    res.json({
      mes:          prefijo,
      mis_latas:    stats.mis_latas    || 0,
      mis_sesiones: stats.mis_sesiones || 0,
      latas_sector: sector.latas_sector || 0
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── START ───────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Abollalatas API corriendo en http://localhost:${PORT}`);
  });
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
