require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const dbModule = require('./db');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev_secret_cambiar';

app.use(cors());
app.use(express.json());

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

// POST /api/auth/registro
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, condominio, sector } = req.body;
    if (!nombre || !email || !password || !condominio || !sector) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }
    const existe = dbModule.get('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existe) return res.status(409).json({ error: 'Email ya registrado' });

    const hash = bcrypt.hashSync(password, 10);
    dbModule.run(
      'INSERT INTO usuarios (nombre, email, password, condominio, sector) VALUES (?,?,?,?,?)',
      [nombre, email, hash, condominio, sector]
    );
    const id = dbModule.lastInsertId();
    const token = jwt.sign({ id, nombre, email, condominio, sector, rol: 'usuario' }, SECRET, { expiresIn: '30d' });
    res.json({ token, nombre, condominio, sector });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = dbModule.get('SELECT * FROM usuarios WHERE email = ?', [email]);
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

// POST /api/sesiones
app.post('/api/sesiones', (req, res) => {
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
    dbModule.run(
      'INSERT INTO sesiones (device_id, usuario_id, condominio, sector, cant_latas, bat_pct, fecha) VALUES (?,?,?,?,?,?,?)',
      [device_id, userPayload.id,
       condominio || userPayload.condominio,
       sector     || userPayload.sector,
       cant_latas, bat_pct || null,
       fecha || new Date().toISOString()]
    );
    const id = dbModule.lastInsertId();
    res.json({ ok: true, sesion_id: id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/sesiones/mias
app.get('/api/sesiones/mias', authMiddleware, (req, res) => {
  try {
    const rows = dbModule.all(
      'SELECT id, fecha, cant_latas, condominio, sector, device_id FROM sesiones WHERE usuario_id = ? ORDER BY fecha DESC LIMIT 100',
      [req.user.id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/stats/mensual?anio=2026&mes=5
app.get('/api/stats/mensual', authMiddleware, (req, res) => {
  try {
    const { anio, mes } = req.query;
    if (!anio || !mes) return res.status(400).json({ error: 'anio y mes requeridos' });
    const prefijo = `${anio}-${String(mes).padStart(2,'0')}`;
    const ranking = dbModule.all(
      `SELECT sector, condominio, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE fecha LIKE ? GROUP BY sector, condominio ORDER BY total_latas DESC`,
      [`${prefijo}%`]
    );
    const totales = dbModule.get(
      'SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE fecha LIKE ?',
      [`${prefijo}%`]
    );
    res.json({ anio, mes, ranking, totales });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/stats/mi-sector
app.get('/api/stats/mi-sector', authMiddleware, (req, res) => {
  try {
    const ahora   = new Date();
    const prefijo = `${ahora.getFullYear()}-${String(ahora.getMonth()+1).padStart(2,'0')}`;
    const stats = dbModule.get(
      'SELECT SUM(cant_latas) as mis_latas, COUNT(*) as mis_sesiones FROM sesiones WHERE usuario_id = ? AND fecha LIKE ?',
      [req.user.id, `${prefijo}%`]
    );
    const sector = dbModule.get(
      'SELECT SUM(cant_latas) as latas_sector FROM sesiones WHERE sector = ? AND condominio = ? AND fecha LIKE ?',
      [req.user.sector, req.user.condominio, `${prefijo}%`]
    );
    res.json({
      mes:          prefijo,
      mis_latas:    stats?.mis_latas    || 0,
      mis_sesiones: stats?.mis_sesiones || 0,
      latas_sector: sector?.latas_sector || 0
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Iniciar servidor
dbModule.getDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Abollalatas API corriendo en http://localhost:${PORT}`);
  });
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
