require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const dbModule = require('./db');
const { startBackupSchedule } = require('./backup');

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
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'nombre, email y password son requeridos' });
    }
    const condFinal = condominio || 'Sin asignar';
    const sectFinal = sector     || 'Sin asignar';

    const existe = dbModule.get('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (existe) {
      if (!condominio && !sector) {
        const token = jwt.sign(
          { id: existe.id, nombre: existe.nombre, email: existe.email, condominio: existe.condominio, sector: existe.sector, rol: existe.rol },
          SECRET, { expiresIn: '30d' }
        );
        return res.json({ token, nombre: existe.nombre, condominio: existe.condominio, sector: existe.sector });
      }
      return res.status(409).json({ error: 'Email ya registrado' });
    }

    const hash = bcrypt.hashSync(password, 10);
    dbModule.run(
      'INSERT INTO usuarios (nombre, email, password, condominio, sector) VALUES (?,?,?,?,?)',
      [nombre, email, hash, condFinal, sectFinal]
    );
    const id = dbModule.lastInsertId();
    const token = jwt.sign({ id, nombre, email, condominio: condFinal, sector: sectFinal, rol: 'usuario' }, SECRET, { expiresIn: '30d' });
    res.json({ token, nombre, condominio: condFinal, sector: sectFinal });
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

// PUT /api/auth/perfil
app.put('/api/auth/perfil', authMiddleware, (req, res) => {
  try {
    const { condominio, sector } = req.body;
    if (!condominio || !sector) {
      return res.status(400).json({ error: 'condominio y sector son requeridos' });
    }
    dbModule.run('UPDATE usuarios SET condominio = ?, sector = ? WHERE id = ?',
      [condominio, sector, req.user.id]);

    const usuario = dbModule.get('SELECT id, nombre, email, condominio, sector, rol FROM usuarios WHERE id = ?', [req.user.id]);
    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, email: usuario.email, condominio: usuario.condominio, sector: usuario.sector, rol: usuario.rol },
      SECRET, { expiresIn: '30d' }
    );
    res.json({ ok: true, token, usuario });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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

    const dispositivo = dbModule.getDispositivo(device_id);
    const condFinal   = dispositivo?.condominio        || condominio || userPayload.condominio;
    const sectFinal   = dispositivo?.sector            || sector     || userPayload.sector;
    const zonaFinal   = dispositivo?.sector_geografico || null;
    const pisoFinal   = dispositivo?.piso              || null;

    dbModule.run(
      `INSERT INTO sesiones (device_id, usuario_id, condominio, sector, sector_geografico, piso, cant_latas, bat_pct, fecha)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [device_id, userPayload.id, condFinal, sectFinal, zonaFinal, pisoFinal,
       cant_latas, bat_pct || null, fecha || new Date().toISOString()]
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

// ===== DISPOSITIVOS (maquinas) =====

app.post('/api/dispositivos', authMiddleware, (req, res) => {
  try {
    const { device_id, nombre, condominio, sector, sector_geografico, piso, lat, lng } = req.body;
    if (!device_id || !condominio || !sector || !sector_geografico) {
      return res.status(400).json({ error: 'device_id, condominio, sector y sector_geografico son requeridos' });
    }
    const existe = dbModule.getDispositivo(device_id);
    if (existe) {
      dbModule.run(
        `UPDATE dispositivos SET nombre=?, condominio=?, sector=?, sector_geografico=?, piso=?, lat=?, lng=?
         WHERE device_id=?`,
        [nombre || existe.nombre, condominio, sector, sector_geografico,
         piso ?? existe.piso, lat ?? existe.lat, lng ?? existe.lng, device_id]
      );
    } else {
      dbModule.run(
        `INSERT INTO dispositivos (device_id, nombre, condominio, sector, sector_geografico, piso, lat, lng)
         VALUES (?,?,?,?,?,?,?,?)`,
        [device_id, nombre || device_id, condominio, sector, sector_geografico, piso || null, lat || null, lng || null]
      );
    }
    res.json({ ok: true, dispositivo: dbModule.getDispositivo(device_id) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/dispositivos', authMiddleware, (req, res) => {
  try {
    res.json(dbModule.all('SELECT * FROM dispositivos ORDER BY creado_en DESC'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== STATS POR CONDOMINIO Y POR ZONA =====

app.get('/api/stats/condominio/:nombre', authMiddleware, (req, res) => {
  try {
    const { nombre } = req.params;
    const { anio, mes } = req.query;
    let where = 'condominio = ?';
    const params = [nombre];
    if (anio && mes) {
      where += ' AND fecha LIKE ?';
      params.push(`${anio}-${String(mes).padStart(2,'0')}%`);
    }
    const totales = dbModule.get(
      `SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE ${where}`,
      params
    );
    const porSector = dbModule.all(
      `SELECT sector, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${where} GROUP BY sector ORDER BY total_latas DESC`,
      params
    );
    res.json({
      condominio: nombre,
      anio: anio || null, mes: mes || null,
      total_latas: totales?.total_latas || 0,
      total_sesiones: totales?.total_sesiones || 0,
      por_sector: porSector
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stats/zona/:nombre', authMiddleware, (req, res) => {
  try {
    const { nombre } = req.params;
    const { anio, mes } = req.query;
    let where = 'sector_geografico = ?';
    const params = [nombre];
    if (anio && mes) {
      where += ' AND fecha LIKE ?';
      params.push(`${anio}-${String(mes).padStart(2,'0')}%`);
    }
    const totales = dbModule.get(
      `SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE ${where}`,
      params
    );
    const porCondominio = dbModule.all(
      `SELECT condominio, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${where} GROUP BY condominio ORDER BY total_latas DESC`,
      params
    );
    res.json({
      zona: nombre,
      anio: anio || null, mes: mes || null,
      total_latas: totales?.total_latas || 0,
      total_sesiones: totales?.total_sesiones || 0,
      por_condominio: porCondominio
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== MAPA =====

app.get('/api/mapa', authMiddleware, (req, res) => {
  try {
    const ahora   = new Date();
    const prefijo = `${ahora.getFullYear()}-${String(ahora.getMonth()+1).padStart(2,'0')}`;

    const dispositivos = dbModule.all('SELECT * FROM dispositivos');
    const resultado = dispositivos.map(d => {
      const totalHist = dbModule.get(
        'SELECT SUM(cant_latas) as total FROM sesiones WHERE device_id = ?',
        [d.device_id]
      );
      const totalMes = dbModule.get(
        'SELECT SUM(cant_latas) as total FROM sesiones WHERE device_id = ? AND fecha LIKE ?',
        [d.device_id, `${prefijo}%`]
      );
      return {
        device_id: d.device_id,
        nombre: d.nombre,
        condominio: d.condominio,
        sector: d.sector,
        sector_geografico: d.sector_geografico,
        piso: d.piso,
        lat: d.lat,
        lng: d.lng,
        total_latas_historico: totalHist?.total || 0,
        total_latas_mes_actual: totalMes?.total || 0
      };
    });
    res.json(resultado);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== STATS ANUAL, SEMESTRAL, BATERIA =====

app.get('/api/stats/anual', authMiddleware, (req, res) => {
  try {
    const { anio } = req.query;
    if (!anio) return res.status(400).json({ error: 'anio requerido' });
    const ranking = dbModule.all(
      `SELECT sector, condominio, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE fecha LIKE ? GROUP BY sector, condominio ORDER BY total_latas DESC`,
      [`${anio}%`]
    );
    const totales = dbModule.get(
      'SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE fecha LIKE ?',
      [`${anio}%`]
    );
    const porMes = dbModule.all(
      `SELECT strftime('%m', fecha) as mes, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE fecha LIKE ? GROUP BY mes ORDER BY mes ASC`,
      [`${anio}%`]
    );
    res.json({
      anio,
      total_latas: totales?.total_latas || 0,
      total_sesiones: totales?.total_sesiones || 0,
      por_mes: porMes,
      ranking
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stats/semestral', authMiddleware, (req, res) => {
  try {
    const { anio, semestre } = req.query;
    if (!anio || !semestre) return res.status(400).json({ error: 'anio y semestre requeridos' });
    const meses = semestre === '1'
      ? ['01','02','03','04','05','06']
      : ['07','08','09','10','11','12'];
    const placeholders = meses.map(() => `fecha LIKE ?`).join(' OR ');
    const params = meses.map(m => `${anio}-${m}%`);
    const totales = dbModule.get(
      `SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE ${placeholders}`,
      params
    );
    const ranking = dbModule.all(
      `SELECT sector, condominio, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${placeholders} GROUP BY sector, condominio ORDER BY total_latas DESC`,
      params
    );
    const porMes = dbModule.all(
      `SELECT strftime('%m', fecha) as mes, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${placeholders} GROUP BY mes ORDER BY mes ASC`,
      params
    );
    res.json({
      anio, semestre: parseInt(semestre), meses_incluidos: meses,
      total_latas: totales?.total_latas || 0,
      total_sesiones: totales?.total_sesiones || 0,
      por_mes: porMes, ranking
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/dispositivos/bateria', authMiddleware, (req, res) => {
  try {
    const baterias = dbModule.all(
      `SELECT s.device_id, d.nombre, d.condominio, d.sector,
              s.bat_pct, s.fecha as ultima_sesion
       FROM sesiones s
       JOIN dispositivos d ON d.device_id = s.device_id
       WHERE s.id IN (
         SELECT MAX(id) FROM sesiones WHERE bat_pct IS NOT NULL GROUP BY device_id
       )
       ORDER BY s.bat_pct ASC`
    );
    res.json(baterias);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== REPORTE POR RANGO DE FECHAS =====

// GET /api/stats/rango?desde=2026-01-01&hasta=2026-06-30&sector=X&condominio=Y
app.get('/api/stats/rango', authMiddleware, (req, res) => {
  try {
    const { desde, hasta, sector, condominio } = req.query;
    if (!desde || !hasta) return res.status(400).json({ error: 'desde y hasta son requeridos' });

    let where = "fecha >= ? AND fecha <= ?";
    const params = [desde, hasta + 'T23:59:59'];

    if (sector && sector !== 'todos') {
      where += ' AND sector = ?';
      params.push(sector);
    }
    if (condominio && condominio !== 'todos') {
      where += ' AND condominio = ?';
      params.push(condominio);
    }

    const totales = dbModule.get(
      `SELECT SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones FROM sesiones WHERE ${where}`,
      params
    );
    const porMes = dbModule.all(
      `SELECT strftime('%Y-%m', fecha) as mes, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${where} GROUP BY mes ORDER BY mes ASC`,
      params
    );
    const porSector = dbModule.all(
      `SELECT sector, condominio, SUM(cant_latas) as total_latas, COUNT(*) as total_sesiones
       FROM sesiones WHERE ${where} GROUP BY sector, condominio ORDER BY total_latas DESC`,
      params
    );
    const sectoresDisponibles = dbModule.all('SELECT DISTINCT sector FROM sesiones WHERE sector IS NOT NULL ORDER BY sector');
    const condominiosDisponibles = dbModule.all('SELECT DISTINCT condominio FROM sesiones WHERE condominio IS NOT NULL ORDER BY condominio');

    res.json({
      desde, hasta,
      sector: sector || 'todos',
      condominio: condominio || 'todos',
      total_latas: totales?.total_latas || 0,
      total_sesiones: totales?.total_sesiones || 0,
      kg_reciclados: ((totales?.total_latas || 0) * 0.015).toFixed(2),
      por_mes: porMes,
      por_sector: porSector,
      sectores_disponibles: sectoresDisponibles.map(s => s.sector),
      condominios_disponibles: condominiosDisponibles.map(c => c.condominio)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== INICIAR SERVIDOR =====
dbModule.getDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Abollalatas API corriendo en http://localhost:${PORT}`);
  });
  startBackupSchedule();
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
