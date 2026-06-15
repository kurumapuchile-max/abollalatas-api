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
    // condominio y sector son opcionales (ej: login con Google que aun no tiene perfil completo).
    // El usuario los completa despues en su perfil.
    const condFinal = condominio || 'Sin asignar';
    const sectFinal = sector     || 'Sin asignar';

    const existe = dbModule.get('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (existe) {
      // Si la peticion NO trae condominio/sector, es el flujo de "Continuar con Google":
      // Base44 reintenta este endpoint en cada login y genera una password aleatoria distinta
      // cada vez, asi que no podemos validarla. Como el email ya esta confirmado por Google,
      // simplemente devolvemos un token valido de la cuenta existente.
      if (!condominio && !sector) {
        const token = jwt.sign(
          { id: existe.id, nombre: existe.nombre, email: existe.email, condominio: existe.condominio, sector: existe.sector, rol: existe.rol },
          SECRET, { expiresIn: '30d' }
        );
        return res.json({ token, nombre: existe.nombre, condominio: existe.condominio, sector: existe.sector });
      }
      // Si SI trae condominio/sector, es un registro manual normal -> el email esta ocupado.
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

// PUT /api/auth/perfil  -> completar/actualizar condominio y sector (ej: tras login con Google)
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

    // Resolver ubicacion: si el device_id esta registrado en "dispositivos",
    // esa ubicacion fija manda por sobre lo que mande el ESP32 o la app.
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

// POST /api/dispositivos  -> crear o actualizar la ficha de una maquina
// body: { device_id, nombre, condominio, sector, sector_geografico, piso, lat, lng }
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

// GET /api/dispositivos -> listar todas las maquinas
app.get('/api/dispositivos', authMiddleware, (req, res) => {
  try {
    res.json(dbModule.all('SELECT * FROM dispositivos ORDER BY creado_en DESC'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== STATS POR CONDOMINIO Y POR ZONA =====

// GET /api/stats/condominio/:nombre?anio=2026&mes=6
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

// GET /api/stats/zona/:nombre?anio=2026&mes=6
// nombre = sector_geografico, ej. "Portal de la Frontera" o "Centro Temuco"
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

// GET /api/mapa -> todas las maquinas con coordenadas y sus totales (historico y mes actual)
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

// Iniciar servidor
dbModule.getDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Abollalatas API corriendo en http://localhost:${PORT}`);
  });
  startBackupSchedule();
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
