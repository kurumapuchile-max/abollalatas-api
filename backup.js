const fs = require('fs');

const DB_PATH      = process.env.DB_FILE || './abollalatas.db';
const GITHUB_TOKEN = process.env.BACKUP_GITHUB_TOKEN;
const BACKUP_REPO  = process.env.BACKUP_REPO;   // ej: "kurumapuchile-max/abollalatas-backup"
const BACKUP_BRANCH = process.env.BACKUP_BRANCH || 'main';

// Sube una copia de la base de datos al repo privado de backup en GitHub.
// Cada dia se crea un archivo nuevo con la fecha, asi queda historial.
async function backupToGitHub() {
  if (!GITHUB_TOKEN || !BACKUP_REPO) {
    console.log('[backup] Variables BACKUP_GITHUB_TOKEN o BACKUP_REPO no configuradas, backup omitido.');
    return;
  }

  try {
    if (!fs.existsSync(DB_PATH)) {
      console.log('[backup] No existe el archivo de base de datos todavia, backup omitido.');
      return;
    }

    const fecha = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const path  = `backups/abollalatas-${fecha}.db`;
    const content = fs.readFileSync(DB_PATH).toString('base64');

    const url = `https://api.github.com/repos/${BACKUP_REPO}/contents/${path}`;

    // Revisar si ya existe un backup de hoy (para actualizarlo en vez de duplicar)
    let sha;
    const existing = await fetch(url + `?ref=${BACKUP_BRANCH}`, {
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json'
      }
    });
    if (existing.status === 200) {
      const data = await existing.json();
      sha = data.sha;
    }

    const resp = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: `Backup automatico ${fecha}`,
        content,
        branch: BACKUP_BRANCH,
        ...(sha ? { sha } : {})
      })
    });

    if (resp.ok) {
      console.log(`[backup] Backup subido correctamente: ${path}`);
    } else {
      const err = await resp.text();
      console.error(`[backup] Error subiendo backup (${resp.status}):`, err);
    }
  } catch (e) {
    console.error('[backup] Error inesperado:', e.message);
  }
}

// Programa el backup para correr cada 24 horas, y una vez al iniciar (con un pequeño delay).
function startBackupSchedule() {
  setTimeout(backupToGitHub, 60 * 1000); // primer backup 1 minuto despues de iniciar
  setInterval(backupToGitHub, 24 * 60 * 60 * 1000); // luego cada 24 horas
}

module.exports = { backupToGitHub, startBackupSchedule };
