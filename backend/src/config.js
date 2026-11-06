const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const projectRoot = path.resolve(__dirname, '../..');
const port = Number(process.env.PORT || 4000);
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 20 * 1024 * 1024);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}
if (!Number.isSafeInteger(maxUploadBytes) || maxUploadBytes < 1) {
  throw new Error('MAX_UPLOAD_BYTES must be a positive safe integer.');
}

function resolveDataPath(value, fallback) {
  const configured = value || fallback;
  return path.isAbsolute(configured) ? configured : path.resolve(projectRoot, configured);
}

module.exports = {
  port,
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  databasePath: resolveDataPath(process.env.DATABASE_PATH, './data/snovasys.sqlite'),
  uploadDir: resolveDataPath(process.env.UPLOAD_DIR, './data/uploads'),
  maxUploadBytes,
  frontendDist: path.resolve(projectRoot, 'frontend/dist')
};
