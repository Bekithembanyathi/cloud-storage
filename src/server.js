const app = require('./app');
const config = require('./config');

const PORT = config.port;

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           🔒 SECURE CLOUD STORAGE SERVER                     ║
║                                                              ║
║   Server running on: http://localhost:${PORT}                   ║
║   Environment: ${config.nodeEnv.padEnd(45)}║
║                                                              ║
║   Security Features:                                         ║
║   ✓ AES-256-CBC File Encryption                              ║
║   ✓ JWT Authentication                                       ║
║   ✓ Role-Based Access Control                                ║
║   ✓ Rate Limiting                                            ║
║   ✓ Audit Logging                                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
