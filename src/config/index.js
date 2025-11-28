require('dotenv').config();
const crypto = require('crypto');

// Generate a secure key if not provided
const generateSecureKey = () => {
  return crypto.randomBytes(32).toString('hex').slice(0, 32);
};

const config = {
  // Server
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',

  // JWT
  jwt: {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  },

  // Encryption (AES-256-CBC)
  encryption: {
    algorithm: 'aes-256-cbc',
    key: process.env.ENCRYPTION_KEY || generateSecureKey(),
    ivLength: parseInt(process.env.ENCRYPTION_IV_LENGTH) || 16
  },

  // File Upload
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024, // 50MB default
    path: process.env.UPLOAD_PATH || './uploads',
    allowedMimeTypes: [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/plain',
      'text/csv',
      'image/jpeg',
      'image/png',
      'image/gif'
      // Note: ZIP files excluded for security - could contain malicious content
    ]
  },

  // Database
  database: {
    path: process.env.DB_PATH || './data/storage.db'
  },

  // Rate Limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  }
};

module.exports = config;
