const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config');

class EncryptionService {
  constructor() {
    this.algorithm = config.encryption.algorithm;
    this.key = Buffer.from(config.encryption.key, 'utf-8');
    this.ivLength = config.encryption.ivLength;
  }

  /**
   * Encrypt a buffer and return encrypted data with IV prepended
   * @param {Buffer} buffer - Data to encrypt
   * @returns {Buffer} - IV + encrypted data
   */
  encryptBuffer(buffer) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
  }

  /**
   * Decrypt a buffer that has IV prepended
   * @param {Buffer} encryptedBuffer - IV + encrypted data
   * @returns {Buffer} - Decrypted data
   */
  decryptBuffer(encryptedBuffer) {
    const iv = encryptedBuffer.subarray(0, this.ivLength);
    const encryptedData = encryptedBuffer.subarray(this.ivLength);
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }

  /**
   * Encrypt a file and save to destination
   * @param {string} sourcePath - Path to source file
   * @param {string} destPath - Path to save encrypted file
   * @returns {Promise<{size: number, hash: string}>}
   */
  async encryptFile(sourcePath, destPath) {
    return new Promise((resolve, reject) => {
      const iv = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      const hash = crypto.createHash('sha256');

      const input = fs.createReadStream(sourcePath);
      const output = fs.createWriteStream(destPath);

      // Write IV first
      output.write(iv);

      let encryptedSize = iv.length;

      input.on('data', (chunk) => {
        hash.update(chunk);
      });

      input.pipe(cipher).pipe(output);

      output.on('finish', () => {
        fs.stat(destPath, (err, stats) => {
          if (err) reject(err);
          else resolve({
            size: stats.size,
            hash: hash.digest('hex')
          });
        });
      });

      output.on('error', reject);
      input.on('error', reject);
    });
  }

  /**
   * Decrypt a file and return as buffer
   * @param {string} encryptedPath - Path to encrypted file
   * @returns {Promise<Buffer>}
   */
  async decryptFile(encryptedPath) {
    return new Promise((resolve, reject) => {
      fs.readFile(encryptedPath, (err, data) => {
        if (err) return reject(err);
        try {
          const decrypted = this.decryptBuffer(data);
          resolve(decrypted);
        } catch (decryptErr) {
          reject(decryptErr);
        }
      });
    });
  }

  /**
   * Encrypt text data
   * @param {string} text - Text to encrypt
   * @returns {string} - Encrypted text in hex format
   */
  encryptText(text) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  }

  /**
   * Decrypt text data
   * @param {string} encryptedText - Encrypted text in hex format
   * @returns {string} - Decrypted text
   */
  decryptText(encryptedText) {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedData = parts[1];
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Generate a secure hash for a file
   * @param {string} filePath - Path to file
   * @returns {Promise<string>}
   */
  async generateFileHash(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const input = fs.createReadStream(filePath);
      input.on('data', (chunk) => hash.update(chunk));
      input.on('end', () => resolve(hash.digest('hex')));
      input.on('error', reject);
    });
  }
}

module.exports = new EncryptionService();
