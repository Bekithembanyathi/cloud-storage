const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Mock the config for testing
jest.mock('../src/config', () => ({
  encryption: {
    algorithm: 'aes-256-cbc',
    key: '12345678901234567890123456789012', // 32-char test key
    ivLength: 16
  }
}));

const encryptionService = require('../src/services/encryptionService');

describe('Encryption Service', () => {
  describe('Text Encryption', () => {
    test('should encrypt and decrypt text correctly', () => {
      const originalText = 'Hello, this is sensitive data!';
      const encrypted = encryptionService.encryptText(originalText);
      const decrypted = encryptionService.decryptText(encrypted);
      
      expect(decrypted).toBe(originalText);
    });

    test('encrypted text should be different from original', () => {
      const originalText = 'Secret message';
      const encrypted = encryptionService.encryptText(originalText);
      
      expect(encrypted).not.toBe(originalText);
      expect(encrypted).toContain(':'); // IV:encrypted format
    });

    test('same text should produce different encrypted values (due to random IV)', () => {
      const text = 'Test message';
      const encrypted1 = encryptionService.encryptText(text);
      const encrypted2 = encryptionService.encryptText(text);
      
      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe('Buffer Encryption', () => {
    test('should encrypt and decrypt buffer correctly', () => {
      const originalBuffer = Buffer.from('Binary data content', 'utf-8');
      const encrypted = encryptionService.encryptBuffer(originalBuffer);
      const decrypted = encryptionService.decryptBuffer(encrypted);
      
      expect(decrypted.toString('utf-8')).toBe('Binary data content');
    });

    test('encrypted buffer should be larger than original (includes IV)', () => {
      const originalBuffer = Buffer.from('Test data');
      const encrypted = encryptionService.encryptBuffer(originalBuffer);
      
      expect(encrypted.length).toBeGreaterThan(originalBuffer.length);
    });
  });

  describe('File Encryption', () => {
    const testDir = path.join(__dirname, 'temp');
    const sourcePath = path.join(testDir, 'source.txt');
    const encryptedPath = path.join(testDir, 'encrypted.enc');

    beforeAll(() => {
      if (!fs.existsSync(testDir)) {
        fs.mkdirSync(testDir, { recursive: true });
      }
    });

    afterAll(() => {
      if (fs.existsSync(testDir)) {
        fs.rmSync(testDir, { recursive: true });
      }
    });

    test('should encrypt and decrypt file correctly', async () => {
      const originalContent = 'This is the content of a test file for encryption.';
      fs.writeFileSync(sourcePath, originalContent);

      // Encrypt
      const { size, hash } = await encryptionService.encryptFile(sourcePath, encryptedPath);
      
      expect(size).toBeGreaterThan(0);
      expect(hash).toBeDefined();
      expect(hash.length).toBe(64); // SHA-256 hash length

      // Verify encrypted file exists and is different
      const encryptedContent = fs.readFileSync(encryptedPath);
      expect(encryptedContent.toString()).not.toBe(originalContent);

      // Decrypt
      const decrypted = await encryptionService.decryptFile(encryptedPath);
      expect(decrypted.toString('utf-8')).toBe(originalContent);
    });

    test('should generate consistent file hash', async () => {
      const content = 'Consistent content for hash testing';
      fs.writeFileSync(sourcePath, content);

      const hash1 = await encryptionService.generateFileHash(sourcePath);
      const hash2 = await encryptionService.generateFileHash(sourcePath);

      expect(hash1).toBe(hash2);
      expect(hash1.length).toBe(64);
    });
  });
});
