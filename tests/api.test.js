const request = require('supertest');
const fs = require('fs');
const path = require('path');

// Test user credentials
const testUser = {
  username: 'testuser',
  email: 'test@example.com',
  password: 'TestPass123!'
};

const testUser2 = {
  username: 'testuser2',
  email: 'test2@example.com',
  password: 'TestPass456!'
};

let app;
let authToken;
let authToken2;
let uploadedFileUuid;

describe('Secure Cloud Storage API', () => {
  // Clean up test database and uploads before tests
  beforeAll(async () => {
    // Clean up data and uploads
    const dbPath = './data/storage.db';
    const uploadsDir = './uploads';
    
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
    
    // Clear cache and re-require modules
    jest.resetModules();
    
    // Now require the app after cleanup
    app = require('../src/app');
    
    // Register users for subsequent tests
    const res1 = await request(app)
      .post('/api/auth/register')
      .send(testUser);
    authToken = res1.body.data?.token;

    const res2 = await request(app)
      .post('/api/auth/register')
      .send(testUser2);
    authToken2 = res2.body.data?.token;
  });

  // Auth Tests
  describe('Authentication', () => {
    test('POST /api/auth/register - should reject duplicate username', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    test('POST /api/auth/register - should validate password strength', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'weakpass',
          email: 'weak@example.com',
          password: 'weak'
        });

      expect(res.status).toBe(400);
    });

    test('POST /api/auth/login - should login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: testUser.username,
          password: testUser.password
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.token).toBeDefined();
      authToken = res.body.data.token;
    });

    test('POST /api/auth/login - should reject invalid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: testUser.username,
          password: 'wrongpassword'
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    test('GET /api/auth/profile - should return user profile', async () => {
      const res = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.username).toBe(testUser.username);
    });

    test('GET /api/auth/profile - should reject without token', async () => {
      const res = await request(app)
        .get('/api/auth/profile');

      expect(res.status).toBe(401);
    });
  });

  // File Tests
  describe('File Operations', () => {
    test('POST /api/files/upload - should upload and encrypt a file', async () => {
      const testFilePath = path.join(__dirname, 'test-file.txt');
      fs.writeFileSync(testFilePath, 'This is a test file for encryption testing');

      const res = await request(app)
        .post('/api/files/upload')
        .set('Authorization', `Bearer ${authToken}`)
        .attach('file', testFilePath);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.file.id).toBeDefined();
      uploadedFileUuid = res.body.data.file.id;

      // Clean up test file
      fs.unlinkSync(testFilePath);
    });

    test('GET /api/files - should list user files', async () => {
      const res = await request(app)
        .get('/api/files')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.owned.length).toBeGreaterThan(0);
    });

    test('GET /api/files/:uuid - should get file details', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileUuid}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.file.id).toBe(uploadedFileUuid);
    });

    test('GET /api/files/:uuid/download - should download and decrypt file', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileUuid}/download`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.text).toBe('This is a test file for encryption testing');
    });

    test('GET /api/files/:uuid - should deny access to other users', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileUuid}`)
        .set('Authorization', `Bearer ${authToken2}`);

      expect(res.status).toBe(403);
    });
  });

  // Sharing Tests
  describe('File Sharing', () => {
    test('POST /api/files/:uuid/share - should share file with another user', async () => {
      const res = await request(app)
        .post(`/api/files/${uploadedFileUuid}/share`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          username: testUser2.username,
          permission: 'read'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('GET /api/files/:uuid - shared user should now have access', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileUuid}`)
        .set('Authorization', `Bearer ${authToken2}`);

      expect(res.status).toBe(200);
      expect(res.body.data.file.isOwner).toBe(false);
    });

    test('POST /api/files/:uuid/share-link - should create share link', async () => {
      const res = await request(app)
        .post(`/api/files/${uploadedFileUuid}/share-link`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          password: 'sharepass123',
          maxDownloads: 5
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.shareLink.token).toBeDefined();
    });
  });

  // Security Tests
  describe('Security', () => {
    test('should reject requests with invalid tokens', async () => {
      const res = await request(app)
        .get('/api/files')
        .set('Authorization', 'Bearer invalid-token');

      expect(res.status).toBe(401);
    });

    test('should reject requests without authorization header', async () => {
      const res = await request(app)
        .get('/api/files');

      expect(res.status).toBe(401);
    });

    test('files should be encrypted on disk', () => {
      const uploadsDir = './uploads';
      if (fs.existsSync(uploadsDir)) {
        const files = fs.readdirSync(uploadsDir).filter(f => f.endsWith('.enc'));
        expect(files.length).toBeGreaterThan(0);
        
        // Verify encrypted file is not plaintext
        const encryptedContent = fs.readFileSync(path.join(uploadsDir, files[0]));
        expect(encryptedContent.toString()).not.toBe('This is a test file for encryption testing');
      }
    });
  });

  // File Deletion
  describe('File Deletion', () => {
    test('DELETE /api/files/:uuid - should delete file', async () => {
      const res = await request(app)
        .delete(`/api/files/${uploadedFileUuid}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('GET /api/files/:uuid - deleted file should not be accessible', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileUuid}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(404);
    });
  });

  // Health Check
  describe('Health Check', () => {
    test('GET /api/health - should return healthy status', async () => {
      const res = await request(app)
        .get('/api/health');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });
});
