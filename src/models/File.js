const db = require('./database');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const config = require('../config');
const encryptionService = require('../services/encryptionService');

class File {
  /**
   * Create a new file record
   * @param {Object} fileData - File data
   * @returns {Object} Created file
   */
  static create({ originalName, encryptedName, mimeType, originalSize, encryptedSize, fileHash, ownerId }) {
    const uuid = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO files (uuid, original_name, encrypted_name, mime_type, original_size, encrypted_size, file_hash, owner_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(uuid, originalName, encryptedName, mimeType, originalSize, encryptedSize, fileHash, ownerId);
    return this.findById(result.lastInsertRowid);
  }

  /**
   * Find file by ID
   * @param {number} id - File ID
   * @returns {Object|null}
   */
  static findById(id) {
    const stmt = db.prepare(`
      SELECT f.*, u.username as owner_username 
      FROM files f 
      JOIN users u ON f.owner_id = u.id 
      WHERE f.id = ? AND f.is_deleted = 0
    `);
    return stmt.get(id);
  }

  /**
   * Find file by UUID
   * @param {string} uuid - File UUID
   * @returns {Object|null}
   */
  static findByUuid(uuid) {
    const stmt = db.prepare(`
      SELECT f.*, u.username as owner_username 
      FROM files f 
      JOIN users u ON f.owner_id = u.id 
      WHERE f.uuid = ? AND f.is_deleted = 0
    `);
    return stmt.get(uuid);
  }

  /**
   * Get all files for a user
   * @param {number} userId - User ID
   * @param {Object} options - Pagination options
   * @returns {Array}
   */
  static findByOwner(userId, { limit = 50, offset = 0 } = {}) {
    const stmt = db.prepare(`
      SELECT f.*, u.username as owner_username 
      FROM files f 
      JOIN users u ON f.owner_id = u.id 
      WHERE f.owner_id = ? AND f.is_deleted = 0 
      ORDER BY f.created_at DESC 
      LIMIT ? OFFSET ?
    `);
    return stmt.all(userId, limit, offset);
  }

  /**
   * Get files shared with a user
   * @param {number} userId - User ID
   * @param {Object} options - Pagination options
   * @returns {Array}
   */
  static findSharedWithUser(userId, { limit = 50, offset = 0 } = {}) {
    const stmt = db.prepare(`
      SELECT f.*, u.username as owner_username, fp.permission
      FROM files f 
      JOIN users u ON f.owner_id = u.id 
      JOIN file_permissions fp ON f.id = fp.file_id
      WHERE fp.user_id = ? AND f.is_deleted = 0 
        AND (fp.expires_at IS NULL OR fp.expires_at > CURRENT_TIMESTAMP)
      ORDER BY f.created_at DESC 
      LIMIT ? OFFSET ?
    `);
    return stmt.all(userId, limit, offset);
  }

  /**
   * Check if user has access to file
   * @param {number} fileId - File ID
   * @param {number} userId - User ID
   * @param {string} requiredPermission - Required permission level
   * @returns {boolean}
   */
  static hasAccess(fileId, userId, requiredPermission = 'read') {
    // Check if user is owner
    const file = this.findById(fileId);
    if (!file) return false;
    if (file.owner_id === userId) return true;

    // Check permissions
    const permissionLevels = { read: 1, write: 2, admin: 3 };
    const stmt = db.prepare(`
      SELECT permission FROM file_permissions 
      WHERE file_id = ? AND user_id = ? 
        AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    `);
    const permission = stmt.get(fileId, userId);
    
    if (!permission) return false;
    return permissionLevels[permission.permission] >= permissionLevels[requiredPermission];
  }

  /**
   * Soft delete a file
   * @param {number} id - File ID
   * @returns {boolean}
   */
  static delete(id) {
    const stmt = db.prepare('UPDATE files SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Permanently delete a file
   * @param {number} id - File ID
   * @returns {boolean}
   */
  static async permanentDelete(id) {
    const file = this.findById(id);
    if (!file) return false;

    // Delete encrypted file from disk
    const filePath = path.join(config.upload.path, file.encrypted_name);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database
    const stmt = db.prepare('DELETE FROM files WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Get file statistics for a user
   * @param {number} userId - User ID
   * @returns {Object}
   */
  static getStats(userId) {
    const stmt = db.prepare(`
      SELECT 
        COUNT(*) as total_files,
        COALESCE(SUM(original_size), 0) as total_original_size,
        COALESCE(SUM(encrypted_size), 0) as total_encrypted_size
      FROM files 
      WHERE owner_id = ? AND is_deleted = 0
    `);
    return stmt.get(userId);
  }
}

module.exports = File;
