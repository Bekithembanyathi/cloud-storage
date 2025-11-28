const db = require('./database');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

class Permission {
  /**
   * Grant permission to a user for a file
   * @param {Object} data - Permission data
   * @returns {Object}
   */
  static grant({ fileId, userId, permission, grantedBy, expiresAt = null }) {
    const stmt = db.prepare(`
      INSERT INTO file_permissions (file_id, user_id, permission, granted_by, expires_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(file_id, user_id) 
      DO UPDATE SET permission = excluded.permission, expires_at = excluded.expires_at
    `);
    stmt.run(fileId, userId, permission, grantedBy, expiresAt);
    return this.findByFileAndUser(fileId, userId);
  }

  /**
   * Revoke permission
   * @param {number} fileId - File ID
   * @param {number} userId - User ID
   * @returns {boolean}
   */
  static revoke(fileId, userId) {
    const stmt = db.prepare('DELETE FROM file_permissions WHERE file_id = ? AND user_id = ?');
    const result = stmt.run(fileId, userId);
    return result.changes > 0;
  }

  /**
   * Find permission by file and user
   * @param {number} fileId - File ID
   * @param {number} userId - User ID
   * @returns {Object|null}
   */
  static findByFileAndUser(fileId, userId) {
    const stmt = db.prepare(`
      SELECT fp.*, u.username 
      FROM file_permissions fp
      JOIN users u ON fp.user_id = u.id
      WHERE fp.file_id = ? AND fp.user_id = ?
    `);
    return stmt.get(fileId, userId);
  }

  /**
   * Get all permissions for a file
   * @param {number} fileId - File ID
   * @returns {Array}
   */
  static findByFile(fileId) {
    const stmt = db.prepare(`
      SELECT fp.*, u.username, u.email
      FROM file_permissions fp
      JOIN users u ON fp.user_id = u.id
      WHERE fp.file_id = ?
      ORDER BY fp.created_at DESC
    `);
    return stmt.all(fileId);
  }
}

class ShareLink {
  /**
   * Create a share link
   * @param {Object} data - Share link data
   * @returns {Object}
   */
  static create({ fileId, createdBy, password = null, maxDownloads = null, expiresAt = null }) {
    const shareToken = crypto.randomBytes(32).toString('hex');
    const passwordHash = password ? bcrypt.hashSync(password, 10) : null;
    
    const stmt = db.prepare(`
      INSERT INTO share_links (file_id, share_token, created_by, password_hash, max_downloads, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(fileId, shareToken, createdBy, passwordHash, maxDownloads, expiresAt);
    return this.findById(result.lastInsertRowid);
  }

  /**
   * Find share link by ID
   * @param {number} id - Share link ID
   * @returns {Object|null}
   */
  static findById(id) {
    const stmt = db.prepare(`
      SELECT sl.*, f.original_name, f.mime_type, f.original_size
      FROM share_links sl
      JOIN files f ON sl.file_id = f.id
      WHERE sl.id = ?
    `);
    return stmt.get(id);
  }

  /**
   * Find share link by token
   * @param {string} token - Share token
   * @returns {Object|null}
   */
  static findByToken(token) {
    const stmt = db.prepare(`
      SELECT sl.*, f.original_name, f.mime_type, f.original_size, f.encrypted_name, f.uuid as file_uuid
      FROM share_links sl
      JOIN files f ON sl.file_id = f.id
      WHERE sl.share_token = ? AND sl.is_active = 1 AND f.is_deleted = 0
    `);
    return stmt.get(token);
  }

  /**
   * Validate share link (check expiry, downloads, password)
   * @param {Object} shareLink - Share link object
   * @param {string} password - Password if required
   * @returns {{ valid: boolean, error?: string }}
   */
  static validate(shareLink, password = null) {
    if (!shareLink) {
      return { valid: false, error: 'Share link not found' };
    }

    if (shareLink.expires_at && new Date(shareLink.expires_at) < new Date()) {
      return { valid: false, error: 'Share link has expired' };
    }

    if (shareLink.max_downloads && shareLink.download_count >= shareLink.max_downloads) {
      return { valid: false, error: 'Download limit reached' };
    }

    if (shareLink.password_hash) {
      if (!password) {
        return { valid: false, error: 'Password required' };
      }
      if (!bcrypt.compareSync(password, shareLink.password_hash)) {
        return { valid: false, error: 'Invalid password' };
      }
    }

    return { valid: true };
  }

  /**
   * Increment download count
   * @param {number} id - Share link ID
   * @returns {boolean}
   */
  static incrementDownload(id) {
    const stmt = db.prepare('UPDATE share_links SET download_count = download_count + 1 WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Deactivate share link
   * @param {number} id - Share link ID
   * @returns {boolean}
   */
  static deactivate(id) {
    const stmt = db.prepare('UPDATE share_links SET is_active = 0 WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Get all share links for a file
   * @param {number} fileId - File ID
   * @returns {Array}
   */
  static findByFile(fileId) {
    const stmt = db.prepare(`
      SELECT id, share_token, max_downloads, download_count, expires_at, is_active, created_at,
             CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END as has_password
      FROM share_links 
      WHERE file_id = ?
      ORDER BY created_at DESC
    `);
    return stmt.all(fileId);
  }
}

class AuditLog {
  /**
   * Create an audit log entry
   * @param {Object} data - Audit log data
   * @returns {Object}
   */
  static create({ userId, action, resourceType = null, resourceId = null, ipAddress = null, userAgent = null, details = null }) {
    const stmt = db.prepare(`
      INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(userId, action, resourceType, resourceId, ipAddress, userAgent, details ? JSON.stringify(details) : null);
    return this.findById(result.lastInsertRowid);
  }

  /**
   * Find audit log by ID
   * @param {number} id - Audit log ID
   * @returns {Object|null}
   */
  static findById(id) {
    const stmt = db.prepare('SELECT * FROM audit_logs WHERE id = ?');
    const log = stmt.get(id);
    if (log && log.details) {
      log.details = JSON.parse(log.details);
    }
    return log;
  }

  /**
   * Get audit logs for a user
   * @param {number} userId - User ID
   * @param {Object} options - Query options
   * @returns {Array}
   */
  static findByUser(userId, { limit = 100, offset = 0 } = {}) {
    const stmt = db.prepare(`
      SELECT * FROM audit_logs 
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(userId, limit, offset).map(log => {
      if (log.details) log.details = JSON.parse(log.details);
      return log;
    });
  }

  /**
   * Get recent audit logs (admin)
   * @param {Object} options - Query options
   * @returns {Array}
   */
  static findRecent({ limit = 100, offset = 0, action = null } = {}) {
    let query = `
      SELECT al.*, u.username
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
    `;
    const params = [];

    if (action) {
      query += ' WHERE al.action = ?';
      params.push(action);
    }

    query += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const stmt = db.prepare(query);
    return stmt.all(...params).map(log => {
      if (log.details) log.details = JSON.parse(log.details);
      return log;
    });
  }
}

module.exports = { Permission, ShareLink, AuditLog };
