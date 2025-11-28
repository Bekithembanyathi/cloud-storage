const db = require('./database');
const bcrypt = require('bcryptjs');

class User {
  /**
   * Create a new user
   * @param {Object} userData - User data
   * @returns {Object} Created user
   */
  static create({ username, email, password, role = 'user' }) {
    const passwordHash = bcrypt.hashSync(password, 12);
    const stmt = db.prepare(`
      INSERT INTO users (username, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(username, email.toLowerCase(), passwordHash, role);
    return this.findById(result.lastInsertRowid);
  }

  /**
   * Find user by ID
   * @param {number} id - User ID
   * @returns {Object|null} User object
   */
  static findById(id) {
    const stmt = db.prepare('SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE id = ?');
    return stmt.get(id);
  }

  /**
   * Find user by username
   * @param {string} username - Username
   * @returns {Object|null} User object with password hash
   */
  static findByUsername(username) {
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    return stmt.get(username);
  }

  /**
   * Find user by email
   * @param {string} email - Email address
   * @returns {Object|null} User object with password hash
   */
  static findByEmail(email) {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    return stmt.get(email.toLowerCase());
  }

  /**
   * Verify password
   * @param {string} password - Plain text password
   * @param {string} hash - Password hash
   * @returns {boolean}
   */
  static verifyPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
  }

  /**
   * Update user
   * @param {number} id - User ID
   * @param {Object} updates - Fields to update
   * @returns {Object} Updated user
   */
  static update(id, updates) {
    const allowedFields = ['username', 'email', 'role', 'is_active'];
    const fields = [];
    const values = [];

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        fields.push(`${key} = ?`);
        values.push(key === 'email' ? value.toLowerCase() : value);
      }
    }

    if (fields.length === 0) return this.findById(id);

    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);

    const stmt = db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`);
    stmt.run(...values);
    return this.findById(id);
  }

  /**
   * Update password
   * @param {number} id - User ID
   * @param {string} newPassword - New password
   * @returns {boolean}
   */
  static updatePassword(id, newPassword) {
    const passwordHash = bcrypt.hashSync(newPassword, 12);
    const stmt = db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    const result = stmt.run(passwordHash, id);
    return result.changes > 0;
  }

  /**
   * Delete user (soft delete)
   * @param {number} id - User ID
   * @returns {boolean}
   */
  static delete(id) {
    const stmt = db.prepare('UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Get all users (admin only)
   * @param {Object} options - Pagination options
   * @returns {Array} Users array
   */
  static findAll({ limit = 50, offset = 0 } = {}) {
    const stmt = db.prepare(`
      SELECT id, username, email, role, is_active, created_at, updated_at 
      FROM users 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset);
  }
}

module.exports = User;
