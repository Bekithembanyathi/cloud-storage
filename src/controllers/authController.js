const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const { AuditLog } = require('../models/Permission');

/**
 * Register a new user
 */
const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    if (User.findByUsername(username)) {
      return res.status(400).json({
        success: false,
        error: 'Username already exists'
      });
    }

    if (User.findByEmail(email)) {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

    // Create user
    const user = User.create({ username, email, password });

    // Log registration
    AuditLog.create({
      userId: user.id,
      action: 'USER_REGISTER',
      resourceType: 'user',
      resourceId: user.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Generate token
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        token
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
};

/**
 * Login user
 */
const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = User.findByUsername(username);
    if (!user) {
      // Log failed attempt
      AuditLog.create({
        userId: null,
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        resourceId: username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { reason: 'User not found' }
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Check if account is active
    if (!user.is_active) {
      return res.status(401).json({
        success: false,
        error: 'Account is deactivated'
      });
    }

    // Verify password
    if (!User.verifyPassword(password, user.password_hash)) {
      // Log failed attempt
      AuditLog.create({
        userId: user.id,
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        resourceId: user.id.toString(),
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { reason: 'Invalid password' }
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    // Log successful login
    AuditLog.create({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      resourceType: 'user',
      resourceId: user.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        token
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
};

/**
 * Get current user profile
 */
const getProfile = async (req, res) => {
  try {
    const user = User.findById(req.user.id);
    const File = require('../models/File');
    const stats = File.getStats(req.user.id);

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          createdAt: user.created_at
        },
        stats: {
          totalFiles: stats.total_files,
          totalStorageUsed: stats.total_original_size
        }
      }
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile'
    });
  }
};

/**
 * Update password
 */
const updatePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password hash
    const user = User.findByUsername(req.user.username);

    // Verify current password
    if (!User.verifyPassword(currentPassword, user.password_hash)) {
      return res.status(400).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    // Update password
    User.updatePassword(req.user.id, newPassword);

    // Log password change
    AuditLog.create({
      userId: req.user.id,
      action: 'PASSWORD_CHANGE',
      resourceType: 'user',
      resourceId: req.user.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update password'
    });
  }
};

/**
 * Logout (client-side token removal, server-side audit)
 */
const logout = async (req, res) => {
  try {
    // Log logout
    AuditLog.create({
      userId: req.user.id,
      action: 'LOGOUT',
      resourceType: 'user',
      resourceId: req.user.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
};

module.exports = {
  register,
  login,
  getProfile,
  updatePassword,
  logout
};
