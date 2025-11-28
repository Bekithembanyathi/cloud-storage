const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const { AuditLog } = require('../models/Permission');

/**
 * Authentication middleware
 * Verifies JWT token and attaches user to request
 */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'No token provided. Authorization header must be: Bearer <token>'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    const user = User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }

    if (!user.is_active) {
      return res.status(401).json({
        success: false,
        error: 'Account is deactivated'
      });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token has expired'
      });
    }
    return res.status(401).json({
      success: false,
      error: 'Invalid token'
    });
  }
};

/**
 * Optional authentication
 * Attaches user to request if token is valid, but doesn't require it
 */
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    const user = User.findById(decoded.userId);
    if (user && user.is_active) {
      req.user = user;
    }
  } catch (err) {
    // Ignore errors for optional auth
  }
  
  next();
};

/**
 * Role-based authorization middleware
 * @param {...string} roles - Allowed roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      // Log unauthorized access attempt
      AuditLog.create({
        userId: req.user.id,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'endpoint',
        resourceId: req.originalUrl,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { requiredRoles: roles, userRole: req.user.role }
      });

      return res.status(403).json({
        success: false,
        error: 'Access denied. Insufficient permissions.'
      });
    }

    next();
  };
};

module.exports = { authenticate, optionalAuth, authorize };
