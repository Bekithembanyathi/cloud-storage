const { validationResult, body, param, query } = require('express-validator');

/**
 * Validation result handler
 */
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }
  next();
};

// User validation rules
const userValidation = {
  register: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores'),
    body('email')
      .isEmail()
      .withMessage('Please provide a valid email address')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    handleValidation
  ],
  login: [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    handleValidation
  ],
  updatePassword: [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('New password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    handleValidation
  ]
};

// File validation rules
const fileValidation = {
  uuid: [
    param('uuid')
      .isUUID(4)
      .withMessage('Invalid file identifier'),
    handleValidation
  ],
  share: [
    body('userId')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Invalid user ID'),
    body('permission')
      .optional()
      .isIn(['read', 'write', 'admin'])
      .withMessage('Permission must be read, write, or admin'),
    body('expiresAt')
      .optional()
      .isISO8601()
      .withMessage('Invalid date format'),
    handleValidation
  ],
  shareLink: [
    body('password')
      .optional()
      .isLength({ min: 4 })
      .withMessage('Password must be at least 4 characters'),
    body('maxDownloads')
      .optional()
      .isInt({ min: 1, max: 1000 })
      .withMessage('Max downloads must be between 1 and 1000'),
    body('expiresAt')
      .optional()
      .isISO8601()
      .withMessage('Invalid date format'),
    handleValidation
  ]
};

// Share link validation
const shareLinkValidation = {
  access: [
    param('token')
      .isLength({ min: 64, max: 64 })
      .withMessage('Invalid share token'),
    body('password')
      .optional()
      .isString()
      .withMessage('Password must be a string'),
    handleValidation
  ]
};

module.exports = {
  handleValidation,
  userValidation,
  fileValidation,
  shareLinkValidation
};
