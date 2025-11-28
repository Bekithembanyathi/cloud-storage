const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const fileController = require('../controllers/fileController');
const { authenticate } = require('../middleware/auth');
const { fileValidation } = require('../middleware/validation');

// Ensure upload directory exists
if (!fs.existsSync(config.upload.path)) {
  fs.mkdirSync(config.upload.path, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tempDir = path.join(config.upload.path, 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    cb(null, tempDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${Date.now()}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Allow all file types by default, can be restricted via config
  if (config.upload.allowedMimeTypes.length > 0) {
    if (config.upload.allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} is not allowed`), false);
    }
  } else {
    cb(null, true);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.upload.maxFileSize
  }
});

// Error handler for multer
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: `File too large. Maximum size is ${config.upload.maxFileSize / (1024 * 1024)}MB`
      });
    }
    return res.status(400).json({
      success: false,
      error: err.message
    });
  } else if (err) {
    return res.status(400).json({
      success: false,
      error: err.message
    });
  }
  next();
};

/**
 * @route   POST /api/files/upload
 * @desc    Upload a file
 * @access  Private
 */
router.post('/upload', authenticate, upload.single('file'), handleMulterError, fileController.uploadFile);

/**
 * @route   GET /api/files
 * @desc    List user's files
 * @access  Private
 */
router.get('/', authenticate, fileController.listFiles);

/**
 * @route   GET /api/files/:uuid
 * @desc    Get file details
 * @access  Private
 */
router.get('/:uuid', authenticate, fileValidation.uuid, fileController.getFile);

/**
 * @route   GET /api/files/:uuid/download
 * @desc    Download a file
 * @access  Private
 */
router.get('/:uuid/download', authenticate, fileValidation.uuid, fileController.downloadFile);

/**
 * @route   DELETE /api/files/:uuid
 * @desc    Delete a file
 * @access  Private
 */
router.delete('/:uuid', authenticate, fileValidation.uuid, fileController.deleteFile);

/**
 * @route   POST /api/files/:uuid/share
 * @desc    Share file with another user
 * @access  Private
 */
router.post('/:uuid/share', authenticate, fileValidation.uuid, fileValidation.share, fileController.shareFile);

/**
 * @route   POST /api/files/:uuid/revoke
 * @desc    Revoke file access
 * @access  Private
 */
router.post('/:uuid/revoke', authenticate, fileValidation.uuid, fileController.revokeAccess);

/**
 * @route   POST /api/files/:uuid/share-link
 * @desc    Create a share link for a file
 * @access  Private
 */
router.post('/:uuid/share-link', authenticate, fileValidation.uuid, fileValidation.shareLink, fileController.createShareLink);

/**
 * @route   DELETE /api/files/share-link/:linkId
 * @desc    Deactivate a share link
 * @access  Private
 */
router.delete('/share-link/:linkId', authenticate, fileController.deactivateShareLink);

module.exports = router;
