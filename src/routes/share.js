const express = require('express');
const router = express.Router();
const shareController = require('../controllers/shareController');
const { optionalAuth } = require('../middleware/auth');
const { shareLinkValidation } = require('../middleware/validation');

/**
 * @route   GET /api/share/:token
 * @desc    Get share link info
 * @access  Public
 */
router.get('/:token', optionalAuth, shareController.getShareInfo);

/**
 * @route   POST /api/share/:token/download
 * @desc    Download file via share link
 * @access  Public
 */
router.post('/:token/download', optionalAuth, shareController.downloadShared);

module.exports = router;
