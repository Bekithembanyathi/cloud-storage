const express = require('express');
const router = express.Router();

const authRoutes = require('./auth');
const fileRoutes = require('./files');
const shareRoutes = require('./share');

router.use('/auth', authRoutes);
router.use('/files', fileRoutes);
router.use('/share', shareRoutes);

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Secure Cloud Storage API is running',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
