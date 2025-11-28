const path = require('path');
const fs = require('fs');
const config = require('../config');
const { ShareLink, AuditLog } = require('../models/Permission');
const encryptionService = require('../services/encryptionService');

/**
 * Get share link info (without downloading)
 */
const getShareInfo = async (req, res) => {
  try {
    const { token } = req.params;

    const shareLink = ShareLink.findByToken(token);
    if (!shareLink) {
      return res.status(404).json({
        success: false,
        error: 'Share link not found or expired'
      });
    }

    // Basic validation (without password check for info)
    if (shareLink.expires_at && new Date(shareLink.expires_at) < new Date()) {
      return res.status(410).json({
        success: false,
        error: 'Share link has expired'
      });
    }

    if (shareLink.max_downloads && shareLink.download_count >= shareLink.max_downloads) {
      return res.status(410).json({
        success: false,
        error: 'Download limit reached'
      });
    }

    res.json({
      success: true,
      data: {
        fileName: shareLink.original_name,
        fileSize: shareLink.original_size,
        mimeType: shareLink.mime_type,
        requiresPassword: !!shareLink.password_hash,
        downloadsRemaining: shareLink.max_downloads 
          ? shareLink.max_downloads - shareLink.download_count 
          : null,
        expiresAt: shareLink.expires_at
      }
    });
  } catch (err) {
    console.error('Get share info error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get share info'
    });
  }
};

/**
 * Download file via share link
 */
const downloadShared = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const shareLink = ShareLink.findByToken(token);
    if (!shareLink) {
      return res.status(404).json({
        success: false,
        error: 'Share link not found'
      });
    }

    // Validate share link
    const validation = ShareLink.validate(shareLink, password);
    if (!validation.valid) {
      // Log failed access
      AuditLog.create({
        userId: req.user?.id || null,
        action: 'SHARE_LINK_ACCESS_FAILED',
        resourceType: 'share_link',
        resourceId: shareLink.id.toString(),
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { error: validation.error }
      });

      return res.status(403).json({
        success: false,
        error: validation.error
      });
    }

    const encryptedPath = path.join(config.upload.path, shareLink.encrypted_name);

    if (!fs.existsSync(encryptedPath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found on storage'
      });
    }

    // Decrypt file
    const decrypted = await encryptionService.decryptFile(encryptedPath);

    // Increment download count
    ShareLink.incrementDownload(shareLink.id);

    // Log download
    AuditLog.create({
      userId: req.user?.id || null,
      action: 'SHARE_LINK_DOWNLOAD',
      resourceType: 'share_link',
      resourceId: shareLink.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { filename: shareLink.original_name }
    });

    // Send file
    res.set({
      'Content-Type': shareLink.mime_type,
      'Content-Disposition': `attachment; filename="${shareLink.original_name}"`,
      'Content-Length': decrypted.length
    });
    res.send(decrypted);
  } catch (err) {
    console.error('Download shared error:', err);
    res.status(500).json({
      success: false,
      error: 'Download failed'
    });
  }
};

module.exports = {
  getShareInfo,
  downloadShared
};
