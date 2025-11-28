const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const File = require('../models/File');
const User = require('../models/User');
const { Permission, ShareLink, AuditLog } = require('../models/Permission');
const encryptionService = require('../services/encryptionService');

/**
 * Upload a file
 */
const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file provided'
      });
    }

    const { originalname, mimetype, size, path: tempPath } = req.file;

    // Generate encrypted filename
    const encryptedName = `${uuidv4()}.enc`;
    const encryptedPath = path.join(config.upload.path, encryptedName);

    // Encrypt and save file
    const { hash } = await encryptionService.encryptFile(tempPath, encryptedPath);
    const encryptedStats = fs.statSync(encryptedPath);

    // Remove temp file
    fs.unlinkSync(tempPath);

    // Save to database
    const file = File.create({
      originalName: originalname,
      encryptedName: encryptedName,
      mimeType: mimetype,
      originalSize: size,
      encryptedSize: encryptedStats.size,
      fileHash: hash,
      ownerId: req.user.id
    });

    // Log upload
    AuditLog.create({
      userId: req.user.id,
      action: 'FILE_UPLOAD',
      resourceType: 'file',
      resourceId: file.uuid,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { filename: originalname, size }
    });

    res.status(201).json({
      success: true,
      message: 'File uploaded and encrypted successfully',
      data: {
        file: {
          id: file.uuid,
          name: file.original_name,
          mimeType: file.mime_type,
          size: file.original_size,
          createdAt: file.created_at
        }
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    // Clean up temp file if exists
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({
      success: false,
      error: 'File upload failed'
    });
  }
};

/**
 * List user's files
 */
const listFiles = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const ownedFiles = File.findByOwner(req.user.id, { limit, offset });
    const sharedFiles = File.findSharedWithUser(req.user.id, { limit, offset });

    res.json({
      success: true,
      data: {
        owned: ownedFiles.map(f => ({
          id: f.uuid,
          name: f.original_name,
          mimeType: f.mime_type,
          size: f.original_size,
          createdAt: f.created_at
        })),
        shared: sharedFiles.map(f => ({
          id: f.uuid,
          name: f.original_name,
          mimeType: f.mime_type,
          size: f.original_size,
          owner: f.owner_username,
          permission: f.permission,
          createdAt: f.created_at
        }))
      }
    });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to list files'
    });
  }
};

/**
 * Get file details
 */
const getFile = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check access
    if (!File.hasAccess(file.id, req.user.id, 'read')) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Get permissions if owner
    let permissions = [];
    let shareLinks = [];
    if (file.owner_id === req.user.id) {
      permissions = Permission.findByFile(file.id);
      shareLinks = ShareLink.findByFile(file.id);
    }

    res.json({
      success: true,
      data: {
        file: {
          id: file.uuid,
          name: file.original_name,
          mimeType: file.mime_type,
          size: file.original_size,
          owner: file.owner_username,
          isOwner: file.owner_id === req.user.id,
          createdAt: file.created_at
        },
        permissions: permissions.map(p => ({
          userId: p.user_id,
          username: p.username,
          permission: p.permission,
          expiresAt: p.expires_at
        })),
        shareLinks: shareLinks.map(s => ({
          id: s.id,
          token: s.share_token,
          hasPassword: s.has_password === 1,
          maxDownloads: s.max_downloads,
          downloadCount: s.download_count,
          expiresAt: s.expires_at,
          isActive: s.is_active === 1
        }))
      }
    });
  } catch (err) {
    console.error('Get file error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get file details'
    });
  }
};

/**
 * Download a file
 */
const downloadFile = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check access
    if (!File.hasAccess(file.id, req.user.id, 'read')) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const encryptedPath = path.join(config.upload.path, file.encrypted_name);

    if (!fs.existsSync(encryptedPath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found on storage'
      });
    }

    // Decrypt file
    const decrypted = await encryptionService.decryptFile(encryptedPath);

    // Log download
    AuditLog.create({
      userId: req.user.id,
      action: 'FILE_DOWNLOAD',
      resourceType: 'file',
      resourceId: file.uuid,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { filename: file.original_name }
    });

    // Send file
    res.set({
      'Content-Type': file.mime_type,
      'Content-Disposition': `attachment; filename="${file.original_name}"`,
      'Content-Length': decrypted.length
    });
    res.send(decrypted);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({
      success: false,
      error: 'File download failed'
    });
  }
};

/**
 * Delete a file
 */
const deleteFile = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Only owner can delete
    if (file.owner_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Only file owner can delete files'
      });
    }

    // Soft delete
    File.delete(file.id);

    // Log deletion
    AuditLog.create({
      userId: req.user.id,
      action: 'FILE_DELETE',
      resourceType: 'file',
      resourceId: file.uuid,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { filename: file.original_name }
    });

    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({
      success: false,
      error: 'File deletion failed'
    });
  }
};

/**
 * Share file with another user
 */
const shareFile = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check if user has admin access to share
    if (!File.hasAccess(file.id, req.user.id, 'admin') && file.owner_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'No permission to share this file'
      });
    }

    const { userId, username, permission = 'read', expiresAt } = req.body;

    // Find user to share with
    let targetUser;
    if (userId) {
      targetUser = User.findById(userId);
    } else if (username) {
      targetUser = User.findByUsername(username);
    }

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    if (targetUser.id === file.owner_id) {
      return res.status(400).json({
        success: false,
        error: 'Cannot share with file owner'
      });
    }

    // Grant permission
    Permission.grant({
      fileId: file.id,
      userId: targetUser.id,
      permission,
      grantedBy: req.user.id,
      expiresAt
    });

    // Log share
    AuditLog.create({
      userId: req.user.id,
      action: 'FILE_SHARE',
      resourceType: 'file',
      resourceId: file.uuid,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { sharedWith: targetUser.username, permission }
    });

    res.json({
      success: true,
      message: `File shared with ${targetUser.username}`,
      data: {
        permission: {
          userId: targetUser.id,
          username: targetUser.username,
          permission,
          expiresAt
        }
      }
    });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to share file'
    });
  }
};

/**
 * Revoke file access
 */
const revokeAccess = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Only owner can revoke
    if (file.owner_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Only file owner can revoke access'
      });
    }

    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'User ID required'
      });
    }

    Permission.revoke(file.id, userId);

    // Log revocation
    AuditLog.create({
      userId: req.user.id,
      action: 'FILE_REVOKE_ACCESS',
      resourceType: 'file',
      resourceId: file.uuid,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { revokedUserId: userId }
    });

    res.json({
      success: true,
      message: 'Access revoked successfully'
    });
  } catch (err) {
    console.error('Revoke access error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke access'
    });
  }
};

/**
 * Create a share link for a file
 */
const createShareLink = async (req, res) => {
  try {
    const file = File.findByUuid(req.params.uuid);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Only owner can create share links
    if (file.owner_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Only file owner can create share links'
      });
    }

    const { password, maxDownloads, expiresAt } = req.body;

    const shareLink = ShareLink.create({
      fileId: file.id,
      createdBy: req.user.id,
      password,
      maxDownloads,
      expiresAt
    });

    // Log share link creation
    AuditLog.create({
      userId: req.user.id,
      action: 'SHARE_LINK_CREATE',
      resourceType: 'share_link',
      resourceId: shareLink.id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { fileId: file.uuid, hasPassword: !!password }
    });

    res.status(201).json({
      success: true,
      message: 'Share link created',
      data: {
        shareLink: {
          id: shareLink.id,
          token: shareLink.share_token,
          url: `${req.protocol}://${req.get('host')}/api/share/${shareLink.share_token}`,
          hasPassword: !!password,
          maxDownloads: shareLink.max_downloads,
          expiresAt: shareLink.expires_at
        }
      }
    });
  } catch (err) {
    console.error('Create share link error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to create share link'
    });
  }
};

/**
 * Deactivate a share link
 */
const deactivateShareLink = async (req, res) => {
  try {
    const { linkId } = req.params;

    const shareLink = ShareLink.findById(linkId);
    if (!shareLink) {
      return res.status(404).json({
        success: false,
        error: 'Share link not found'
      });
    }

    // Get file to check ownership
    const file = File.findById(shareLink.file_id);
    if (!file || file.owner_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Only file owner can deactivate share links'
      });
    }

    ShareLink.deactivate(linkId);

    // Log deactivation
    AuditLog.create({
      userId: req.user.id,
      action: 'SHARE_LINK_DEACTIVATE',
      resourceType: 'share_link',
      resourceId: linkId,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      message: 'Share link deactivated'
    });
  } catch (err) {
    console.error('Deactivate share link error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to deactivate share link'
    });
  }
};

module.exports = {
  uploadFile,
  listFiles,
  getFile,
  downloadFile,
  deleteFile,
  shareFile,
  revokeAccess,
  createShareLink,
  deactivateShareLink
};
