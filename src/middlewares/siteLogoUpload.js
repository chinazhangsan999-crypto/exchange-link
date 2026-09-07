'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const uploadDirectory = path.join(__dirname, '..', '..', 'public', 'uploads', 'logo');
fs.mkdirSync(uploadDirectory, { recursive: true });

const extensions = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp'
};

const storage = multer.diskStorage({
  destination: (_req, _file, callback) => callback(null, uploadDirectory),
  filename: (_req, file, callback) => callback(null, `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${extensions[file.mimetype]}`)
});

const uploader = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => callback(null, Boolean(extensions[file.mimetype]))
});

function siteLogoUpload(req, res, next) {
  uploader.single('logo')(req, res, error => {
    if (!error) return next();
    const message = error.code === 'LIMIT_FILE_SIZE'
      ? 'Logo 文件不能超过 2MB'
      : 'Logo 上传失败，请使用 PNG、JPG 或 WebP 图片';
    return res.status(400).json({ code: 400, msg: message, data: null });
  });
}

module.exports = { siteLogoUpload };
