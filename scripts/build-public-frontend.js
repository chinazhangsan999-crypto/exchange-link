'use strict';

const fs = require('fs');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const sourceDirectory = path.join(projectRoot, 'public');
const outputDirectory = path.join(projectRoot, 'dist', 'public-frontend');

if (!outputDirectory.startsWith(`${projectRoot}${path.sep}`)) {
  throw new Error('公共前端输出目录越界，已拒绝执行');
}

fs.rmSync(outputDirectory, { recursive: true, force: true });
fs.mkdirSync(outputDirectory, { recursive: true });
fs.cpSync(sourceDirectory, outputDirectory, {
  recursive: true,
  filter(source) {
    const relative = path.relative(sourceDirectory, source);
    if (!relative) return true;
    if (relative.toLowerCase().endsWith('.map')) return false;
    return relative.split(path.sep)[0].toLowerCase() !== 'admin';
  }
});

console.log(`公共前端已输出到：${outputDirectory}`);
