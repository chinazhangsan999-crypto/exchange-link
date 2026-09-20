'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

test('后台登录和刷新后主动读取待审核友链数量', () => {
  const model = read('src/models/PartnerModel.js');
  const controller = read('src/controllers/AdminController.js');
  const routes = read('src/routes/admin.js');
  const review = read('public/admin/review.js');
  const init = read('public/admin/init.js');

  assert.match(model, /async function countReviewPartners\(\)[\s\S]*is_approved = 0/);
  assert.match(controller, /async function getReviewCount\(req, res\)[\s\S]*countReviewPartners/);
  assert.match(routes, /router\.get\('\/api\/admin\/review\/count', AdminController\.getReviewCount\)/);
  assert.match(review, /id="review-count"[^>]*>…<\/b>/);
  assert.match(review, /api\('\/api\/admin\/review\/count'\)/);
  assert.match(review, /window\.refreshReviewCount = refreshReviewCount/);
  assert.match(init, /handleLoginSuccess[\s\S]*window\.refreshReviewCount\?\.\(\)/);
  assert.match(init, /if \(hasSession\(\)\) \{[\s\S]*window\.refreshReviewCount\?\.\(\)/);
});
