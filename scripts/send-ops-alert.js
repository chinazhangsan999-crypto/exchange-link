'use strict';

const { sendAdminAlert } = require('../src/services/AlertService');

const [title = '⚠️ 运维告警', ...content] = process.argv.slice(2);

sendAdminAlert(title, content.join(' '))
  .then(result => {
    if (!result?.sent) {
      console.error(`运维告警发送失败：${result?.reason || '未知原因'}`);
      process.exitCode = 1;
    }
  })
  .catch(error => {
    console.error('运维告警发送异常：', error?.message || error);
    process.exitCode = 1;
  });
