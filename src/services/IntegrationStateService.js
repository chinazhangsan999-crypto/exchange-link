'use strict';

const { CONTROL_CENTER_ENABLED } = require('../config/env');
const SystemModel = require('../models/SystemModel');

let initialized = false;
let enrolled = CONTROL_CENTER_ENABLED;
let localPasswordLoginEnabled = !CONTROL_CENTER_ENABLED;
let bootstrapPasswordActive = !CONTROL_CENTER_ENABLED;

function enabledValue(value) { return String(value) === '1'; }

async function initialize() {
  const values = await SystemModel.getIntegrationState();
  if (CONTROL_CENTER_ENABLED && !enabledValue(values.control_center_enrolled)) {
    await SystemModel.upsertConfigs([
      ['control_center_enrolled', '1'],
      ['local_password_login_enabled', '0'],
      ['bootstrap_password_active', '0']
    ]);
    values.control_center_enrolled = '1';
    values.local_password_login_enabled = '0';
    values.bootstrap_password_active = '0';
  }
  enrolled = enabledValue(values.control_center_enrolled) || CONTROL_CENTER_ENABLED;
  localPasswordLoginEnabled = enabledValue(values.local_password_login_enabled) && !enrolled;
  bootstrapPasswordActive = enabledValue(values.bootstrap_password_active) && !enrolled;
  initialized = true;
  return status();
}

function status() {
  return { initialized, enrolled, localPasswordLoginEnabled, bootstrapPasswordActive };
}

function isControlCenterEnrolled() { return enrolled; }
function isLocalPasswordLoginAllowed() {
  return !enrolled && localPasswordLoginEnabled && bootstrapPasswordActive;
}

async function markEnrolled(passwordHash) {
  await SystemModel.completeControlCenterEnrollment(passwordHash);
  enrolled = true;
  localPasswordLoginEnabled = false;
  bootstrapPasswordActive = false;
}

module.exports = { initialize, status, isControlCenterEnrolled, isLocalPasswordLoginAllowed, markEnrolled };
