'use strict';

const { ADMIN_FRONTEND_ORIGIN, IS_PRODUCTION } = require('../config/env');
const CredentialStore = require('./IntegrationCredentialStore');

let storedOrigin = '';

function normalizeOrigin(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    const localDevelopment = !IS_PRODUCTION
      && parsed.protocol === 'http:'
      && ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if ((parsed.protocol !== 'https:' && !localDevelopment) || parsed.username || parsed.password
      || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    return parsed.origin.toLowerCase();
  } catch {
    return '';
  }
}

function originFromDomain(domain) {
  const hostname = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  return hostname ? normalizeOrigin(`https://${hostname}`) : '';
}

function refreshFromStoredConfig() {
  storedOrigin = originFromDomain(CredentialStore.cloudflareBootstrapConfig().adminDomain);
  return currentOrigin();
}

function setStoredOrigin(value) {
  storedOrigin = normalizeOrigin(value);
  return currentOrigin();
}

function setStoredDomain(domain) {
  storedOrigin = originFromDomain(domain);
  return currentOrigin();
}

function currentOrigin() {
  return normalizeOrigin(ADMIN_FRONTEND_ORIGIN) || storedOrigin;
}

refreshFromStoredConfig();

module.exports = {
  currentOrigin,
  refreshFromStoredConfig,
  setStoredOrigin,
  setStoredDomain
};
