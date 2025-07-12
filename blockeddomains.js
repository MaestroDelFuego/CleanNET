const fs = require('fs');
const logger = require('./logger');
const { ADS_FILE, PHISHING_DOMAINS_FILE } = require('./config');

const BLOCKED_DOMAINS = new Set();
const BLOCKED_PHISHING_DOMAINS = new Set();

function normalizeDomain(domain) {
  try {
    return domain.toLowerCase().trim().replace(/\.$/, '');
  } catch {
    return domain;
  }
}

function loadBlockedDomains(file = ADS_FILE) {
  try {
    const data = fs.readFileSync(file, 'utf-8');
    BLOCKED_DOMAINS.clear();
    data.split('\n').forEach(line => {
      const domain = line.trim().toLowerCase();
      if (domain && !domain.startsWith('#')) {
        BLOCKED_DOMAINS.add(domain);
      }
    });
    logger.info(`✅ Loaded ${BLOCKED_DOMAINS.size} blocked domains from ${file}`);
  } catch (err) {
    logger.error(`❌ Failed to load blocked domains from ${file}: ${err.message}`);
  }
}

function loadPhishingDomains(file = PHISHING_DOMAINS_FILE) {
  try {
    const raw = fs.readFileSync(file, 'utf-8');
    const data = JSON.parse(raw);
    BLOCKED_PHISHING_DOMAINS.clear();

    for (const domain of data.blockedDomains || []) {
      if (typeof domain === 'string' && domain.trim()) {
        BLOCKED_PHISHING_DOMAINS.add(normalizeDomain(domain));
      }
    }
    logger.info(`✅ Loaded ${BLOCKED_PHISHING_DOMAINS.size} phishing domains from ${file}`);
  } catch (err) {
    logger.error(`❌ Failed to load phishing domains: ${err.message}`);
  }
}

function isBlocked(domain) {
  try {
    const d = normalizeDomain(domain);
    if (BLOCKED_DOMAINS.has(d)) {
      return true;
    }
    const parts = d.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      if (BLOCKED_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  } catch {
    return false;
  }
}

module.exports = {
  BLOCKED_DOMAINS,
  BLOCKED_PHISHING_DOMAINS,
  normalizeDomain,
  loadBlockedDomains,
  loadPhishingDomains,
  isBlocked,
};
