const phishingAuth = require('./phishingauthority.api.js');
const { startDnsServer } = require('./dnsServer');
const { startWebServer } = require('./webServer');
const { loadBlockedDomains, loadPhishingDomains } = require('./blockeddomains.js');
const logger = require('./logger');

async function startServer() {
  try {
    logger.info('🚀 Starting CleanNET DNS Server...');
    await phishingAuth.compareAndUpdateFiles();
    await loadBlockedDomains();
    await loadPhishingDomains();

    await startDnsServer();
    await startWebServer();

  } catch (e) {
    logger.error(`❌ Failed to start server: ${e.message}`);
  }
}

startServer();
