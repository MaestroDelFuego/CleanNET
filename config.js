const path = require('path');

module.exports = {
  PORT: 3000,
  ADS_FILE: path.resolve(__dirname, './CleanNET/ads.txt'),
  PHISHING_DOMAINS_FILE: path.resolve(__dirname, './PhishingAuthorityData/blockedDomains.json'),
  DISCORD_WEBHOOK_URL: '', // Replace this if needed
  ipNameMap: {
    'IP': 'Hostname'
  },
  CUSTOM_RESOLVES: {
    'test.local': 'localhost',
  },
  upstreamDnsServers: ['8.8.8.8', '1.1.1.1'],
};
