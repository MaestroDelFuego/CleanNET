const dns = require('native-dns');
const os = require('os');
const phishingAuth = require('./phishingauthority.api.js');
const { BLOCKED_DOMAINS, BLOCKED_PHISHING_DOMAINS, isBlocked, normalizeDomain } = require('./blockeddomains.js');
const { sendDiscordWebhook } = require('./discordwebhook.js');
const { getCustomResolve, forwardRequest } = require('./dnsUtils');
const logger = require('./logger');
const { ipNameMap } = require('./config');

const server = dns.createServer();

const dnsClients = new Map(); // IP -> count or metadata
const dnsClientQueries = new Map(); // Map<IP, Array of query logs>

server.on('request', async (request, response) => {
  const clientIp = request.address.address;
  const clientHost = os.hostname();

  if (dnsClients.has(clientIp)) {
    dnsClients.set(clientIp, dnsClients.get(clientIp) + 1);
  } else {
    dnsClients.set(clientIp, 1);
  }

  if (!dnsClientQueries.has(clientIp)) {
    dnsClientQueries.set(clientIp, []);
  }

  try {
    const question = request.question[0];
    const domain = normalizeDomain(question.name);

    dnsClientQueries.get(clientIp).push({
      domain,
      timestamp: new Date().toISOString(),
    });

    if (question.type !== dns.consts.NAME_TO_QTYPE.A) {
      forwardRequest(request, response);
      return;
    }

    if (isBlocked(domain)) {
      logger.warn(`⛔ Blocked domain requested: ${domain}`);
      await sendDiscordWebhook(`⛔ **Phishing Attempt BLOCKED**: \`${domain}\`\n📡 IP: \`${clientIp}\`\n🔎 Host: \`${clientHost}\``);
      response.answer.push(
        dns.A({
          name: question.name,
          address: '0.0.0.0',
          ttl: 300,
        })
      );
      response.send();
      return;
    }

    const { riskScore, risk, safetyMessage, reasons } = await phishingAuth.calculateRisk(domain);

    if (BLOCKED_PHISHING_DOMAINS.has(domain)) {
      logger.warn(`⛔ Blocked domain requested: ${domain}`);
      await sendDiscordWebhook(`⛔ **Phishing Attempt BLOCKED**: \`${domain}\`\n📡 IP: \`${clientIp}\`\n🔎 Host: \`${clientHost}\``);
      response.answer.push(
        dns.A({
          name: question.name,
          address: '0.0.0.0',
          ttl: 300,
        })
      );
      response.send();
      return;
    }

    const customIP = getCustomResolve(domain);
    if (customIP) {
      logger.info(`🔧 Custom resolve for ${domain} -> ${customIP}`);
      response.answer.push(
        dns.A({
          name: question.name,
          address: customIP,
          ttl: 300,
        })
      );
      response.send();
      return;
    }

    const RISK_THRESHOLD = 60;
    if (riskScore >= RISK_THRESHOLD) {
      logger.warn(`🛑 Phishing risk detected for ${domain} (score: ${riskScore}), blocking`);
      response.answer.push(
        dns.A({
          name: question.name,
          address: '0.0.0.0',
          ttl: 300,
        })
      );
      await sendDiscordWebhook(`🛑 **Phishing risk detected and BLOCKED**: \`${domain}\` (score: ${riskScore})\n📡 IP: \`${clientIp}\`\n🔎 Host: \`${clientHost}\`\nReasons: ${reasons.join(', ')}`);
      response.send();
      return;
    }

    logger.info(`✅ Domain resolved: ${domain} (risk: ${riskScore})`);
    forwardRequest(request, response);

  } catch (e) {
    logger.error(`❌ DNS request error: ${e.message}`);
    response.header.rcode = dns.consts.NAME_TO_RCODE.SERVFAIL;
    response.send();
  }
});

server.on('error', (err) => {
  logger.error(`❌ DNS Server error: ${err}`);
});

function startDnsServer() {
  return new Promise((resolve) => {
    server.serve(53);
    logger.info('✅ DNS server running on port 53');
    resolve();
  });
}

module.exports = { startDnsServer, dnsClients, dnsClientQueries };
