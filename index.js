const dns = require('native-dns');
const express = require('express');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize } = format;

const app = express();
const PORT = 3000;
const server = dns.createServer();

const phishingAuth = require('./phishingauthority.api.js');

const ADS_FILE = path.resolve(__dirname, './CleanNET/ads.txt');
const PHISHING_DOMAINS_FILE = path.resolve(__dirname, './PhishingAuthorityData/blockedDomains.json');

const BLOCKED_DOMAINS = new Set();
const BLOCKED_PHISHING_DOMAINS = new Set();

const DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1392996516859478147/GNcO6bpBHjp1bSV4zoO0XPMZk5P1e6ZGXq51h_LH21LbXc6iOVsGa6YLm7cRqKUtYDPF'; // Replace this

const dnsClients = new Map(); // IP -> count or metadata
const dnsClientQueries = new Map(); // Map<IP, Array of query logs>


const ipNameMap = {
  '192.168.1.120': 'Olivers PC',
  '192.168.1.251': 'Olivers IPhone',
  // Add more IPs as needed
};


async function sendDiscordWebhook(message) {
  if (!DISCORD_WEBHOOK_URL) {
    console.warn('⚠️ Discord webhook URL is not set. Skipping webhook.');
    return;
  }

  const payload = {
    content: message,
    username: 'CleanNET DNS Bot',  // Optional: customize webhook sender name
    avatar_url: 'https://i.imgur.com/AfFp7pu.png', // Optional: customize webhook avatar
  };

  const maxRetries = 3;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      attempt++;
      const response = await fetch(DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        console.info(`✅ Discord webhook sent successfully on attempt ${attempt}`);
        break;
      } else {
        const errorText = await response.text();
        console.error(`❌ Discord webhook failed (status ${response.status}): ${errorText}`);

        if (response.status >= 400 && response.status < 500) {
          // Client errors like 400, 401, 403 usually mean no point retrying
          break;
        }
      }
    } catch (error) {
      console.error(`❌ Discord webhook error on attempt ${attempt}: ${error.message}`);
    }

    // Delay before retrying
    await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
  }
}

// Custom log format for console output
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level}] ${message}`;
});

const logger = createLogger({
  level: 'info', // default level; you can set to 'debug' for more details
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    logFormat
  ),
  transports: [
    new transports.Console({
      format: combine(colorize(), timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), logFormat),
    }),
    // Optionally add file transport:
    // new transports.File({ filename: 'logs/server.log' }),
  ],
});

const CUSTOM_RESOLVES = {
  'test.local': 'localhost',
};

const upstreamDnsServers = ['8.8.8.8', '1.1.1.1']; // Upstream DNS servers
phishingAuth.compareAndUpdateFiles();
logger.info('🚀 Starting CleanNET DNS Server...');

// Normalize domain helper
function normalizeDomain(domain) {
  try {
    return domain.toLowerCase().trim().replace(/\.$/, '');
  } catch {
    return domain;
  }
}

// Load blocked phishing domains from JSON file
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

// Load blocked ad domains from ads.txt file
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

loadBlockedDomains();
loadPhishingDomains();

// Check if domain is blocked (exact or parent domain)
function isBlocked(domain) {
  try {
    const d = normalizeDomain(domain);
    if (BLOCKED_DOMAINS.has(d)){
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

// Get custom IP for specific domains
function getCustomResolve(domain) {
  try {
    const d = normalizeDomain(domain);
    if (CUSTOM_RESOLVES[d]) return CUSTOM_RESOLVES[d];
    const parts = d.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (CUSTOM_RESOLVES[parent]) return CUSTOM_RESOLVES[parent];
    }
    return null;
  } catch {
    return null;
  }
}

// Forward DNS request to upstream server(s)
function forwardRequest(request, response, serverIndex = 0) {
  if (serverIndex >= upstreamDnsServers.length) {
    response.header.rcode = dns.consts.NAME_TO_RCODE.SERVFAIL;
    response.send();
    return;
  }
  try {
    const question = request.question[0];
    const upstreamRequest = dns.Request({
      question: dns.Question({
        name: question.name,
        type: question.type,
      }),
      server: { address: upstreamDnsServers[serverIndex], port: 53, type: 'udp' },
      timeout: 2000,
    });

    upstreamRequest.on('timeout', () => {
      logger.warn(`⚠️ DNS ${upstreamDnsServers[serverIndex]} timed out`);
      forwardRequest(request, response, serverIndex + 1);
    });

    upstreamRequest.on('message', (err, msg) => {
      if (err) {
        logger.error(`❌ DNS upstream error: ${err}`);
        forwardRequest(request, response, serverIndex + 1);
        return;
      }
      msg.answer.forEach(a => {
        response.answer.push(a);
      });
      response.send();
    });

    upstreamRequest.send();
  } catch (e) {
    logger.error(`❌ forwardRequest error: ${e}`);
    response.header.rcode = dns.consts.NAME_TO_RCODE.SERVFAIL;
    response.send();
  }
}

// DNS request handler
server.on('request', async (request, response) => {
  const clientIp = request.address.address;
  const clientHost = os.hostname(); // or use reverse lookup if needed

  // Track client IPs
  if (dnsClients.has(clientIp)) {
    dnsClients.set(clientIp, dnsClients.get(clientIp) + 1);
  } else {
    dnsClients.set(clientIp, 1);
  }

  try {
    const question = request.question[0];
    const domain = normalizeDomain(question.name);

    if (!dnsClientQueries.has(clientIp)) {
  dnsClientQueries.set(clientIp, []);
}
dnsClientQueries.get(clientIp).push({
  domain,
  timestamp: new Date().toISOString(),
});

    if (question.type !== dns.consts.NAME_TO_QTYPE.A) {
      forwardRequest(request, response);
      return;
    }

    if (isBlocked(domain)) {
      logger.warn(`⛔ Blocked Ad domain requested: ${domain}`);
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
      logger.warn(`⛔ Blocked Phishing domain requested: ${domain}`);
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
      response.send();
      return;
    }

    logger.info(`➡️ Forwarding DNS query upstream for domain: ${domain}`);
    forwardRequest(request, response);
  } catch (e) {
    logger.error(`❌ DNS request handler error: ${e}`);
    response.header.rcode = dns.consts.NAME_TO_RCODE.SERVFAIL;
    response.send();
  }
});

server.on('error', (err) => {
  logger.error(`❌ DNS Server error: ${err.stack}`);
});

server.on('listening', () => {
  logger.info('🖥️ DNS Server started on port 53');
});

server.serve(53);

// -------------- Web UI -------------------

// Format uptime string (rounded to minutes)
function formatUptime(seconds) {
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}

app.get('/', async (req, res) => {
  try {
    const ads = Array.from(BLOCKED_DOMAINS).sort();
    const dnsClientEntries = Array.from(dnsClientQueries.entries()).map(([ip, logs]) => ({
      ip,
      name: ipNameMap[ip] || 'Unknown Device',
      queries: logs,
    }));

    const phishing = Array.from(BLOCKED_PHISHING_DOMAINS).sort();
    const domain = req.query.domain || '';
    let riskResult = null;
    let errorMsg = null;

    if (domain) {
      try {
        riskResult = await phishingAuth.calculateRisk(domain);
      } catch (err) {
        logger.error(`❌ calculateRisk error: ${err}`);
        errorMsg = `Error calculating risk: ${err.message || err}`;
      }
    }

    // System stats
    const uptimeSec = os.uptime();
    const uptimeStr = formatUptime(uptimeSec);
    const loadAvg = os.loadavg(); // 1, 5, 15 min
    const memTotalMB = Math.round(os.totalmem() / 1024 / 1024);
    const memFreeMB = Math.round(os.freemem() / 1024 / 1024);
    const memUsedMB = memTotalMB - memFreeMB;
    const memUsedPercent = ((memUsedMB / memTotalMB) * 100).toFixed(1);

    const cpus = os.cpus();
    const cpuModel = cpus[0].model;
    const cpuCount = cpus.length;

    const cpuLoadPercent = Math.min(100, Math.max(0.1, (loadAvg[0] / cpuCount) * 100)).toFixed(1);

    const perCoreLoad = Array(cpuCount).fill((cpuLoadPercent / cpuCount).toFixed(1));

    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CleanNET DNS Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white font-sans p-6">
  <div class="max-w-6xl mx-auto space-y-8">
    <header class="flex items-center justify-between border-b border-gray-700 pb-4">
      <h1 class="text-3xl font-bold text-green-400">🛡️ CleanNET DNS Dashboard</h1>
      <form method="GET" class="flex gap-2">
        <input type="text" name="domain" placeholder="example.com" value="${domain}" required
          class="bg-gray-800 text-white px-4 py-2 rounded focus:outline-none focus:ring focus:border-green-400"/>
        <button type="submit"
          class="bg-green-500 hover:bg-green-600 text-black font-semibold px-4 py-2 rounded">Analyze</button>
      </form>
    </header>

    ${errorMsg ? `<div class="bg-red-600 text-white px-4 py-3 rounded">${errorMsg}</div>` : ''}

    ${riskResult ? `
      <section class="bg-gray-800 p-6 rounded shadow-md space-y-2">
        <h2 class="text-2xl font-semibold text-green-300">Risk Analysis for <span class="text-white">${domain}</span></h2>
        <div>
          <span class="font-bold">Risk Level:</span>
          <span class="inline-block px-2 py-1 rounded text-white font-semibold ${
            riskResult.risk >= 100 ? 'bg-red-500' : riskResult.risk >= 50 ? 'bg-yellow-500' : 'bg-green-500'
          }">${riskResult.risk >= 100 ? 'HIGH' : riskResult.risk >= 50 ? 'MEDIUM' : 'LOW'}</span>
        </div>
        <div><strong>Score:</strong> ${riskResult.risk}</div>
        <div><strong>Message:</strong> ${riskResult.safetyMessage}</div>
        <div>
          <details class="mt-2">
            <summary class="cursor-pointer text-green-400 hover:underline">Reasons</summary>
            <ul class="list-disc list-inside mt-2 text-sm text-gray-300">
              ${riskResult.reasons.map(r => `<li>${r}</li>`).join('')}
            </ul>
          </details>
        </div>
      </section>
    ` : ''}

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <section class="bg-gray-800 p-4 rounded shadow-md">
        <h2 class="text-xl font-semibold text-green-300">🛑 Blocked Ad Domains (${ads.length})</h2>
        <div class="max-h-64 overflow-y-auto mt-2">
          <ul class="text-sm text-gray-300 list-disc list-inside">
            ${ads.map(d => `<li>${d}</li>`).join('')}
          </ul>
        </div>
      </section>

      <section class="bg-gray-800 p-4 rounded shadow-md">
        <h2 class="text-xl font-semibold text-green-300">🎣 Blocked Phishing Domains (${phishing.length})</h2>
        <div class="max-h-64 overflow-y-auto mt-2">
          <ul class="text-sm text-gray-300 list-disc list-inside">
            ${phishing.map(d => `<li>${d}</li>`).join('')}
          </ul>
        </div>
      </section>
    </div>
<section class="bg-gray-800 p-4 rounded shadow-md mt-6">
  <h2 class="text-xl font-semibold text-green-300">🧑‍💻 DNS Clients (${dnsClientEntries.length})</h2>
  <div class="mt-4 space-y-4">
    ${dnsClientEntries.map(entry => `
      <details class="bg-gray-700 rounded p-3">
        <summary class="cursor-pointer text-lg font-medium text-white">
          ${entry.name} <span class="text-sm text-gray-400">(${entry.ip}) — ${entry.queries.length} queries</span>
        </summary>
        <ul class="mt-2 text-sm text-gray-300 list-disc list-inside max-h-48 overflow-y-auto">
          ${entry.queries.map(q => `
            <li><code>${q.domain}</code> <span class="text-gray-500">at ${new Date(q.timestamp).toLocaleTimeString()}</span></li>
          `).join('')}
        </ul>
      </details>
    `).join('')}
  </div>
</section>

    <section class="bg-gray-800 p-4 rounded shadow-md mt-6">
      <h2 class="text-xl font-semibold text-green-300">💻 System Info</h2>
      <ul class="mt-2 text-gray-300 text-sm space-y-1">
        <li><strong>Uptime:</strong> ${uptimeStr}</li>
        <li><strong>CPU:</strong> ${cpuModel} (${cpuCount} cores)</li>
        <li><strong>CPU Load (1m avg):</strong> ${cpuLoadPercent}%</li>
        <li><strong>Memory Usage:</strong> ${memUsedMB} MB / ${memTotalMB} MB (${memUsedPercent}%)</li>
      </ul>
    </section>
  </div>
</body>
</html>
    `);
  } catch (e) {
    logger.error(`❌ Express server error: ${e}`);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  logger.info(`🌐 Web UI started on http://localhost:${PORT}`);
});
