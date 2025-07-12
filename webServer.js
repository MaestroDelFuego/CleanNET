const express = require('express');
const os = require('os');
const { dnsClients, dnsClientQueries } = require('./dnsServer');
const logger = require('./logger');
const { ipNameMap } = require('./config');
const { BLOCKED_DOMAINS, BLOCKED_PHISHING_DOMAINS } = require('./blockeddomains');

// Format uptime string (rounded to minutes)
function formatUptime(seconds) {
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}

function startWebServer() {
  const app = express();
  const PORT = 3000;

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
    logger.info(`✅ Web UI running on http://localhost:${PORT}`);
  });
}

module.exports = { startWebServer };
