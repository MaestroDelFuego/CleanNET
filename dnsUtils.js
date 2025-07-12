const dns = require('native-dns');
const logger = require('./logger');
const { CUSTOM_RESOLVES, upstreamDnsServers } = require('./config');

function normalizeDomain(domain) {
  try {
    return domain.toLowerCase().trim().replace(/\.$/, '');
  } catch {
    return domain;
  }
}

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

module.exports = {
  normalizeDomain,
  getCustomResolve,
  forwardRequest,
};
