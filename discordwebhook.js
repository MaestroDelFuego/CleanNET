const fetch = require('node-fetch');
const { DISCORD_WEBHOOK_URL } = require('./config');
const logger = require('./logger');

async function sendDiscordWebhook(message) {
  if (!DISCORD_WEBHOOK_URL) {
    console.warn('⚠️ Discord webhook URL is not set. Skipping webhook.');
    return;
  }

  const payload = {
    content: message,
    username: 'CleanNET DNS Bot',
    avatar_url: 'https://i.imgur.com/AfFp7pu.png',
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
          break;
        }
      }
    } catch (error) {
      console.error(`❌ Discord webhook error on attempt ${attempt}: ${error.message}`);
    }
    await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
  }
}

module.exports = { sendDiscordWebhook };
