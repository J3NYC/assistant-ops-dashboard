#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { encrypt, hashSecret } = require('../lib/encryption');

async function main() {
  const outPath = process.argv[2] || path.join(process.cwd(), 'sensitive-migration-output.json');

  const apiKeys = JSON.parse(process.env.API_KEY_SECRETS_JSON || '{}');
  const hashedKeys = {};
  for (const [id, secret] of Object.entries(apiKeys)) {
    if (!secret) continue;
    hashedKeys[id] = await hashSecret(secret);
  }

  const webhookSecret = process.env.WEBHOOK_HMAC_SECRET || '';
  const encryptedWebhookSecret = webhookSecret ? encrypt(webhookSecret) : '';

  const token = process.env.USER_TOKEN_PLAINTEXT || '';
  const encryptedUserToken = token ? encrypt(token) : '';

  const output = {
    generatedAt: new Date().toISOString(),
    encryptedWebhookSecret,
    encryptedUserToken,
    apiKeyHashes: hashedKeys,
  };

  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`Wrote migration output: ${outPath}`);
  console.log('Set ENCRYPTED_WEBHOOK_SECRET from output and remove WEBHOOK_HMAC_SECRET plaintext env');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
