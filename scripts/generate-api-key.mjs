#!/usr/bin/env node
// Usage: npm run apikey:generate -- <name> <read|write|admin>
// Prints a new random API key (show it once, store it in your secret manager)
// and the API_KEYS entry to configure — only the SHA-256 hash is stored server-side.
import { createHash, randomBytes } from 'node:crypto';

const [name, scope = 'read'] = process.argv.slice(2);
if (!name || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(name) || !['read', 'write', 'admin'].includes(scope)) {
  console.error('Usage: npm run apikey:generate -- <name> <read|write|admin>');
  process.exit(1);
}
const key = `fsk_${randomBytes(32).toString('base64url')}`;
const hash = createHash('sha256').update(key, 'utf8').digest('hex');
console.log(`API key (give to the client, never commit):\n  ${key}\n`);
console.log(`API_KEYS entry (append, comma separated):\n  ${name}:${scope}:${hash}`);
