#!/usr/bin/env node
/**
 * FinVault — Gerador de chaves RSA 4096-bit para JWT RS256
 * Uso: node scripts/keygen.js
 */
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const keysDir = path.join(__dirname, '..', 'keys');
if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });

console.log('🔑 Gerando par de chaves RSA 4096-bit...');
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey, { mode: 0o600 });
fs.writeFileSync(path.join(keysDir, 'public.pem'),  publicKey);

console.log('✅ Chaves geradas em ./keys/');
console.log('');
console.log('Cole no .env (substitua quebras de linha por \\n):');
console.log('');
console.log('JWT_PRIVATE_KEY=' + JSON.stringify(privateKey));
console.log('JWT_PUBLIC_KEY='  + JSON.stringify(publicKey));
console.log('');
console.log('🔒 AES key (32 bytes):');
console.log('AES_KEY=' + crypto.randomBytes(32).toString('hex'));
console.log('');
console.log('🔒 DB password:');
console.log('DB_PASS=' + crypto.randomBytes(24).toString('base64'));
console.log('');
console.log('🔒 Redis password:');
console.log('REDIS_PASS=' + crypto.randomBytes(24).toString('base64'));
