const sodium = require('sodium-native');

const secretKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);

sodium.randombytes_buf(secretKey);

console.log(`Secret key: ${secretKey.toString('hex')}`);
