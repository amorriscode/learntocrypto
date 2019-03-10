const sodium = require('sodium-native');

const secretKey = Buffer.from(process.argv[2], 'hex');
const message = Buffer.from(process.argv[3]);

const cipher = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES);
const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)

sodium.crypto_secretbox_easy(cipher, message, nonce, secretKey);

console.log(`Encrypted message: ${cipher.toString('hex')}`);
