const sodium = require('sodium-native');

const secretKey = Buffer.from(process.argv[2], 'hex');
const cipher = Buffer.from(process.argv[3], 'hex');

const message = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES);
const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)

const decrypted = sodium.crypto_secretbox_open_easy(message, cipher, nonce, secretKey);

const output = decrypted
  ? `Decrypted message: ${message.toString()}`
  : 'Decryption failed!';

console.log(output);