const sodium = require('sodium-native');

const signature = Buffer.alloc(sodium.crypto_sign_BYTES).fill(process.argv[2], 'hex');
const message = Buffer.from(process.argv[3]);
const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES).fill(process.argv[4], 'hex');

const verified = sodium.crypto_sign_verify_detached(signature, message, publicKey);

const result = verified
  ? 'The signature has been verified!'
  : 'The signature does not match. Something nefarious is going on.';

console.log(result);