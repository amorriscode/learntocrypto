const sodium = require('sodium-native');

const message = Buffer.from(process.argv[2]);

const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);

sodium.crypto_sign_keypair(publicKey, secretKey);

const signature = Buffer.alloc(sodium.crypto_sign_BYTES);

sodium.crypto_sign_detached(signature, message, secretKey);

console.log(`Public Key: ${publicKey.toString('hex')}`);
console.log(`Signature: ${signature.toString('hex')}`);