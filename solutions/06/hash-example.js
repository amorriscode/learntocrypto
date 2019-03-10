const sodium = require('sodium-native');

// Create two buffers with the max bytes
// helloBuffer will be the buffer to hash
// outBuffer will be the buffer to store the hash
const helloBuffer = Buffer.from('Hello, World!');
const outBuffer = Buffer.alloc(sodium.crypto_generichash_BYTES);

// Hash the helloBuffer
sodium.crypto_generichash(outBuffer, helloBuffer);

// Make sure that we got the correct result
const hexString = outBuffer.toString('hex');
const comparisonResult = hexString === '511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03';

console.log(`It is ${comparisonResult} that ${hexString} is equal to 511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03!`);