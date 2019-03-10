const jsonStream = require('duplex-json-stream');
const net = require('net');
const sodium = require('sodium-native');
const fs = require('fs');

// TODO: Fix terrible register hack
const newCustomer = process.argv[2] === 'register';
const customerId = newCustomer ? null : process.argv[2];
const cmd = newCustomer ? 'register' : process.argv[3];
const value = process.argv[4];

const LAST_HASH_PATH = './last_hash';
let LAST_HASH;

const CUST_PUBLIC_KEY_PATH = './cust_key.pub';
const CUST_SECRET_KEY_PATH = './cust_key';
let CUST_PUBLIC_KEY = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
let CUST_SECRET_KEY = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);

// Make sure our bank has the keys to the vault
// Load the keys or generate them if new customer
if (fs.existsSync(CUST_PUBLIC_KEY_PATH) && fs.existsSync(CUST_SECRET_KEY_PATH)) {
  const custPublicKey = fs.readFileSync(CUST_PUBLIC_KEY_PATH, 'utf8');
  const custSecretKey = fs.readFileSync(CUST_SECRET_KEY_PATH, 'utf8');

  CUST_PUBLIC_KEY = CUST_PUBLIC_KEY.fill(custPublicKey, 'hex');
  CUST_SECRET_KEY = CUST_SECRET_KEY.fill(custSecretKey, 'hex');
} else  if (newCustomer) {
  sodium.crypto_sign_keypair(CUST_PUBLIC_KEY, CUST_SECRET_KEY);

  fs.writeFileSync(CUST_PUBLIC_KEY_PATH, CUST_PUBLIC_KEY.toString('hex'));
  fs.writeFileSync(CUST_SECRET_KEY_PATH, CUST_SECRET_KEY.toString('hex'));
}

// Load the last hash if it exists (and it should!)
if (fs.existsSync(LAST_HASH_PATH)) {
  LAST_HASH = fs.readFileSync(LAST_HASH_PATH, 'utf8');
}

const client = jsonStream(net.connect(3876));

const cmdParams = {
  balance: {},
  deposit: { amount: value },
  withdraw: { amount: value },
};

client.on('data', (msg) => {
  const { hash } = msg;

  console.log('Teller received:', msg);

  if (hash) {
    fs.writeFileSync(LAST_HASH_PATH, hash);
  }
});

const entry = {
  cmd,
  ...cmdParams[cmd],
  customerId,
};

// Sign all of the requests
const entryBuffer = Buffer.from(JSON.stringify(entry));
const signature = Buffer.alloc(sodium.crypto_sign_BYTES);

sodium.crypto_sign_detached(signature, entryBuffer, CUST_SECRET_KEY);

client.end({
  entry,
  lastHash: LAST_HASH,
  signature: signature.toString('hex'),
  publicKey: CUST_PUBLIC_KEY.toString('hex'),
});
