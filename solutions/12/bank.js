const jsonStream = require('duplex-json-stream');
const net = require('net');
const fs = require('fs');
const sodium = require('sodium-native');

const LEDGER_PATH = './ledger';
const GENESIS_HASH = Buffer.alloc(32).toString('hex');

const PUBLIC_KEY_PATH = './key.pub';
const SECRET_KEY_PATH = './key';
let PUBLIC_KEY = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
let SECRET_KEY = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);

const ENCRYPT_KEY_PATH = './encryptKey'
const NONCE_PATH = './nonce'
let ENCRYPT_KEY = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);
let NONCE = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);

// Make sure our bank has the keys to the vault
// Load the keys if they exist or create them
if (fs.existsSync(PUBLIC_KEY_PATH) && fs.existsSync(SECRET_KEY_PATH)) {
  const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const secretKey = fs.readFileSync(SECRET_KEY_PATH, 'utf8');

  PUBLIC_KEY = PUBLIC_KEY.fill(publicKey, 'hex');
  SECRET_KEY = SECRET_KEY.fill(secretKey, 'hex');
} else {
  sodium.crypto_sign_keypair(PUBLIC_KEY, SECRET_KEY);

  fs.writeFileSync(PUBLIC_KEY_PATH, PUBLIC_KEY.toString('hex'));
  fs.writeFileSync(SECRET_KEY_PATH, SECRET_KEY.toString('hex'));
}

// Make sure our bank has an encryption key
// Load it if it exists or create it
if (fs.existsSync(ENCRYPT_KEY_PATH) && fs.existsSync(NONCE_PATH)) {
  const encryptKey = fs.readFileSync(ENCRYPT_KEY_PATH, 'utf8');
  const nonce = fs.readFileSync(NONCE_PATH, 'utf8');

  ENCRYPT_KEY = ENCRYPT_KEY.fill(encryptKey, 'hex');
  NONCE = NONCE.fill(nonce, 'hex');
} else {
  sodium.randombytes_buf(ENCRYPT_KEY);
  sodium.randombytes_buf(NONCE);

  fs.writeFileSync(ENCRYPT_KEY_PATH, ENCRYPT_KEY.toString('hex'));
  fs.writeFileSync(NONCE_PATH, NONCE.toString('hex'));
}

const getPrevHash = (ledger) => {
  return ledger.length
    ? ledger[ledger.length - 1].hash
    : GENESIS_HASH;
};

const hashToHex = (hash) => {
  const inBuffer = Buffer.from(hash);
  const outBuffer = Buffer.alloc(sodium.crypto_generichash_BYTES);

  sodium.crypto_generichash(outBuffer, inBuffer);

  return outBuffer.toString('hex');
};

// Verify all the hashes in the ledger are correct
// Otherwise close the bank for investigation
const verifyLedger = (ledger) => {
  ledger.forEach(({ value, hash, signature }, index) => {
    const stringifiedValue = JSON.stringify(value);

    // The GENESIS_HASH is always used for the first ledger entry
    const prevHash = index === 0 ? GENESIS_HASH : ledger[index - 1].hash;
    const currHash = hashToHex(prevHash + stringifiedValue);

    // Verify the signature
    const sigBuffer = Buffer.alloc(sodium.crypto_sign_BYTES).fill(signature, 'hex');
    const message = Buffer.from(stringifiedValue);

    const verified = sodium.crypto_sign_verify_detached(sigBuffer, message, PUBLIC_KEY);

    // The hash has been calculated to be different
    // or the signature could not be verified
    if (currHash !== hash || !verified) {
      console.log(`The bank's ledger has been tampered with! The authorities have been notified.`);
      process.exit(1);
    }
  });
};

// Load the stored ledger if it exists
let storedLedger;
if (fs.existsSync(LEDGER_PATH)) {
  console.log('Loading stored ledger...');

  const encryptedLedger = Buffer.from(fs.readFileSync(LEDGER_PATH, 'utf8'), 'hex');
  const ledgerBuffer = Buffer.alloc(encryptedLedger.length - sodium.crypto_secretbox_MACBYTES);

  if (sodium.crypto_secretbox_open_easy(ledgerBuffer, encryptedLedger, NONCE, ENCRYPT_KEY)) {
    console.log('Ledger decrypted successfully!');
    storedLedger = JSON.parse(ledgerBuffer.toString());
  } else {
    console.log('Sadly, there was a problem decrypting the ledger.');
    process.exit(1);
  }

  if (storedLedger) {
    verifyLedger(storedLedger);
  }
};

const ledger = storedLedger || [];

const writeLedger = (ledger) => {
  const ledgerBuffer = Buffer.from(JSON.stringify(ledger));

  const encryptedLedger = Buffer.alloc(ledgerBuffer.length + sodium.crypto_secretbox_MACBYTES);

  sodium.crypto_secretbox_easy(encryptedLedger, ledgerBuffer, NONCE, ENCRYPT_KEY);

  fs.writeFileSync(LEDGER_PATH, encryptedLedger.toString('hex'));
};

// Add transactions to the ledger and write to file
// TODO: Append instead of nuking the whole ledger?
const writeLedgerEntry = (entry) => {
  const stringifiedEntry = JSON.stringify(entry);
  const prevHash = getPrevHash(ledger);

  // Create a signature with the message and secret key
  const message = Buffer.from(stringifiedEntry);
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES);

  sodium.crypto_sign_detached(signature, message, SECRET_KEY);

  ledger.push({
    value: entry,
    hash: hashToHex(prevHash + stringifiedEntry),
    signature: signature.toString('hex'),
  });

  writeLedger(ledger);
};

// Combine all transactions to provide user with balance
const balanceReducer = (customerId) => ledger.reduce((balance, { value }) => {
  const { cmd, id, amount } = value;

  const entryHandler = {
    deposit: () => balance + amount,
    withdraw: () => balance - amount,
  };

  return customerId === id && entryHandler.hasOwnProperty(cmd)
    ? entryHandler[cmd]()
    : balance;
}, 0);

const balanceHandler = ({ id }) => ({ balance: balanceReducer(id) });

const depositHandler = ({ id, amount }) => {
  writeLedgerEntry({ cmd: 'deposit', id, amount: parseInt(amount) });
  return balanceHandler({ id });
};

// Allow the user to withdraw money
// but deny them if insufficient funds
const withdrawHandler = ({ id, amount }) => {
  const amountToWithdraw = parseInt(amount);
  const { balance } = balanceHandler({ id });

  let err;
  if (balance >= amountToWithdraw) {
    writeLedgerEntry({ cmd: 'withdraw', id, amount: parseInt(amount) });
  } else {
    err = 'Insufficient funds!';
  }

  return {
    ...balanceHandler({ id }),
    err,
  };
};

const registerHandler = () => {
  const idBuffer = Buffer.alloc(32);
  sodium.randombytes_buf(idBuffer);

  const id = idBuffer.toString('hex');

  writeLedgerEntry({ cmd: 'register', id });

  return { id };
};

const cmdHandler = {
  deposit: depositHandler,
  balance: balanceHandler,
  withdraw: withdrawHandler,
  register: registerHandler,
};

const server = net.createServer((socket) => {
  socket = jsonStream(socket);

  socket.on('data', (msg) => {
    console.log('Bank received:', msg);

    const { cmd, ...rest } = msg;

    // Don't crash when the user is being nefarious
    if (!cmdHandler.hasOwnProperty(cmd)) {
      socket.end(`I'm sorry sir, I don't understand that request.`);
    } else {
      const returnVal = cmdHandler[cmd](rest);

      socket.end({ cmd, ...returnVal });
    }
  });
});

server.listen(3876);
