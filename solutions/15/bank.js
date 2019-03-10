const jsonStream = require('duplex-json-stream');
const net = require('net');
const fs = require('fs');
const sodium = require('sodium-native');

const LEDGER_PATH = './ledger';
const GENESIS_HASH = sodium.sodium_malloc(32).toString('hex');

const PUBLIC_KEY_PATH = './key.pub';
const SECRET_KEY_PATH = './key';
let PUBLIC_KEY = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
let SECRET_KEY = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES);

const ENCRYPT_KEY_PATH = './encryptKey'
const NONCE_PATH = './nonce'
let ENCRYPT_KEY = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES);
let NONCE = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);

// Make sure our bank has the keys to the vault
// Load the keys if they exist or create them
if (fs.existsSync(PUBLIC_KEY_PATH) && fs.existsSync(SECRET_KEY_PATH)) {
  const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const secretKey = fs.readFileSync(SECRET_KEY_PATH, 'utf8');

  PUBLIC_KEY = PUBLIC_KEY.fill(publicKey, 'hex');

  SECRET_KEY = SECRET_KEY.fill(secretKey, 'hex');
  sodium.sodium_mprotect_noaccess(SECRET_KEY);
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
  sodium.sodium_mprotect_noaccess(ENCRYPT_KEY);

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
  const ledgerBuffer = sodium.sodium_malloc(encryptedLedger.length - sodium.crypto_secretbox_MACBYTES);

  sodium.sodium_mprotect_readwrite(ENCRYPT_KEY);
  const decrypted = sodium.crypto_secretbox_open_easy(ledgerBuffer, encryptedLedger, NONCE, ENCRYPT_KEY);
  sodium.sodium_mprotect_noaccess(ENCRYPT_KEY);

  if (decrypted) {
    console.log('Ledger decrypted successfully!');
    storedLedger = JSON.parse(ledgerBuffer.toString());

    // Don't leak the decrypted ledger or encrypt key
    sodium.sodium_mprotect_noaccess(ledgerBuffer);
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

  sodium.sodium_mprotect_readwrite(ENCRYPT_KEY);
  sodium.crypto_secretbox_easy(encryptedLedger, ledgerBuffer, NONCE, ENCRYPT_KEY);
  sodium.sodium_mprotect_noaccess(ENCRYPT_KEY);

  fs.writeFileSync(LEDGER_PATH, encryptedLedger.toString('hex'));
};

const verifyCustomer = ({ entry, signature, publicKey }) => {
  // Verify that the user's signature
  const publicKeyBuffer = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES).fill(publicKey, 'hex');
  const sigBuffer = Buffer.alloc(sodium.crypto_sign_BYTES).fill(signature, 'hex');
  const entryBuffer = Buffer.from(JSON.stringify(entry));

  return sodium.crypto_sign_verify_detached(sigBuffer, entryBuffer, publicKeyBuffer);
}

// Add transactions to the ledger and write to file
// TODO: Append instead of nuking the whole ledger?
const writeLedgerEntry = (value, msg) => {
  const { cmd } = value;

  if (cmd === 'register' || verifyCustomer(msg)) {
    const stringifiedValue = JSON.stringify(value);
    const prevHash = getPrevHash(ledger);
  
    // Create a signature with the value and secret key
    const valueBuffer = Buffer.from(stringifiedValue);
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
  
    sodium.sodium_mprotect_readwrite(SECRET_KEY);
    sodium.crypto_sign_detached(signature, valueBuffer, SECRET_KEY);
    sodium.sodium_mprotect_noaccess(SECRET_KEY);

    const hash = hashToHex(prevHash + stringifiedValue);
  
    ledger.push({
      value,
      hash,
      signature: signature.toString('hex'),
    });
  
    writeLedger(ledger);

    return hash;
  }
};

// Combine all transactions to provide user with balance
const balanceReducer = (currCustomerId) => ledger.reduce((balance, { value }) => {
  const { cmd, customerId, amount } = value;

  const entryHandler = {
    deposit: () => balance + amount,
    withdraw: () => balance - amount,
  };

  return currCustomerId === customerId && entryHandler.hasOwnProperty(cmd)
    ? entryHandler[cmd]()
    : balance;
}, 0);

const balanceHandler = (msg, hash) => {
  const { entry } = msg;
  const { customerId } = entry;
  
  const verified = verifyCustomer(msg);

  if (!hash) {
    hash = writeLedgerEntry({ cmd: 'balance', customerId }, msg);
  }

  return verified
    ? { balance: balanceReducer(customerId), hash }
    : { err: 'It appears you are not the owner of that account.' };
};

const depositHandler = (msg) => {
  const { entry } = msg;
  const { customerId, amount } = entry;

  const hash = writeLedgerEntry({ cmd: 'deposit', customerId, amount: parseInt(amount) }, msg);

  return balanceHandler(msg, hash);
};

// Allow the user to withdraw money
// but deny them if insufficient funds
const withdrawHandler = (msg) => {
  const { entry } = msg;
  const { amount, customerId } = entry;

  const amountToWithdraw = parseInt(amount);
  const { balance } = balanceHandler(msg);

  let err;
  let hash;
  if (balance >= amountToWithdraw) {
    hash = writeLedgerEntry({ cmd: 'withdraw', customerId, amount: parseInt(amount) }, msg);
  } else {
    err = 'Insufficient funds!';
  }

  return {
    ...balanceHandler(msg),
    hash,
    err,
  };
};

const registerHandler = () => {
  const idBuffer = Buffer.alloc(32);
  sodium.randombytes_buf(idBuffer);

  const customerId = idBuffer.toString('hex');

  const hash = writeLedgerEntry({ cmd: 'register', customerId });

  return { customerId, hash };
};

const cmdHandler = {
  deposit: depositHandler,
  balance: balanceHandler,
  withdraw: withdrawHandler,
  register: registerHandler,
};

const verifyLastHash = ({ entry, lastHash }) => {
  const { customerId } = entry;
  const customerTransactions = ledger.filter(({ value }) => value.customerId === customerId);
  
  return lastHash === customerTransactions[customerTransactions.length - 1].hash;
};

const server = net.createServer((socket) => {
  socket = jsonStream(socket);

  socket.on('data', (msg) => {
    console.log('Bank received:', msg);

    const { entry } = msg;
    const { cmd } = entry;

    const verifiedLastHash = cmd !== 'register'
      ? verifyLastHash(msg)
      : true;

    if (!verifiedLastHash) {
      // Don't accept commands with the wrong verified last hash
      socket.end(`I'm sorry sir, there appears to be an issue with your request.`);
    } else if (!cmdHandler.hasOwnProperty(cmd)) {
      // Don't crash when the user is being nefarious
      socket.end(`I'm sorry sir, I don't understand that request.`);
    } else {
      const returnVal = cmdHandler[cmd](msg);

      socket.end({ cmd, ...returnVal });
    }
  });
});

server.listen(3876);
