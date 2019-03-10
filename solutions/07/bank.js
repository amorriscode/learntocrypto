const jsonStream = require('duplex-json-stream');
const net = require('net');
const fs = require('fs');
const sodium = require('sodium-native');

const LEDGER_PATH = './ledger.json';
const GENESIS_HASH = Buffer.alloc(32).toString('hex');

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
  ledger.forEach(({ value, hash }, index) => {
    // The GENESIS_HASH is always used for the first ledger entry
    const prevHash = index === 0 ? GENESIS_HASH : getPrevHash(ledger);
    const currHash = hashToHex(prevHash + JSON.stringify(value));

    if (currHash !== hash) {
      console.log(`The bank's ledger has been tampered with! The authorities have been notified.`);
      process.exit(1);
    }
  });
};

// Load the stored ledger if it exists
let storedLedger;
if (fs.existsSync(LEDGER_PATH)) {
  console.log('Loading stored ledger...');
  storedLedger = JSON.parse(fs.readFileSync(LEDGER_PATH, 'utf8'));

  verifyLedger(storedLedger);
};

const ledger = storedLedger || [];

// Add transactions to the ledger and write to file
// TODO: Append instead of nuking the whole ledger?
const writeLedgerEntry = (entry) => {
  const prevHash = getPrevHash(ledger);

  ledger.push({
    value: entry,
    hash: hashToHex(prevHash + JSON.stringify(entry)),
  });

  fs.writeFileSync(LEDGER_PATH, JSON.stringify(ledger));
};

// Combine all transactions to provide user with balance
const balanceReducer = () => ledger.reduce((balance, { value }) => {
  const { cmd, amount } = value;

  const entryHandler = {
    deposit: () => balance + amount,
    withdraw: () => balance - amount,
  };

  return entryHandler[cmd]();
}, 0);

const balanceHandler = () => ({ balance: balanceReducer() });

const depositHandler = ({ amount }) => {
  writeLedgerEntry({ cmd: 'deposit', amount: parseInt(amount) });
  return balanceHandler();
};

// Allow the user to withdraw money
// but deny them if insufficient funds
const withdrawHandler = ({ amount }) => {
  const amountToWithdraw = parseInt(amount);
  const { balance } = balanceHandler();

  let err;
  if (balance >= amountToWithdraw) {
    writeLedgerEntry({ cmd: 'withdraw', amount: parseInt(amount) });
  } else {
    err = 'Insufficient funds!';
  }

  return {
    ...balanceHandler(),
    err,
  };
};

const cmdHandler = {
  deposit: depositHandler,
  balance: balanceHandler,
  withdraw: withdrawHandler,
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
