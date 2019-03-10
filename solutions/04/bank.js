const jsonStream = require('duplex-json-stream');
const net = require('net');
const fs = require('fs');

const LEDGER_PATH = './ledger.json';

// Load the stored ledger if it exists
let storedLedger;
if (fs.existsSync(LEDGER_PATH)) {
  console.log('Loading stored ledger...');
  storedLedger = JSON.parse(fs.readFileSync(LEDGER_PATH, 'utf8'));
};

const ledger = storedLedger || [];

// Add transactions to the ledger and write to file
// TODO: Append instead of nuking the whole ledger?
const writeLedgerEntry = (entry) => {
  ledger.push(entry);
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(ledger));
};

// Combine all transactions to provide user with balance
const balanceReducer = () => ledger.reduce((balance, ledgerEntry) => {
  const { cmd, amount } = ledgerEntry;

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