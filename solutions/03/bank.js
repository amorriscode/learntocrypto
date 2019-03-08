const jsonStream = require('duplex-json-stream');
const net = require('net');

const ledger = [];

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
  ledger.push({ cmd: 'deposit', amount: parseInt(amount) });
  return balanceHandler();
};

const withdrawHandler = ({ amount }) => {
  const amountToWithdraw = parseInt(amount);
  const { balance } = balanceHandler();

  let err;
  if (balance >= amountToWithdraw) {
    ledger.push({ cmd: 'withdraw', amount: parseInt(amount) });
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

    const returnVal = cmdHandler[cmd](rest);

    socket.end({ cmd, ...returnVal });
  });
});

server.listen(3876);