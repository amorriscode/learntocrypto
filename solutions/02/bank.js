const jsonStream = require('duplex-json-stream');
const net = require('net');

const ledger = [];

const ledgerReducer = () => ledger.reduce((balance, { amount }) => balance + amount, 0);

const balanceHandler = () => ({ balance: ledgerReducer() });

const depositHandler = ({ amount }) => {
  ledger.push({ cmd: 'deposit', amount: parseInt(amount) });
  return balanceHandler();
};

const cmdHandler = {
  deposit: depositHandler,
  balance: balanceHandler,
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