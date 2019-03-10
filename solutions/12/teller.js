const jsonStream = require('duplex-json-stream');
const net = require('net');

const client = jsonStream(net.connect(3876));

const id = process.argv[2];
// TODO: Fix terrible register hack
const cmd = process.argv[2] === 'register'
  ? 'register'
  : process.argv[3];
const value = process.argv[4];

const cmdParams = {
  balance: {},
  deposit: { amount: value },
  withdraw: { amount: value },
};

client.on('data', (msg) => {
  console.log('Teller received:', msg);
});

client.end({ cmd, ...cmdParams[cmd], id });
