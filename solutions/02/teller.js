const jsonStream = require('duplex-json-stream');
const net = require('net');

const client = jsonStream(net.connect(3876));

const cmd = process.argv[2];
const value = process.argv[3];

const cmdParams = {
  balance: {},
  deposit: {
    amount: value,
  },
};

client.on('data', (msg) => {
  console.log('Teller received:', msg);
});

client.end({ cmd, ...cmdParams[cmd] });
