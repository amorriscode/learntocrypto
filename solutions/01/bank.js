const jsonStream = require('duplex-json-stream');
const net = require('net');

const server = net.createServer((socket) => {
  socket = jsonStream(socket);

  socket.on('data', (msg) => {
    console.log('Bank received:', msg)
    socket.write({ cmd: 'balance', balance: 0 });
  });
});

server.listen(3876);