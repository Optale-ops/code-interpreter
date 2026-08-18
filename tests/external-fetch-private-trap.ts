import net from 'node:net';

let contacts = 0;
const server = net.createServer(socket => {
  contacts += 1;
  console.error(`PRIVATE_TRAP_CONTACT_${contacts}`);
  socket.destroy();
});
server.listen(443, '0.0.0.0', () => {
  console.log('EXTERNAL_FETCH_PRIVATE_TRAP_READY');
});
