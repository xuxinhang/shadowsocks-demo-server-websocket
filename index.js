const net = require('net');
const crypto = require('crypto');

function EVP_BytesToKey (password, key_len, iv_len) {
  var count, d, data, i, iv, key, m, md5, ms;
  m = [];
  i = 0;
  count = 0;
  while (count < key_len + iv_len) {
    md5 = crypto.createHash('md5');
    data = password;
    if (i > 0) {
      data = Buffer.concat([m[i - 1], password]);
    }
    md5.update(data);
    d = md5.digest();
    m.push(d);
    count += d.length;
    i += 1;
  }
  ms = Buffer.concat(m);
  key = ms.slice(0, key_len);
  iv = ms.slice(key_len, key_len + iv_len);
  // bytes_to_key_results[password] = [key, iv];
  return [key, iv];
};




// Prepare Crypto

class Decoder {
  constructor (password, IV) {
    const [myKey, myIV_] = EVP_BytesToKey(Buffer.from('password', 'binary'), 16, 16);
    const myIV = IV;
    const decipher = crypto.createDecipheriv('aes-128-ctr', myKey, myIV);
    this.decipher = decipher;
    let result = Buffer.from([]);
    this.result = result;
    decipher.on('readable', () => {
      let chunk;
      while(chunk = decipher.read()) {
        result = Buffer.concat([result, chunk]);
      }
    });
    decipher.on('end', () => {
      console.log(result.toString());
    });
  }
  write (data) {
    this.decipher.write(data);
  }
  end () {
    this.decipher.end();
  }
}

// remote connection poll
const remoteSocketPool = {};


const server = new net.Server({});

server.on('connection', function connected (socket) {
  console.log('a connection coming');
  let vi_sent = false;
  let myIV = null;
  let decipher, cipher;
  const [myKey, myIV_] = EVP_BytesToKey(Buffer.from('password', 'binary'), 16, 16);

  let remote = null; // the socket to the remote server.

  socket.on('connect', () => {
    console.log('local connect');
  });

  socket.on('data', (data) => {
    console.log('socket data now.');

    if (!myIV) {
      myIV = data.slice(0, 16);
      data = data.slice(16);
      decipher = crypto.createDecipheriv('aes-128-ctr', myKey, myIV);
      cipher = crypto.createCipheriv('aes-128-ctr', myKey, myIV);
    }

    let result = decipher.update(data);

    const parsed = parseData(result);
    if (!parsed) {
      socket.end();
      return;
    }

    const { type: remoteAddrType, host: remoteHost, port: remotePort, payload } = parsed;
    console.log(remoteHost, remotePort);

    socket.pause();

    // Open connection to remote
    const poolKey = `${remoteHost}:${remotePort}`;
    if (true || !(poolKey in remoteSocketPool)) {
      const remote = net.connect({
        host: remoteHost,
        port: remotePort,
      });
      remoteSocketPool[poolKey] = remote;
      remote.on('connect', () => {
        console.log('Connected to remote port');
        socket.resume();
      });
    }

    remote = remoteSocketPool[poolKey];

    remote.write(payload, () => {
      console.log('payload written successfully');
    });

    remote.on('data', (buf) => {
      const payload = cipher.update(buf);
      let data = payload;
      if (vi_sent === false) {
        data = Buffer.concat([myIV, payload]);
        vi_sent = true;
      }
      if (!socket.write(data)) {
        // remote.pause();
      }
    });

    remote.on('end', () => {
      console.info('remote socket on end');
      socket.end();
    })

    remote.on('error', (e) => {
      console.error(e);
    });

    remote.on('close', (hadError) => {
      console.info('remote socket on close');
      if (hadError) {
        socket.end();
      } else {
        socket.destroy();
      }
    })
  });

  socket.on('end', () => {
    console.log('local connection end');
    remote.end();
  });

  socket.on('close', hadError => {
    if (hadError) {
      remote.destroy();
    } else {
      remote.end();
    }
  });

  socket.on('error', e => {
    console.error(e);
  });
});

server.listen(8388);

function parseData (data) {
  const addrType = Number(data[0]);
  let host, port, payload;
  switch (addrType) {
    case 0x01:
      host = data.slice(1, 5);
      port = data.readUInt16BE(5); // data.slice(5, 7);
      payload = data.slice(7);
      break;
    case 0x03:
      const len = Number(data[1]);
      host = data.slice(2, 2 + len);
      port = data.readUInt16BE(2 + len); // data.slice(2 + len, 2 + len + 2);
      payload = data.slice(2 + len + 2);
      break;
    case 0x04:
      host = data.slice(1, 17);
      port = data.readUInt16BE(17); // data.slice(17, 19);
      payload = data.slice(19);
      break;
    default:
      console.log(`Unknow Address Type == ${addrType}`);
      // throw new Error('Unknown Addresss Type');
      return false;
  }

  return {
    type: addrType,
    host: String(host),
    port: Number(port),
    payload,
  };
}


