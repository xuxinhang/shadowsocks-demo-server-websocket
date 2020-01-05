const net = require('net');
const crypto = require('crypto');

// For Debug
let remoteSocketOpenCount = 0;

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


class DataBuffer {
  constructor() {
    this.slices = [];
  }
  push(buf) {
    return this.slices.push(buf);
  }
  shift() {
    return this.slices.shift();
  }
  get length () {
    return this.slices.length;
  }
}


const server = new net.Server({});

server.on('connection', function connected (local) {
  console.log('a connection coming');
  let vi_sent = false;
  let myIV = null;
  let decipher = null, cipher = null;
  const [myKey, myIV_] = EVP_BytesToKey(Buffer.from('password', 'binary'), 16, 16);

  let remote = null; // the socket to the remote server.
  let remoteConnected = false;

  let localConHeader = null;
  const localDataBuffer = new DataBuffer();

  const clean = () => {
    remote = null;
    connection = null;
    cipher = null;
    decipher = null;
    console.log('local connection cleaned.');
  };

  local.on('connect', () => {
    console.log('local on connect');
  });

  local.on('data', (raw) => {
    console.log('local on data.');

    if (remote && remoteConnected) {
      const data = decipher.update(raw);
      remote.write(data);

    } else if (remote && !remoteConnected) {
      const data = decipher.update(raw);
      // localDataBuffer.push(data);
      remote.write(data);

    } else {
      let rawData;
      if (!myIV) {
        myIV = raw.slice(0, 16);
        rawData = raw.slice(16);
        decipher = crypto.createDecipheriv('aes-128-ctr', myKey, myIV);
        cipher = crypto.createCipheriv('aes-128-ctr', myKey, myIV);
      }

      let data = decipher.update(rawData);

      if (!localConHeader) {
        const parsed = parseHeader(data);
        if (!parsed) {
          local.end();
          return;
        }
        localConHeader = parsed;
      }

      const { type: remoteAddrType, host: remoteHost, port: remotePort, headerLength } = localConHeader;
      const poolKey = `${remoteHost}:${remotePort}`;
      console.log(poolKey);
      const payload = data.slice(headerLength);

      // socket.pause();

      // Save data into buffers
      // localDataBuffer.push(payload);

      // Open connection to remote
      console.log(`create new connection to remote server, accu=${++remoteSocketOpenCount}`);
      remote = remote || net.connect({
        host: remoteHost,
        port: remotePort,
      });

      remote.write(payload);

      remote.on('connect', () => {
        console.log('Connected to remote port');
        // socket.resume();
        remoteConnected = true;

        // Write saved data in buffer
        // while (localDataBuffer.length) {
        //   remote.write(localDataBuffer.shift());
        // }
      });

      remote.on('data', (buf) => {
        const payload = cipher.update(buf);
        let data = payload;
        if (!vi_sent) {
          data = Buffer.concat([myIV, payload]);
          vi_sent = true;
        }
        if (!local.write(data)) {
          // remote.pause();
        }
      });

      remote.on('drain', () => {
        // socket.resume();
      });

      remote.on('end', () => {
        console.info('remote connection on end');
        local.end();
      })

      remote.on('error', (e) => {
        console.error(e);
      });

      remote.on('close', (hadError) => {
        console.info('remote connection on close');
        if (hadError) {
          local.end();
        } else {
          local.destroy();
        }
      });
    }
  });

  local.on('end', () => {
    console.log('local connection end');
    remote.end();
  });

  local.on('close', hadError => {
    if (hadError) {
      remote.destroy();
    } else {
      remote.end();
    }
  });

  local.on('error', e => {
    console.error(e);
  });

  local.on('drain', () => {
    // remote.resume();
  });
});

server.listen(8388);

function parseHeader (data) {
  const addrType = Number(data[0]);
  let host, port, payload;
  switch (addrType) {
    case 0x01:
      host = data.slice(1, 5);
      port = data.readUInt16BE(5); // data.slice(5, 7);
      headerLength = 7;
      break;
    case 0x03:
      const len = Number(data[1]);
      host = data.slice(2, 2 + len);
      port = data.readUInt16BE(2 + len); // data.slice(2 + len, 2 + len + 2);
      headerLength = 2 + len + 2;
      break;
    case 0x04:
      host = data.slice(1, 17);
      port = data.readUInt16BE(17); // data.slice(17, 19);
      headerLength = 19;
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
    headerLength,
  };
}


