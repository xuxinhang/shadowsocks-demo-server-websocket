const WebSocket = require('ws');
const net = require('net');
const crypto = require('crypto');
const { EVP_BytesToKey, DataBuffer, parseHeader } = require('./utils');


/**
 * Shadowsocks over Websocket
 */

const wss = new WebSocket.Server({ port: 8389 });

wss.on('connection', local => {
  let localIVSent = false;
  let myIV = null;
  let decipher = null, cipher = null;
  const [myKey, myIV_] = EVP_BytesToKey(Buffer.from('password', 'binary'), 16, 16);

  let remote = null; // the socket to the remote server.
  let remoteConnected = false;

  let localConHeader = null;
  const localDataBuffer = new DataBuffer();

  // constant
  const IV_LENGTH = 16;
  const CIPHER_ALGORITHM = 'aes-128-cfb';

  local.on('message', raw => {
    if (remote && remoteConnected) {
      const data = decipher.update(raw);
      remote.write(data);

    } else if (remote && !remoteConnected) {
      const data = decipher.update(raw);
      // remote.write(data);
      // Save data into buffers
      localDataBuffer.push(data);

    } else {
      myIV = raw.slice(0, IV_LENGTH);
      const rawData = raw.slice(IV_LENGTH);
      decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, myKey, myIV);
      cipher = crypto.createCipheriv(CIPHER_ALGORITHM, myKey, myIV);
      const data = decipher.update(rawData);

      localConHeader = parseHeader(data); // error catcher
      const { host: remoteHost, type: remoteAddrType, port: remotePort, headerLength } = localConHeader;
      const payload = data.slice(headerLength);

      // Save data into buffers
      localDataBuffer.push(payload);

      remote = net.connect({
        port: remotePort,
        host: remoteHost,
      });

      remote.on('connect', () => {
        remoteConnected = true;

        // Write saved data in buffer
        while (localDataBuffer.length) {
          remote.write(localDataBuffer.shift());
        }
      });

      remote.on('data', buf => {
        const payload = cipher.update(buf);
        // [TODO]
        let localSentData = payload;
        if (!localIVSent) {
          localSentData = Buffer.concat([myIV, payload]);
          localIVSent = true;
        }
        local.send(localSentData); // if false ?
      });

      remote.on('end', () => {
        console.info('remote connection on end');
        local.close();
      })

      remote.on('error', e => {
        console.error(e);
      });

      remote.on('close', hadError => {
        console.info('remote connection on close');
        if (hadError) {
          local.close();
        } else {
          local.terminate();
        }
      });
    }
  });

  local.on('close', () => {
    remote.end();
  });

  local.on('error', e => {
    console.error(e);
  });
})

