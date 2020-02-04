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

module.exports = {
  EVP_BytesToKey,
  DataBuffer,
  parseHeader,
};


