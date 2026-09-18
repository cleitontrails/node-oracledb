// Copyright (c) 2022, 2025, Oracle and/or its affiliates.

//-----------------------------------------------------------------------------
//
// This software is dual-licensed to you under the Universal Permissive License
// (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl and Apache License
// 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose
// either license.
//
// If you elect to accept the software under the Apache License, Version 2.0,
// the following applies:
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//-----------------------------------------------------------------------------
//
// The key derivation and framing implemented here follow go-ora
// (https://github.com/sijms/go-ora), MIT License, Copyright (c) 2020 Samy
// Sultan.
//
//-----------------------------------------------------------------------------

'use strict';

const crypto = require('crypto');
const errors = require("../../errors.js");

const BLOCK_SIZE = 16;

function toBigInt(buf) {
  return buf.length == 0 ? 0n : BigInt('0x' + buf.toString('hex'));
}

function toBuffer(value, length) {
  return Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex');
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = result * base % modulus;
    }
    base = base * base % modulus;
    exponent >>= 1n;
  }
  return result;
}

/**
 * Derives the session key from the Diffie-Hellman group the server sent.
 * Done over BigInt rather than crypto.createDiffieHellman because OpenSSL
 * rejects some of the groups Oracle picks and trims leading zeros off the
 * shared secret, which would shift the key Oracle expects.
 *
 * @param {number} length size in bytes of the group, and of both results
 * @returns {object} publicKey to send back, and the shared sessionKey
 */
function diffieHellman(gen, prime, serverKey, length) {
  const p = toBigInt(prime);
  const privateKey = toBigInt(crypto.randomBytes(length));
  return {
    publicKey: toBuffer(modPow(toBigInt(gen), privateKey, p), length),
    sessionKey: toBuffer(modPow(toBigInt(serverKey), privateKey, p), length)
  };
}

/**
 * Oracle restarts the CBC chain at a zero IV on every packet, so this object
 * carries no state between calls and one instance serves the whole session.
 */
class PayloadCipher {

  constructor(key) {
    this.key = key;
    this.algorithm = `aes-${key.length * 8}-cbc`;
    this.iv = Buffer.alloc(BLOCK_SIZE);
  }

  encrypt(data) {
    const padding = (BLOCK_SIZE - data.length % BLOCK_SIZE) % BLOCK_SIZE;
    const cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
    cipher.setAutoPadding(false);
    const body = Buffer.concat([data, Buffer.alloc(padding)]);
    /* The trailing byte carries the padding count biased by one. */
    return Buffer.concat([cipher.update(body), cipher.final(),
      Buffer.from([padding + 1])]);
  }

  decrypt(data) {
    const padding = data[data.length - 1];
    if ((data.length - 1) % BLOCK_SIZE != 0 || padding < 1 ||
        padding > BLOCK_SIZE) {
      errors.throwErr(errors.ERR_ANO_PACKET);
    }
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, this.iv);
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(data.subarray(0, data.length - 1)),
      decipher.final()]);
    return plain.subarray(0, data.length - padding);
  }
}

/**
 * Crypto-checksumming with the SHA-2 family. Each digest is salted with a
 * keystream block, so the send and receive chains advance once per packet and
 * a dropped or reordered packet makes every later checksum fail.
 */
class DataIntegrityHash {

  constructor(algorithm, key, iv) {
    this.algorithm = algorithm;
    this.size = crypto.createHash(algorithm).digest().length;
    this.buffer = Buffer.alloc(32);
    this.sendSalt = Buffer.alloc(this.size);
    this.recvSalt = Buffer.alloc(this.size);

    const genKey = Buffer.alloc(BLOCK_SIZE);
    key.copy(genKey, 0, 0, 5);
    genKey[5] = 0xFF;
    this.keyGen = this._cbc(genKey, iv.subarray(0, BLOCK_SIZE));
    this.init();
  }

  _cbc(key, iv) {
    const cipher = crypto.createCipheriv(`aes-${key.length * 8}-cbc`, key, iv);
    cipher.setAutoPadding(false);
    return cipher;
  }

  init() {
    this.buffer = this.keyGen.update(this.buffer);
    const key = Buffer.from(this.buffer.subarray(0, BLOCK_SIZE));
    const iv = this.buffer.subarray(BLOCK_SIZE);
    this.keyGen = this._cbc(key, iv);
    key[5] = 90;
    this.sendGen = this._cbc(key, iv);
    key[5] = 180;
    this.recvGen = this._cbc(key, iv);
  }

  compute(data) {
    this.sendSalt = this.sendGen.update(this.sendSalt);
    return crypto.createHash(this.algorithm).update(data)
      .update(this.sendSalt).digest();
  }

  validate(data) {
    const bodyLen = data.length - this.size;
    if (bodyLen <= 0) {
      errors.throwErr(errors.ERR_ANO_PACKET);
    }
    const body = data.subarray(0, bodyLen);
    this.recvSalt = this.recvGen.update(this.recvSalt);
    const expected = crypto.createHash(this.algorithm).update(body)
      .update(this.recvSalt).digest();
    if (!crypto.timingSafeEqual(expected, data.subarray(bodyLen))) {
      errors.throwErr(errors.ERR_ANO_INTEGRITY);
    }
    return body;
  }
}

module.exports = { PayloadCipher, DataIntegrityHash, diffieHellman };
