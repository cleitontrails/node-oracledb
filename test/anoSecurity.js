/* Copyright (c) 2025, Oracle and/or its affiliates. */

/******************************************************************************
 *
 * This software is dual-licensed to you under the Universal Permissive License
 * (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl and Apache License
 * 2.0 as shown at https://www.apache.org/licenses/LICENSE-2.0. You may choose
 * either license.
 *
 * If you elect to accept the software under the Apache License, Version 2.0,
 * the following applies:
 *
 * Licensed under the Apache License, Version 2.0 (the `License`);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an `AS IS` BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * NAME
 *   327. anoSecurity.js
 *
 * DESCRIPTION
 *   Tests the Native Network Encryption primitives used by the Advanced
 *   Networking Option. The expected values come from go-ora, whose output a
 *   live Oracle server accepts; a difference of one byte in key derivation or
 *   in the chaining would be rejected by the server and not by any local test.
 *
 *****************************************************************************/
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { PayloadCipher, DataIntegrityHash, diffieHellman } =
  require('../lib/thin/sqlnet/anoSecurity.js');

const KEY = Buffer.from(
  '00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9', 'hex');
const IV = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf', 'hex');

function counted(length) {
  return Buffer.from(Array.from({ length }, (_, i) => i & 0xFF));
}

describe('327. anoSecurity.js', function() {

  describe('327.1 AES payload cipher', function() {

    const expected = {
      0: '01',
      1: '179ba2eaca25a8a605a8b5b130d5dd0510',
      15: '11895a0122d95b8d667ebf341334a47902',
      16: '10a8c1bd5b39414ac6a03bad808e70e101',
      17: '10a8c1bd5b39414ac6a03bad808e70e12b6104cf03ef0f17c6d5b108b76872e310'
    };

    it('327.1.1 matches the reference ciphertext', function() {
      const cipher = new PayloadCipher(KEY);
      for (const [length, hex] of Object.entries(expected)) {
        assert.strictEqual(cipher.encrypt(counted(Number(length))).toString('hex'),
          hex, `payload of ${length} bytes`);
      }
    });

    it('327.1.2 restarts the chain on every packet', function() {
      const cipher = new PayloadCipher(KEY);
      const first = cipher.encrypt(counted(64));
      assert.deepStrictEqual(cipher.encrypt(counted(64)), first);
    });

    it('327.1.3 round trips every length across a block boundary', function() {
      const cipher = new PayloadCipher(KEY);
      for (let length = 0; length <= 40; length++) {
        const plain = counted(length);
        assert.deepStrictEqual(cipher.decrypt(cipher.encrypt(plain)), plain,
          `payload of ${length} bytes`);
      }
    });

    it('327.1.4 rejects a truncated packet', function() {
      const cipher = new PayloadCipher(KEY);
      const packet = cipher.encrypt(counted(32));
      assert.throws(() => cipher.decrypt(packet.subarray(0, packet.length - 1)),
        /NJS-531/);
    });

    it('327.1.5 keys every AES size off the same secret', function() {
      for (const size of [16, 24, 32]) {
        const cipher = new PayloadCipher(KEY.subarray(0, size));
        assert.deepStrictEqual(cipher.decrypt(cipher.encrypt(counted(50))),
          counted(50));
      }
    });
  });

  describe('327.2 crypto-checksum', function() {

    const expected = [
      'bbd2c651d22cb6b0f4d1df0504ad65d038b0b492e9761fe1816c35626af7e2e0',
      '36e14a4ea68924ba502322c79adb992c7003447f726397f4a6538a26ea778618',
      'c5ebe683a3894be5239f1c10377a0d217026fd735db116d97827dfb20002095e',
      '2c484cde2d0ef3f3b51eed38dca8afa49ce5d5f07a19ced077520bd95541ca20'
    ];

    it('327.2.1 matches the reference digest chain', function() {
      const hash = new DataIntegrityHash('sha256', KEY, IV);
      expected.forEach((hex, i) => {
        assert.strictEqual(
          hash.compute(Buffer.from(`pacote de dados numero ${i}`)).toString('hex'),
          hex, `packet ${i}`);
      });
    });

    it('327.2.2 salts each packet differently', function() {
      const hash = new DataIntegrityHash('sha256', KEY, IV);
      const body = Buffer.from('mesmo conteudo');
      assert.notDeepStrictEqual(hash.compute(body), hash.compute(body));
    });

    it('327.2.3 rejects a tampered packet', function() {
      const hash = new DataIntegrityHash('sha256', KEY, IV);
      const forged = Buffer.concat([Buffer.from('resposta'), Buffer.alloc(32)]);
      assert.throws(() => hash.validate(forged), /NJS-537/);
    });

    it('327.2.4 rejects a packet shorter than its digest', function() {
      const hash = new DataIntegrityHash('sha256', KEY, IV);
      assert.throws(() => hash.validate(Buffer.alloc(32)), /NJS-531/);
    });

    it('327.2.5 supports the wider SHA-2 digests', function() {
      for (const algorithm of ['sha256', 'sha384', 'sha512']) {
        const hash = new DataIntegrityHash(algorithm, KEY, IV);
        const size = crypto.createHash(algorithm).digest().length;
        assert.strictEqual(hash.compute(Buffer.from('x')).length, size);
      }
    });
  });

  describe('327.3 Diffie-Hellman', function() {

    function modPow(base, exponent, modulus) {
      let result = 1n;
      base %= modulus;
      while (exponent > 0n) {
        if (exponent & 1n) result = result * base % modulus;
        base = base * base % modulus;
        exponent >>= 1n;
      }
      return result;
    }

    it('327.3.1 agrees with the peer on the session key', function() {
      const group = crypto.createDiffieHellman(512);
      const prime = BigInt('0x' + group.getPrime('hex'));
      const gen = BigInt('0x' + group.getGenerator('hex'));
      const length = group.getPrime().length;

      const serverPrivate = BigInt('0x' + crypto.randomBytes(length).toString('hex'));
      const serverPublic = modPow(gen, serverPrivate, prime);

      const keys = diffieHellman(group.getGenerator(),
        group.getPrime(),
        Buffer.from(serverPublic.toString(16).padStart(length * 2, '0'), 'hex'),
        length);

      const peerView = modPow(BigInt('0x' + keys.publicKey.toString('hex')),
        serverPrivate, prime);
      assert.strictEqual(BigInt('0x' + keys.sessionKey.toString('hex')), peerView);
    });

    it('327.3.2 pads both keys to the size of the group', function() {
      const group = crypto.createDiffieHellman(512);
      const length = group.getPrime().length;
      const keys = diffieHellman(group.getGenerator(), group.getPrime(),
        Buffer.alloc(length, 1), length);
      assert.strictEqual(keys.publicKey.length, length);
      assert.strictEqual(keys.sessionKey.length, length);
    });
  });
});
