'use strict';

const {decodeSeed, decodeNodePublic} = require('ripple-address-codec');
const hashjs = require('hash.js');
const {utils: {parseBytes}} = require('elliptic');
const Sha512 = require('./sha512');

function isVirtual(_, __, descriptor) {
  descriptor.value = function() {
    throw new Error('virtual method not implemented ');
  };
}

function cached(_, name, descriptor) {
  const computer = descriptor.value;
  const key = '_' + name;
  descriptor.value = function() {
    let value = this[key];
    if (value === undefined) {
      value = this[key] = computer.call(this);
    }
    return value;
  };
}

function toGenericArray(sequence) {
  const generic = [];
  for (let i = 0; i < sequence.length; i++) {
    generic.push(sequence[i]);
  }
  return generic;
}

function bytesToHex(a) {
  return a.map(function(byteValue) {
    const hex = byteValue.toString(16).toUpperCase();
    return hex.length > 1 ? hex : '0' + hex;
  }).join('');
}

function deriveAccountIDBytes(publicBytes) {
  const hash256 = hashjs.sha256().update(publicBytes).digest();
  const hash160 = hashjs.ripemd160().update(hash256).digest();
  return hash160;
}

function seedFromPhrase(phrase) {
  return hashjs.sha512().update(phrase).digest().slice(0, 16);
}

function parsePublicKey(publicKey) {
  if (typeof publicKey === 'string' && publicKey[0] === 'n') {
    return decodeNodePublic(publicKey);
  }
  return parseBytes(publicKey);
}

function parseSeed(seed, type='secp256k1') {
  if (typeof seed !== 'string') {
    return {bytes: seed, type};
  }
  return decodeSeed(seed);
}

function parseKey(key) {
  // parsePublicKey will parse any validator base58 if the key is a string and
  // the key starts with "n"
  const bytes = parsePublicKey(key);
  return {type: bytes.length === 33 &&
                bytes[0] === 0xED ? 'ed25519' : 'secp256k1',
          bytes};
}

module.exports = {
  cached,
  bytesToHex,
  deriveAccountIDBytes,
  isVirtual,
  seedFromPhrase,
  Sha512,
  toGenericArray,
  parseBytes,
  parsePublicKey,
  parseSeed,
  parseKey
};
