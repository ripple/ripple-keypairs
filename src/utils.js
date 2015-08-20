'use strict';

const util = require('util');
const {decodeSeed, decodeNodePublic} = require('ripple-address-codec');
const hashjs = require('hash.js');
const {utils: {parseBytes}} = require('elliptic');
const Sha512 = require('./sha512');

function extendClass(klass, definition) {
  if (definition.extends) {
    util.inherits(klass, definition.extends);
  }
  const proto = klass.prototype;
  const allMethods = klass._allMethods = [];
  function addFunc(original, wrapper) {
    proto[original.name] = wrapper;
    allMethods.push(original.name);
  }
  (definition.virtuals || []).forEach(f => {
    addFunc(f, function() {
      throw new Error('unimplemented');
    });
  });
  (definition.methods || []).forEach(f => {
    addFunc(f, f);
  });
  (definition.statics || []).forEach(f => {
    klass[f.name] = f;
  });
  (definition.cached || []).forEach(f => {
    const key = '_' + f.name;
    addFunc(f, function() {
      let value = this[key];
      if (value === undefined) {
        value = this[key] = f.call(this);
      }
      return value;
    });
  });
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

function parseSeed(seed, type = 'secp256k1') {
  if (typeof seed !== 'string') {
    return {bytes: seed, type};
  }
  return decodeSeed(seed);
}

function parseKey(key) {
  // parsePublicKey will parse any node base58 if the key is a string and
  // the key starts with "n"
  const bytes = parsePublicKey(key);
  return {type: bytes.length === 33 &&
                bytes[0] === 0xED ? 'ed25519' : 'secp256k1',
          bytes};
}

module.exports = {
  bytesToHex,
  deriveAccountIDBytes,
  extendClass,
  seedFromPhrase,
  Sha512,
  toGenericArray,
  parseBytes,
  parsePublicKey,
  parseSeed,
  parseKey
};
