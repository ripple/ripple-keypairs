'use strict';

const assert = require('assert');
const brorand = require('brorand');
const codec = require('ripple-address-codec');
const utils = require('./utils');
const {KeyType} = require('./keypair');
const {Ed25519Pair} = require('./ed25519');
const {K256Pair, accountPublicFromPublicGenerator} = require('./secp256k1');
const {decodeSeed, encodeAccountID} = codec;
const {seedFromPhrase,
       parsePublicKey,
       deriveAccountIDBytes,
       parseSeed,
       parseKey} = utils;

function nodePublicAccountID(publicKey) {
  const generatorBytes = parsePublicKey(publicKey);
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes);
  return encodeAccountID(deriveAccountIDBytes(accountPublicBytes));
}

function pairContructor(type) {
  return type === 'ed25519' ? Ed25519Pair : K256Pair;
}

function keyPairFromSeed(seed, type = KeyType.secp256k1, options) {
  if (typeof seed === 'string') {
    const decoded = decodeSeed(seed);
    const optionsArg = type;
    return keyPairFromSeed(decoded.bytes, decoded.type, optionsArg);
  }
  assert(type === KeyType.secp256k1 || type === KeyType.ed25519);
  return pairContructor(type).fromSeed(seed, options);
}

function keyPairFromPublic(publicKey) {
  const key = parseKey(publicKey);
  return pairContructor(key.type).fromPublic(key.bytes);
}

function keyPairFromPrivate(publicKey) {
  const key = parseKey(publicKey);
  return pairContructor(key.type).fromPrivate(key.bytes);
}

function deriveAccountKeys(seedBytes, type) {
  return keyPairFromSeed(seedBytes, type).toJSON();
}

function deriveNodeKeys(seedBytes) {
  return K256Pair.fromSeed(seedBytes, {node: true}).toJSON();
}

function generateAccountKeys(opts = {}) {
  const seedBytes = opts.entropy || brorand(16);
  return deriveAccountKeys(seedBytes, opts.type);
}

function accountKeysFromSeed(seed, seedType) {
  const {type, bytes} = parseSeed(seed, seedType);
  return deriveAccountKeys(bytes, type);
}

function accountKeysFromPhrase(phrase, seedType) {
  return deriveAccountKeys(seedFromPhrase(phrase), seedType);
}

function generateNodeKeys(opts = {}) {
  return deriveNodeKeys(opts.entropy || brorand(16));
}

function nodeKeysFromSeed(seed, seedType) {
  const {type, bytes} = parseSeed(seed, seedType);
  assert(type === KeyType.secp256k1);
  return deriveNodeKeys(bytes);
}

function nodeKeysFromPhrase(phrase) {
  return deriveNodeKeys(seedFromPhrase(phrase));
}

function sign(message, privateKey) {
  return keyPairFromPrivate(privateKey).sign(message);
}

function verify(signature, message, publicKey) {
  return keyPairFromPublic(publicKey).verify(signature, message);
}

module.exports = {
  generateAccountKeys,
  accountKeysFromSeed,
  sign,
  verify,

  keyPairFromPublic,
  keyPairFromSeed,
  keyPairFromPrivate,

  seedFromPhrase,
  nodePublicAccountID,
  deriveAccountIDBytes,
  accountKeysFromPhrase,
  generateNodeKeys,
  nodeKeysFromSeed,
  nodeKeysFromPhrase
};
