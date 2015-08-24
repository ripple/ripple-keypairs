'use strict';
const assert = require('assert');
const brorand = require('brorand');
const hashjs = require('hash.js');
const elliptic = require('elliptic');
const Ed25519 = elliptic.eddsa('ed25519');
const Secp256k1 = elliptic.ec('secp256k1');
const addressCodec = require('ripple-address-codec');
const deriveSecret = require('./secp256k1').deriveSecret;
const utils = require('./utils');
const hexToBytes = utils.hexToBytes;
const bytesToHex = utils.bytesToHex;

function generateSeed(options = {}) {
  assert(!options.entropy || options.entropy.length >= 16, 'entropy too short');
  const entropy = options.entropy ? options.entropy.slice(0, 16) : brorand(16);
  return addressCodec.encodeSeed(entropy, options.algorithm || 'secp256k1');
}

const secp256k1 = {
  deriveKeypair: function(entropy, options) {
    const prefix = '00';
    const privateKey = prefix + deriveSecret(entropy, options)
      .toString(16, 64).toUpperCase();
    const publicKey = bytesToHex(
      Secp256k1.keyFromPrivate(privateKey).getPublic().encodeCompressed());
    return {privateKey, publicKey};
  },
  sign: function(message, privateKey) {
    const digest = hashjs.sha512().update(message).digest().slice(0, 32);
    const key = Secp256k1.keyFromPrivate(hexToBytes(privateKey));
    return bytesToHex(key.sign(digest, {canonical: true}).toDER());
  },
  verify: function(signature, message, publicKey) {
    const key = Secp256k1.keyFromPublic(hexToBytes(publicKey));
    const digest = hashjs.sha512().update(message).digest().slice(0, 32);
    return key.verify(digest, signature);
  }
};

const ed25519 = {
  deriveKeypair: function(entropy) {
    const prefix = 'ED';
    const rawPrivateKey = new utils.Sha512().add(entropy).first256();
    const privateKey = prefix + bytesToHex(rawPrivateKey);
    const publicKey = prefix + bytesToHex(
      Ed25519.keyFromSecret(rawPrivateKey).pubBytes());
    return {privateKey, publicKey};
  },
  sign: function(message, privateKey) {
    const key = Ed25519.keyFromSecret(hexToBytes(privateKey).slice(1));
    return bytesToHex(key.sign(message).toBytes());
  },
  verify: function(signature, message, publicKey) {
    const key = Ed25519.keyFromPublic(hexToBytes(publicKey).slice(1));
    return key.verify(message, hexToBytes(signature));
  }
};

function select(algorithm) {
  const methods = {secp256k1, ed25519};
  return methods[algorithm];
}

function deriveKeypair(seed, options) {
  const decoded = addressCodec.decodeSeed(seed);
  return select(decoded.type).deriveKeypair(decoded.bytes, options);
}

function getAlgorithmFromKey(key) {
  const bytes = hexToBytes(key);
  return (bytes.length === 33 && bytes[0] === 0xED) ? 'ed25519' : 'secp256k1';
}

function sign(message, privateKey) {
  const algorithm = getAlgorithmFromKey(privateKey);
  return select(algorithm).sign(message, privateKey);
}

function verify(signature, message, publicKey) {
  const algorithm = getAlgorithmFromKey(publicKey);
  return select(algorithm).verify(signature, message, publicKey);
}

function deriveAddress(publicKey) {
  return addressCodec.encodeAccountID(
    utils.deriveAccountIDBytes(hexToBytes(publicKey)));
}

function isValidAddress(address) {
  try {
    const bytes = addressCodec.decodeAccountID(address);
    return bytes.length === 20;
  } catch (error) {
    return false;
  }
}

module.exports = {
  generateSeed,
  deriveKeypair,
  sign,
  verify,
  deriveAddress,
  isValidAddress
};
