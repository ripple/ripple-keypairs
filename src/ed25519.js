'use strict';

const elliptic = require('elliptic');
const Ed25519 = elliptic.eddsa('ed25519');
const {KeyPair, KeyType} = require('./keypair');
const {Sha512, cached, parseBytes} = require('./utils');

/*
@param {Array} seed bytes
 */
function deriveEdKeyPairPrivate(seed) {
  return new Sha512().add(seed).first256();
}

class Ed25519Pair extends KeyPair {
  constructor(options) {
    super(options);
    this.type = KeyType.ed25519;
  }

  /**
  * @param {String|Array} publicKey - public key in canonical form
  *                                   (0xED + 32 bytes)
  * @return {Ed25519Pair} key pair
  */
  static fromPublic(publicKey) {
    return new Ed25519Pair({publicBytes: parseBytes(publicKey)});
  }

  static fromPrivate(privateKey) {
    return new Ed25519Pair({privateBytes: parseBytes(privateKey)});
  }

  /**
  * @param {Array<Number>} seedBytes - A 128 bit seed
  * @return {Ed25519Pair} key pair
  */
  static fromSeed(seedBytes) {
    return new Ed25519Pair({seedBytes});
  }


  sign(message) {
    return this.key().sign(message).toBytes();
  }

  verify(signature, message) {
    return this.key().verify(message, signature);
  }

  @cached
  publicBytes() {
    return [0xED].concat(this.key().pubBytes());
  }

  @cached
  privateBytes() {
    return [0xED].concat(this._privateKeySigningBytes());
  }

  @cached
  _privateKeySigningBytes() {
    return this._privateBytes ? this._privateBytes.slice(1) :
                               deriveEdKeyPairPrivate(this._seedBytes);
  }

  @cached
  key() {
    if (this.hasPrivateKey()) {
      return Ed25519.keyFromSecret(this._privateKeySigningBytes());
    }
    return Ed25519.keyFromPublic(this.publicBytes().slice(1));
  }
}

module.exports = {
  Ed25519Pair
};
