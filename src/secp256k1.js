'use strict';

const elliptic = require('elliptic');
const secp256k1 = elliptic.ec('secp256k1');
const hashjs = require('hash.js');
const {KeyPair, KeyType} = require('./keypair');
const {Sha512, cached} = require('./utils');

function deriveScalar(bytes, discrim) {
  const order = secp256k1.curve.n;
  for (let i = 0; i <= 0xFFFFFFFF; i++) {
    // We hash the bytes to find a 256 bit number, looping until we are sure it
    // is less than the order of the curve.
    const hasher = new Sha512().add(bytes);
    // If the optional discriminator index was passed in, update the hash.
    if (discrim !== undefined) {
      hasher.addU32(discrim);
    }
    hasher.addU32(i);
    const key = hasher.first256BN();
    if (key.cmpn(0) > 0 && key.cmp(order) < 0) {
      return key;
    }
  }
  throw new Error('impossible unicorn ;)');
}

/**
* @param {Array} seed - bytes
* @param {Object} [opts] - object
* @param {Number} [opts.accountIndex=0] - the account number to generate
* @param {Boolean} [opts.validator=false] - generate root key-pair,
*                                              as used by validators.
* @return {bn.js} - 256 bit scalar value
*
*/
function deriveSecret(seed, opts = {}) {
  const root = opts.validator;
  const order = secp256k1.curve.n;

  // This private generator represents the `root` private key, and is what's
  // used by validators for signing when a keypair is generated from a seed.
  const privateGen = deriveScalar(seed);
  if (root) {
    // As returned by validation_create for a given seed
    return privateGen;
  }
  const publicGen = secp256k1.g.mul(privateGen);
  // A seed can generate many keypairs as a function of the seed and a uint32.
  // Almost everyone just uses the first account, `0`.
  const accountIndex = opts.accountIndex || 0;
  return deriveScalar(publicGen.encodeCompressed(), accountIndex)
            .add(privateGen).mod(order);
}

function accountPublicFromPublicGenerator(publicGenBytes) {
  const rootPubPoint = secp256k1.curve.decodePoint(publicGenBytes);
  const scalar = deriveScalar(publicGenBytes, 0);
  const point = secp256k1.g.mul(scalar);
  const offset = rootPubPoint.add(point);
  return offset.encodeCompressed();
}

class K256Pair extends KeyPair {
  constructor(options) {
    super(options);
    this.type = KeyType.secp256k1;
    this.validator = options.validator;
  }

  static fromSeed(seedBytes, opts = {}) {
    return new K256Pair({seedBytes, validator: opts.validator});
  }

  /*
  @param {Array<Byte>} message (bytes)
   */
  sign(message) {
    return this._createSignature(message).toDER();
  }

  /*
  @param {Array<Byte>} message - bytes
  @param {Array<Byte>} signature - DER encoded signature bytes
   */
  verify(message, signature) {
    try {
      return this.key().verify(this.hashMessage(message), signature);
      /* eslint-disable no-catch-shadow */
    } catch (e) {
      /* eslint-enable no-catch-shadow */
      return false;
    }
  }

  @cached
  pubKeyCanonicalBytes() {
    return this.key().getPublic().encodeCompressed();
  }

  _createSignature(message) {
    return this.key().sign(this.hashMessage(message), {canonical: true});
  }

  /*
  @param {Array<Byte>} message - (bytes)
  @return {Array<Byte>} - 256 bit hash of the message
   */
  hashMessage(message) {
    return hashjs.sha512().update(message).digest().slice(0, 32);
  }

  @cached
  key() {
    if (this.seedBytes) {
      const options = {validator: this.validator};
      return secp256k1.keyFromPrivate(deriveSecret(this.seedBytes, options));
    }
    return secp256k1.keyFromPublic(this.pubKeyCanonicalBytes());
  }

}

module.exports = {
  K256Pair,
  deriveSecret,
  accountPublicFromPublicGenerator
};
