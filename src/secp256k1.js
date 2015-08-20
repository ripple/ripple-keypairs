'use strict';

const elliptic = require('elliptic');
const secp256k1 = elliptic.ec('secp256k1');
const {KeyPair, KeyType} = require('./keypair');
const utils = require('./utils');
const {Sha512, extendClass, toGenericArray, parseBytes, parsePublicKey} = utils;

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
* @param {Boolean} [opts.node=false] - generate root key-pair,
*                                              as used by nodes.
* @return {bn.js} - 256 bit scalar value
*
*/
function derivePrivate(seed, opts = {}) {
  const root = opts.node;
  const order = secp256k1.curve.n;

  // This private generator represents the `root` private key, and is what's
  // used by nodes for signing when a keypair is generated from a seed.
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

function K256Pair(options) {
  KeyPair.call(this, options);
  this.type = KeyType.secp256k1;
}

extendClass(K256Pair, {
  extends: KeyPair,
  statics: [
    /**
    * @param {String|Array} publicKey - public key in canonical form
    * @return {K256Pair} key pair
    */
    function fromPublic(publicKey) {
      return new K256Pair({publicBytes: parsePublicKey(publicKey)});
    },

    function fromPrivate(privateKey) {
      return new K256Pair({privateBytes: parseBytes(privateKey)});
    },

    function fromSeed(seedBytes, opts = {}) {
      return new K256Pair({seedBytes, node: opts.node});
    }
  ],
  methods: [
    /*
    @param {Array<Byte>} message (bytes)
     */
    function sign(message) {
      const speedup = this.speedup();
      if (speedup) {
        return toGenericArray(
          speedup.sign(new Buffer(this.hashMessage(message)),
                       this.privateBuffer(),
                       true));
      }
      return this._createSignature(message).toDER();
    },

    /*
    @param {Array<Byte>} signature - DER encoded signature bytes
    @param {Array<Byte>} message - bytes
     */
    function verify(signature, message) {
      try {
        const speedup = this.speedup();
        if (speedup) {
          return speedup.verify(new Buffer(this.hashMessage(message)),
                                new Buffer(signature),
                                this.publicBuffer());
        }
        return this.key().verify(this.hashMessage(message), signature);
      } catch (e) {
        return false;
      }
    },

    function _createSignature(message) {
      return this.key().sign(this.hashMessage(message), {canonical: true});
    },

    function _private() {
      // elliptic will happily parse bytes or a bn.js object
      return this._privateBytes ||
             derivePrivate(this._seedBytes, {node: this.is_node_key});
    },

    /*
    @param {Array<Byte>} message - (bytes)
    @return {Array<Byte>} - 256 bit hash of the message
     */
    function hashMessage(message) {
      return new Sha512().add(message).first256();
    }
  ],
  cached: [
    function speedup() {
      if (!process || !(process.env.USE_SECP256K1_SPEEDUP === 'true')) {
        return false;
      }
      try {
        return require('secp256k1');
      } catch(e) {
        return false;
      }
    },

    function privateBuffer() {
      return new Buffer(this.privateBytes());
    },

    function publicBuffer() {
      return new Buffer(this.publicBytes());
    },

    function publicBytes() {
      return this.key().getPublic().encodeCompressed();
    },

    function privateBytes() {
      return this._private().toArray('be', 32);
    },

    function key() {
      if (this.hasPrivateKey()) {
        return secp256k1.keyFromPrivate(this._private());
      }
      return secp256k1.keyFromPublic(this.publicBytes());
    }
  ]
});

module.exports = {
  K256Pair,
  accountPublicFromPublicGenerator
};
