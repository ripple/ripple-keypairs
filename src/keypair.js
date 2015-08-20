'use strict';

const codec = require('ripple-address-codec');
const {
  bytesToHex,
  extendClass,
  deriveAccountIDBytes
} = require('./utils');

const KeyType = {
  secp256k1: 'secp256k1',
  ed25519: 'ed25519'
};

function KeyPair({seedBytes, publicBytes, privateBytes, node}) {
  this._seedBytes = seedBytes;
  this._publicBytes = publicBytes;
  this._privateBytes = privateBytes;
  this.is_node_key = node;
}

extendClass(KeyPair, {
  virtuals: [
    function sign() {},

    /*
    * @param {Array<Byte>} signature
    * @param {Array<Byte>} message
    */
    function verify() {},

    /*
    * @return {Array<Byte>} of bytes, in canonical form, for signing
    */
    function publicBytes() {},

    /*
    * @return {Array<Byte>} of bytes, in canonical form, with leading key type
    *                       discriminator bytes
    */
    function privateBytes() {}
  ],

  cached: [
    function publicHex() {
      return bytesToHex(this.publicBytes());
    },

    function privateHex() {
      return bytesToHex(this.privateBytes());
    },

    function idBytes() {
      return deriveAccountIDBytes(this.publicBytes());
    },

    function id() {
      return codec.encodeAccountID(this.idBytes());
    },

    function seed() {
      // seed entropy used to create the pair, if specified
      return codec.encodeSeed(this._seedBytes, this.type);
    },

    function privateKeyHex() {
      return bytesToHex(this.privateBytes());
    }
  ],

  methods: [
    function hasPrivateKey() {
      return this._privateBytes || this._seedBytes;
    },

    function signHex(message) {
      return bytesToHex(this.sign(message));
    },

    function toJSON() {
      const json = {
        publicKey: this.is_node_key ?
                codec.encodeNodePublic(this.publicBytes()) :
                this.publicHex()
      };

      const hasSeed = this._seedBytes;
      const hasPrivate = hasSeed || this._privateBytes;

      if (hasSeed) {
        json.seed = this.seed();
      }
      if (hasPrivate) {
        json.privateKey = this.privateHex();
      }
      if (!this.is_node_key) {
        json.id = this.id();
      }
      return json;
    }
  ]
});

module.exports = {
  KeyPair,
  KeyType
};
