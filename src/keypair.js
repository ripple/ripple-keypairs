'use strict';

const codec = require('ripple-address-codec');
const {
  bytesToHex,
  cached,
  isVirtual,
  deriveAccountIDBytes
} = require('./utils');

const KeyType = {
  secp256k1: 'secp256k1',
  ed25519: 'ed25519'
};

class KeyPair {
  constructor({seedBytes, publicBytes, privateBytes}) {
    this._seedBytes = seedBytes;
    this._publicBytes = publicBytes;
    this._privateBytes = privateBytes;
  }

  /*
  * @param {Array} message
  */
  @isVirtual
  sign() {}

  /*
  * @param {Array<Byte>} signature
  * @param {Array<Byte>} message
  */
  @isVirtual
  verify() {}

  /*
  * @return {Array<Byte>} of bytes, in canonical form, for signing
  */
  @isVirtual
  publicBytes() {}

  /*
  * @return {Array<Byte>} of bytes, in canonical form, with leading key type
  *                       discriminator bytes
  */
  @isVirtual
  privateBytes() {}

  @cached
  publicHex() {
    return bytesToHex(this.publicBytes());
  }

  @cached
  privateHex() {
    return bytesToHex(this.privateBytes());
  }

  @cached
  idBytes() {
    return deriveAccountIDBytes(this.publicBytes());
  }

  hasPrivateKey() {
    return this._privateBytes || this._seedBytes;
  }

  /**
  * The canonical keypair
  */
  @cached
  id() {
    return codec.encodeAccountID(this.idBytes());
  }

  @cached
  seed() {
    // seed entropy used to create the pair, if specified
    return codec.encodeSeed(this._seedBytes, this.type);
  }

  @cached
  privateKeyHex() {
    return bytesToHex(this.privateBytes());
  }

  signHex(message) {
    return bytesToHex(this.sign(message));
  }

  toJSON() {
    const json = {
      publicKey: this.validator ?
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
    if (!this.validator) {
      json.id = this.id();
    }
    return json;
  }
}

module.exports = {
  KeyPair,
  KeyType
};
