'use strict';
const assert = require('assert');
const fixtures = require('./fixtures/api.json');
const api = require('../src/api');
const decodeSeed = require('ripple-address-codec').decodeSeed;
const entropy = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

describe('api', () => {
  it('generateSeed - secp256k1', () => {
    assert.strictEqual(api.generateSeed({entropy}), fixtures.secp256k1.seed);
  });

  it('generateSeed - secp256k1, random', () => {
    const seed = api.generateSeed();
    assert(seed.charAt(0) === 's');
    const {type, bytes} = decodeSeed(seed);
    assert(type === 'secp256k1');
    assert(bytes.length === 16);
  });

  it('generateSeed - ed25519', () => {
    assert.strictEqual(api.generateSeed({entropy, algorithm: 'ed25519'}),
      fixtures.ed25519.seed);
  });

  it('generateSeed - ed25519, random', () => {
    const seed = api.generateSeed({algorithm: 'ed25519'});
    assert(seed.slice(0, 3) === 'sEd');
    const {type, bytes} = decodeSeed(seed);
    assert(type === 'ed25519');
    assert(bytes.length === 16);
  });

  it('deriveKeypair - secp256k1', () => {
    const keypair = api.deriveKeypair(fixtures.secp256k1.seed);
    assert.deepEqual(keypair, fixtures.secp256k1.keypair);
  });

  it('deriveKeypair - ed25519', () => {
    const keypair = api.deriveKeypair(fixtures.ed25519.seed);
    assert.deepEqual(keypair, fixtures.ed25519.keypair);
  });

  it('deriveAddress - secp256k1 public key', () => {
    const address = api.deriveAddress(fixtures.secp256k1.keypair.publicKey);
    assert.strictEqual(address, fixtures.secp256k1.address);
  });

  it('deriveAddress - ed25519 public key', () => {
    const address = api.deriveAddress(fixtures.ed25519.keypair.publicKey);
    assert.strictEqual(address, fixtures.ed25519.address);
  });

  it('isValidAddress - secp256k1 address valid', () => {
    assert(api.isValidAddress(fixtures.secp256k1.address));
  });

  it('isValidAddress - ed25519 address valid', () => {
    assert(api.isValidAddress(fixtures.ed25519.address));
  });

  it('isValidAddress - invalid', () => {
    assert(!api.isValidAddress(fixtures.invalid.address));
  });

  it('sign - secp256k1', () => {
    const privateKey = fixtures.secp256k1.keypair.privateKey;
    const signature = api.sign(fixtures.secp256k1.message, privateKey);
    assert.strictEqual(signature, fixtures.secp256k1.signature);
  });

  it('verify - secp256k1', () => {
    const signature = fixtures.secp256k1.signature;
    const publicKey = fixtures.secp256k1.keypair.publicKey;
    const message = fixtures.secp256k1.message;
    assert(api.verify(signature, message, publicKey));
  });

  it('sign - ed25519', () => {
    const privateKey = fixtures.ed25519.keypair.privateKey;
    const signature = api.sign(fixtures.ed25519.message, privateKey);
    assert.strictEqual(signature, fixtures.ed25519.signature);
  });

  it('verify - ed25519', () => {
    const signature = fixtures.ed25519.signature;
    const publicKey = fixtures.ed25519.keypair.publicKey;
    const message = fixtures.ed25519.message;
    assert(api.verify(signature, message, publicKey));
  });
});
