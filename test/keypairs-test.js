'use strict';

const codec = require('ripple-address-codec');
const assert = require('assert-diff');
const _ = require('lodash');
const fs = require('fs');

const utils = require('../src/utils');
const keypairs = require('../src');
const {K256Pair} = require('../src/secp256k1');
const {KeyType} = require('../src/keypair');
const {Ed25519Pair} = require('../src/ed25519');

const {
  verify,
  sign,
  keyPairFromSeed,
  seedFromPhrase,
  generateAccountKeys,
  accountKeysFromSeed,
  accountKeysFromPhrase,
  generateNodeKeys,
  nodeKeysFromSeed,
  nodeKeysFromPhrase,
  nodePublicAccountID
} = keypairs;

const {SerializedObject} = require('ripple-lib');
const TX_HASH_PREFIX_SIGN = [0x53, 0x54, 0x58, 0x00];

const FIXTURES = {
  message: [0xB, 0xE, 0xE, 0xF],

  tx_json: {
    Account: 'rJZdUusLDtY9NEsGea7ijqhVrXv98rYBYN',
    Amount: '1000',
    Destination: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    Fee: '10',
    Flags: 2147483648,
    Sequence: 1,
    SigningPubKey: 'EDD3993CDC6647896C455F136648B7750' +
                   '723B011475547AF60691AA3D7438E021D',
    TransactionType: 'Payment',
    expected_sig: 'C3646313B08EED6AF4392261A31B961F' +
                  '10C66CB733DB7F6CD9EAB079857834C8' +
                  'B0334270A2C037E63CDCCC1932E08328' +
                  '82B7B7066ECD2FAEDEB4A83DF8AE6303'
  }
};

function numberOfTests({whenCI, always}) {
  return process.env.CI ? whenCI : always;
}

function loadFixtureJSON(name) {
  const fixturesFile = __dirname + '/fixtures/' + name;
  return JSON.parse(fs.readFileSync(fixturesFile).toString());
}

describe('ed25519', function() {
  let pair;

  before(function() {
    pair = Ed25519Pair.fromSeed(seedFromPhrase('niq'));
  });

  it('can be constructed from a public key to verify a txn', function() {
    const sig = pair.sign(FIXTURES.message);
    const key = Ed25519Pair.fromPublic(pair.publicBytes());
    assert(key.verify(sig, FIXTURES.message));
    assert(!key.verify(sig, FIXTURES.message.concat(0)));
  });

  it('can be serve as the work horse for the `verify` method', function() {
    const sig = pair.sign(FIXTURES.message);
    const key = Ed25519Pair.fromPublic(pair.publicBytes());
    assert(key.verify(sig, FIXTURES.message));
    assert(!key.verify(sig, FIXTURES.message.concat(0)));
  });

  it('can be used from a secret key to resign a txn', function() {
    const sig = pair.sign(FIXTURES.message);
    assert.deepEqual(sign(FIXTURES.message, pair.privateBytes()), sig);
  });

  it('has a String member `type` equal to KeyPair.ed25519 constant',
      function() {
    assert.equal(pair.type, KeyType.ed25519);
  });

  it('has a public key representation beginning with ED', function() {
    const pub_hex = pair.publicHex();
    assert(pub_hex.length === 66);
    assert(pub_hex.slice(0, 2) === 'ED');
  });
  it('derives the same keypair for a given passphrase as rippled', function() {
    const pub_hex = pair.publicHex();
    const target_hex = 'EDD3993CDC6647896C455F136648B7750' +
                   '723B011475547AF60691AA3D7438E021D';
    assert.equal(pub_hex, target_hex);
  });
  it('generates the same account_id as rippled for a given keypair',
      function() {
    assert.equal(pair.id(),
                 'rJZdUusLDtY9NEsGea7ijqhVrXv98rYBYN');
  });
  it('creates signatures that are a function of secret/message', function() {
    const signature = pair.sign(FIXTURES.message);
    assert(Array.isArray(signature));
    assert(pair.verify(signature, FIXTURES.message));
  });
  it('signs transactions exactly as rippled', function() {
    const so = SerializedObject.from_json(FIXTURES.tx_json);
    const message = TX_HASH_PREFIX_SIGN.concat(so.buffer);
    const sig = pair.signHex(message);
    assert.equal(sig, FIXTURES.tx_json.expected_sig);
  });
});

describe('keyPairFromSeed', function() {
  it('returns an Ed25519Pair from an ed25519 seed', function() {
    const pair = keyPairFromSeed('sEdTM1uX8pu2do5XvTnutH6HsouMaM2');
    assert.equal(pair.type, KeyType.ed25519);
  });
  it('returns a K256Pair from an secp256k1 (default) seed', function() {
    const pair = keyPairFromSeed('sn259rEFXrQrWyx3Q7XneWcwV6dfL');
    assert.equal(pair.type, KeyType.secp256k1);
  });
  it('can be intantiated with an array of bytes', function() {
    const seed = 'sn259rEFXrQrWyx3Q7XneWcwV6dfL';
    const {bytes} = codec.decodeSeed(seed);
    const pair = keyPairFromSeed(bytes);
    assert.equal(pair.type, KeyType.secp256k1);
    assert.equal(pair.seed(), seed);
  });
});

describe('accountKeysFromPhrase', function() {
  it('can gan generate ed25519 wallets', function() {
    const expected = {
      seed: 'sEd7rBGm5kxzauRTAV2hbsNz7N45X91',
      id: 'rJZdUusLDtY9NEsGea7ijqhVrXv98rYBYN',
      privateKey:
        'ED' +
          'C99B2B037295A6A0F8DBFEA341ED1FC5A7BE6882D7E8DC287C2F4498B87A933A',
      publicKey:
        'ED' +
        'D3993CDC6647896C455F136648B7750723B011475547AF60691AA3D7438E021D'
    };
    const wallet = accountKeysFromPhrase('niq', 'ed25519');
    assert.deepEqual(wallet, expected);
  });
  it('generates secp256k1 wallets by default', function() {
    const expected = {
      seed: 'shQUG1pmPYrcnSUGeuJFJTA1b3JSL',
      id: 'rNvfq2SVbCiio1zkN5WwLQW8CHgy2dUoQi',
      privateKey:
        '152E883D92D57814CC0B4E00C1449F153BF59965C78F5ADE7E0B15B3EDE3915C',
      publicKey:
        '02' +
        '1E788CDEB9104C9179C3869250A89999C1AFF92D2C3FF7925A1696835EA3D840'
    };
    const wallet = accountKeysFromPhrase('niq');
    assert.deepEqual(wallet, expected);
  });
});

describe('nodeKeysFromPhrase', function() {
  it('generates keys used by node nodes/nodes', function() {
    const expected = {
      seed: 'shQUG1pmPYrcnSUGeuJFJTA1b3JSL',
      publicKey: 'n9KNees3ippJvi7ZT1GqHMCmEmmkCVPxQRPfU5tPzmg9MtWevpjP',
      privateKey:
        '90959EDC6D5C97941CA33F37E60C1AE9CD5098137D7029443E56377D9E37CE3C'
    };
    const wallet = nodeKeysFromPhrase('niq');
    assert.deepEqual(wallet, expected);
  });
});

describe('generateAccountKeys', function() {
  const entropy = _.fill(Array(16), 0);

  it('can generate ed25519 wallets', function() {
    const expected = {
      seed: 'sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE',
      id: 'r9zRhGr7b6xPekLvT6wP4qNdWMryaumZS7',
      privateKey:
        'ED0B6CBAC838DFE7F47EA1BD0DF00EC282FDF45510C92161072CCFB84035390C4D',
      publicKey:
        'ED' +
        '1A7C082846CFF58FF9A892BA4BA2593151CCF1DBA59F37714CC9ED39824AF85F'
    };
    const actual = generateAccountKeys({type: 'ed25519', entropy});
    assert.deepEqual(actual, expected);
    assert.deepEqual(accountKeysFromSeed(actual.seed), expected);
  });
  it('can generate secp256k1 wallets (by default)', function() {
    const expected = {
      seed: 'sp6JS7f14BuwFY8Mw6bTtLKWauoUs',
      id: 'rGCkuB7PBr5tNy68tPEABEtcdno4hE6Y7f',
      privateKey:
        '2512BBDFDBB77510883B7DCCBEF270B86DEAC8B64AC762873D75A1BEE6298665',
      publicKey:
        '03' +
        '90A196799EE412284A5D80BF78C3E84CBB80E1437A0AECD9ADF94D7FEAAFA284'
    };
    const actual = generateAccountKeys({type: undefined, entropy});
    assert.deepEqual(actual, expected);
    assert.deepEqual(accountKeysFromSeed(actual.seed), expected);
  });
});

describe('generateNodeKeys', function() {
  const entropy = _.fill(Array(16), 0);
  it('can generate secp256k1 node keys', function() {
    /*
    rippled validation_create 00000000000000000000000000000000
    {
       "result" : {
          "status" : "success",
          "validation_key" : "A A A A A A A A A A A A",
          "validation_public_key" :
              "n9LPxYzbDpWBZ1bC3J3Fdkgqoa3FEhVKCnS8yKp7RFQFwuvd8Q2c",
          "validation_seed" : "sp6JS7f14BuwFY8Mw6bTtLKWauoUs"
       }
    }
    */
    const expected = {
      seed: 'sp6JS7f14BuwFY8Mw6bTtLKWauoUs',
      publicKey: 'n9LPxYzbDpWBZ1bC3J3Fdkgqoa3FEhVKCnS8yKp7RFQFwuvd8Q2c',
      privateKey:
        'D296B892B3A7964BD0CC882FC7C0BE948B6BBD8EB1EFF8C13942FCAABF1F3877'
    };
    const actual = generateNodeKeys({entropy});
    assert.deepEqual(actual, expected);
    assert.deepEqual(nodeKeysFromSeed(actual.seed), expected);
  });

  it('can generate the correct accountID from node public key', () => {
    const accountID = 'rhcfR9Cg98qCxHpCcPBmMonbDBXo84wyTn';
    const nodePublic =
          'n9MXXueo837zYH36DvMc13BwHcqtfAWNJY5czWVbp7uYTj7x17TH';
    assert.equal(nodePublicAccountID(nodePublic), accountID);
  });
});

function withSpeedUp(useSpeedUp, func) {
  return function() {
    process.env.USE_SECP256K1_SPEEDUP = useSpeedUp ? 'true' : '';

    let erred = false;
    try {
      func.apply(this, arguments);
    } catch(e) {
      erred = e;
    }
    process.env.USE_SECP256K1_SPEEDUP = '';
    if (erred) {
      throw erred;
    }
  };
}

describe('secp256k1', function() {
  function makeTests({useSpeedUp}) {
    const expected = loadFixtureJSON('secp256k1-sigs.json');
    const withSpeed = _.partial(withSpeedUp, useSpeedUp);

    let key;
    before(withSpeedUp(
      useSpeedUp,
      function() {
        key = K256Pair.fromSeed(seedFromPhrase('niq'));
        key.speedup(); // Important: so it's ready to go!
        assert.equal(Boolean(key.speedup()), useSpeedUp);
      })
    );

    function test_factory(i) {
      let message, sig;

      before(function() {
        message = [i];
        sig = key.sign(message);
      });

      describe('message [' + i + ']', function() {
        it('can deterministically sign/verify', withSpeed(function() {
          if (expected[i]) {
            assert.equal(utils.bytesToHex(sig), expected[i]);
          }
          assert(key.verify(sig, message));
        }));
        it('can sign again using prederived key', withSpeed(function() {
          assert.deepEqual(sign(message, key.privateBytes()), sig);
        }));
        it('can verify with just a public key', withSpeed(function() {
          assert(verify(sig, message, key.publicBytes()));
          assert(!verify(sig, message.concat(0), key.publicBytes()));
        }));
      });
    }

    const numTests = numberOfTests({whenCI: expected.length, always: 10});

    for (let n = 0; n < numTests; n++) {
      test_factory(n);
    }
  }
  describe('generated tests (speedup)', function() {
    makeTests({useSpeedUp: true});
  });
  describe('generated tests (elliptic)', function() {
    makeTests({useSpeedUp: false});
  });
});
