'use strict';

// Known-answer tests for the cryptography the address module carries itself. Each block names where its
// expected values come from. Where Node's own crypto (OpenSSL) can compute the same thing, the vendored
// code is also compared with it on random inputs.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { keccak256, sponge } = require('../src/address/crypto/keccak');
const { ripemd160, ripemd160Vendored, NODE_HAS_RIPEMD160 } = require('../src/address/crypto/ripemd160');
const base58 = require('../src/address/crypto/base58');
const bech32 = require('../src/address/crypto/bech32');
const cashaddr = require('../src/address/crypto/cashaddr');
const secp256k1 = require('../src/address/crypto/secp256k1');
const ed25519 = require('../src/address/crypto/ed25519');
const { fromBytesLE, toBytesBE } = require('../src/address/crypto/bigint');

const hex = text => Buffer.from(text, 'hex');

describe('Keccak-256', () => {
    // Keccak team, ShortMsgKAT_256.txt from the round 3 SHA-3 submission (Len = 0, 8 and 16 bits), and the
    // Keccak-256 values Ethereum tooling lists for "abc" and the pangram.
    const KATS = [
        ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
        ['cc', 'eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a'],
        ['41fb', 'a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2'],
        [Buffer.from('abc').toString('hex'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
        [Buffer.from('The quick brown fox jumps over the lazy dog').toString('hex'), '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'],
    ];
    for (const [input, digest] of KATS) {
        it(`of "${input}"`, () => assert.equal(keccak256(hex(input)).toString('hex'), digest));
    }

    it('is not SHA3-256, which Node offers', () => {
        assert.notEqual(keccak256(Buffer.alloc(0)).toString('hex'), crypto.createHash('sha3-256').update('').digest('hex'));
    });

    it('runs the same permutation and sponge as SHA3-256 and SHA3-512 when given their padding, at every length up to three blocks', () => {
        for (let length = 0; length <= 3 * 136 + 1; length++) {
            const data = crypto.randomBytes(length);
            assert.deepEqual(sponge(136, 0x06, data, 32), crypto.createHash('sha3-256').update(data).digest(), `sha3-256, ${length} bytes`);
            assert.deepEqual(sponge(72, 0x06, data, 64), crypto.createHash('sha3-512').update(data).digest(), `sha3-512, ${length} bytes`);
        }
    });
});

describe('RIPEMD-160', () => {
    // The test vectors on the RIPEMD-160 page by Antoon Bosselaers (homes.esat.kuleuven.be/~bosselae/ripemd160.html).
    const KATS = [
        ['', '9c1185a5c5e9fc54612808977ee8f548b2258d31'],
        ['a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'],
        ['abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
        ['message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'],
        ['abcdefghijklmnopqrstuvwxyz', 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'],
        ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '12a053384a9c0c88e405a06c27dcf49ada62eb2b'],
        ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'b0e20b6e3116640286ed3a87a5713079b21f5189'],
        ['1234567890'.repeat(8), '9b752e45573d4b39f4dbd3323cab82bf63326bfb'],
        ['a'.repeat(1000000), '52783243c1697bdbe16d37f97f68f08325dc1528'],
    ];

    describe('the vendored copy, which is always tested', () => {
        for (const [input, digest] of KATS) {
            it(`of ${input.length > 64 ? `${input.length} characters` : `"${input}"`}`, () => {
                assert.equal(ripemd160Vendored(Buffer.from(input, 'latin1')).toString('hex'), digest);
            });
        }

        it('pads correctly around the 55/56/64-byte block edges', () => {
            for (let length = 50; length <= 130; length++) {
                const data = crypto.randomBytes(length);
                assert.deepEqual(ripemd160Vendored(data), ripemd160(data), `${length} bytes`);
            }
        });
    });

    it('the one in use (Node\'s when present, else the vendored copy)', () => {
        for (const [input, digest] of KATS.slice(0, 8)) {
            assert.equal(ripemd160(Buffer.from(input, 'latin1')).toString('hex'), digest);
        }
        if (!NODE_HAS_RIPEMD160) {
            assert.equal(ripemd160, ripemd160Vendored);
        }
    });

    it('matches Node\'s ripemd160 on random inputs, when Node has it', t => {
        if (!NODE_HAS_RIPEMD160) {
            t.skip('this Node build has no ripemd160');

            return;
        }
        for (let i = 0; i < 64; i++) {
            const data = crypto.randomBytes(i * 7);
            assert.deepEqual(ripemd160Vendored(data), crypto.createHash('ripemd160').update(data).digest());
        }
    });
});

describe('Base58 and Base58Check', () => {
    // Bitcoin Core, src/test/data/base58_encode_decode.json.
    const KATS = [
        ['', ''],
        ['61', '2g'],
        ['626262', 'a3gV'],
        ['636363', 'aPEr'],
        ['73696d706c792061206c6f6e6720737472696e67', '2cFupjhnEsSn59qHXstmK2ffpLv2'],
        ['00eb15231dfceb60925886b67d065299925915aeb172c06647', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'],
        ['516b6fcd0f', 'ABnLTmg'],
        ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
        ['572e4794', '3EFU7m'],
        ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'],
        ['10c8511e', 'Rt5zm'],
        ['00000000000000000000', '1111111111'],
        ['000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5', '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'],
    ];
    for (const [bytes, text] of KATS) {
        it(`${bytes || '(empty)'} <-> ${text || '(empty)'}`, () => {
            assert.equal(base58.encode(hex(bytes)), text);
            assert.deepEqual(base58.decode(text), hex(bytes));
        });
    }

    it('refuses characters outside the alphabet', () => {
        for (const text of ['0', 'O', 'I', 'l', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L ']) {
            assert.equal(base58.decode(text), null, text);
        }
    });

    it('Base58Check: a version 1 Bitcoin address (Bitcoin wiki, "Technical background of version 1 Bitcoin addresses")', () => {
        const payload = hex('00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31');
        assert.equal(base58.encodeCheck(payload), '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs');
        assert.deepEqual(base58.decodeCheck('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'), payload);
        assert.equal(base58.decodeCheck('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAt'), null, 'a changed checksum');
        assert.equal(base58.decodeCheck('1'), null, 'too short for a checksum');
    });

    it('Base58Check in the XRP alphabet: the XRP Ledger genesis account (xrpl.org, account rHb9CJAW...)', () => {
        // Its account ID is RIPEMD-160(SHA-256(public key 0330E7FC...D020)).
        const accountId = ripemd160(crypto.createHash('sha256').update(hex('0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020')).digest());
        assert.equal(accountId.toString('hex'), 'b5f762798a53d543a014caf8b297cff8f2f937e8');
        assert.equal(base58.encodeCheck(Buffer.concat([Buffer.from([0]), accountId]), base58.RIPPLE_ALPHABET), 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
    });
});

describe('Bech32 (BIP173)', () => {
    // BIP173, "Test vectors": valid Bech32 strings.
    const VALID = [
        'A12UEL5L',
        'a12uel5l',
        'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
        'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
        '11' + 'q'.repeat(82) + 'c8247j',
        'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
        '?1ezyfcl',
    ];
    for (const text of VALID) {
        it(`checksum of ${text}`, () => {
            const lower = text.toLowerCase();
            const at = lower.lastIndexOf('1');
            const hrp = lower.slice(0, at);
            const data = [...lower.slice(at + 1)].map(c => bech32.CHARSET.indexOf(c));
            assert.equal(bech32.polymod([...bech32.hrpExpand(hrp), ...data]), 1);
            assert.equal(bech32.encode(hrp, data.slice(0, -6)), lower);
        });
    }

    // BIP173, "Test vectors": valid addresses and their scriptPubKey (version 0 only).
    const ADDRESSES = [
        ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
        ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
        ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
    ];
    for (const [address, script] of ADDRESSES) {
        it(`address ${address}`, () => {
            const hrp = address.toLowerCase().slice(0, 2);
            assert.equal(bech32.segwitV0Address(hrp, hex(script).subarray(2)), address.toLowerCase());
        });
    }
});

describe('CashAddr', () => {
    // The CashAddr specification (bitcoincash.org spec/cashaddr.md), "Test vectors" (payload size, type,
    // prefix, hash).
    const ENCODINGS = [
        [0, 'bitcoincash', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2'],
        [1, 'bchtest', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t'],
        [1, 'pref', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5'],
        [15, 'prefix', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf'],
        [0, 'bitcoincash', '7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea', 'bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0'],
        [1, 'bchtest', '7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea', 'bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr'],
    ];
    for (const [type, prefix, hash, address] of ENCODINGS) {
        it(address, () => assert.equal(cashaddr.encode(prefix, type, hex(hash)), address));
    }

    // The same specification, "Examples of address translation": legacy Base58 -> CashAddr.
    const TRANSLATIONS = [
        ['1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu', 'bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'],
        ['1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR', 'bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy'],
        ['16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb', 'bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r'],
        ['3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC', 'bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq'],
        ['3LDsS579y7sruadqu11beEJoTjdFiFCdX4', 'bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e'],
        ['31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw', 'bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37'],
    ];
    for (const [legacy, address] of TRANSLATIONS) {
        it(`${legacy} -> ${address}`, () => {
            const payload = base58.decodeCheck(legacy);
            const type = payload[0] === 0x05 ? cashaddr.TYPE_P2SH : cashaddr.TYPE_P2PKH;
            assert.equal(cashaddr.encode('bitcoincash', type, payload.subarray(1)), address);
        });
    }
});

describe('secp256k1', () => {
    // SEC 2 v2.0 section 2.4.1 (G), and the multiples of G listed in Chuck Batson's "secp256k1 test vectors".
    it('G compresses and decompresses', () => {
        const compressed = secp256k1.compress(secp256k1.G);
        assert.equal(compressed.toString('hex'), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
        assert.deepEqual(secp256k1.decompress(compressed), secp256k1.G);
    });

    const MULTIPLES = [
        [1n, '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'],
        [2n, 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'],
        [3n, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'],
    ];
    for (const [k, x, y] of MULTIPLES) {
        it(`${k}G`, () => assert.deepEqual(secp256k1.multiplyG(k), { x: BigInt(`0x${x}`), y: BigInt(`0x${y}`) }));
    }

    it('(n - 1)G is -G, nG is infinity, and 0G is infinity', () => {
        assert.deepEqual(secp256k1.multiplyG(secp256k1.N - 1n), { x: secp256k1.G.x, y: secp256k1.P - secp256k1.G.y });
        assert.equal(secp256k1.multiplyG(secp256k1.N), null);
        assert.equal(secp256k1.multiplyG(0n), null);
    });

    it('adds: P + P = 2P, P + (-P) = infinity, infinity + P = P', () => {
        const p = secp256k1.multiplyG(7n);
        assert.deepEqual(secp256k1.add(p, p), secp256k1.multiplyG(14n));
        assert.equal(secp256k1.add(p, { x: p.x, y: secp256k1.P - p.y }), null);
        assert.deepEqual(secp256k1.add(null, p), p);
        assert.deepEqual(secp256k1.add(p, secp256k1.multiplyG(5n)), secp256k1.multiplyG(12n));
    });

    it('multiplies and decompresses exactly as OpenSSL does, on random keys', () => {
        for (let i = 0; i < 24; i++) {
            const secret = crypto.randomBytes(32);
            const k = BigInt(`0x${secret.toString('hex')}`) % secp256k1.N;
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(toBytesBE(k, 32));
            const point = secp256k1.multiplyG(k);
            assert.deepEqual(secp256k1.compress(point), ecdh.getPublicKey(null, 'compressed'));
            assert.deepEqual(Buffer.concat([Buffer.from([4]), secp256k1.rawXY(point)]), ecdh.getPublicKey(null, 'uncompressed'));
            assert.deepEqual(secp256k1.decompress(ecdh.getPublicKey(null, 'compressed')), point);
        }
    });

    it('refuses what is not a compressed point, as OpenSSL does', () => {
        assert.throws(() => secp256k1.decompress(Buffer.alloc(33, 0)), /02 or 03/);
        assert.throws(() => secp256k1.decompress(hex('04'.padEnd(66, '1'))), /02 or 03/);
        assert.throws(() => secp256k1.decompress(Buffer.alloc(32, 2)), /33 bytes/);
        // x = p is outside the field.
        assert.throws(() => secp256k1.decompress(Buffer.concat([Buffer.from([2]), toBytesBE(secp256k1.P, 32)])), /field prime/);
        // Small x values: whether a point exists must match OpenSSL's verdict.
        for (let x = 0n; x < 40n; x++) {
            const encoded = Buffer.concat([Buffer.from([2]), toBytesBE(x, 32)]);
            let openssl = true;
            try {
                crypto.ECDH.convertKey(encoded, 'secp256k1', undefined, undefined, 'uncompressed');
            } catch (e) {
                openssl = false;
            }
            let ours = true;
            try {
                secp256k1.decompress(encoded);
            } catch (e) {
                ours = false;
            }
            assert.equal(ours, openssl, `x = ${x}`);
        }
    });
});

describe('Ed25519', () => {
    const PKCS8_PREFIX = hex('302e020100300506032b657004220420');
    const scalarOf = secret => {
        const h = crypto.createHash('sha512').update(secret).digest().subarray(0, 32);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;

        return fromBytesLE(h);
    };

    // RFC 8032 section 7.1, TEST 1 and TEST 2: secret key -> public key.
    const RFC8032 = [
        ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
        ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'],
    ];
    for (const [secret, publicKey] of RFC8032) {
        it(`RFC 8032 public key ${publicKey.slice(0, 16)}...`, () => {
            const point = ed25519.multiply(scalarOf(hex(secret)), ed25519.BASE);
            assert.equal(ed25519.encode(point).toString('hex'), publicKey);
            assert.deepEqual(ed25519.encode(ed25519.decode(hex(publicKey))), hex(publicKey));
        });
    }

    it('multiplies and encodes exactly as OpenSSL derives Ed25519 public keys, on random seeds', () => {
        for (let i = 0; i < 24; i++) {
            const seed = crypto.randomBytes(32);
            const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
            const expected = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(12);
            const point = ed25519.multiply(scalarOf(seed), ed25519.BASE);
            assert.deepEqual(ed25519.encode(point), expected);
            assert.deepEqual(ed25519.encode(ed25519.decode(expected)), expected);
        }
    });

    it('adds consistently with multiplication, and L * B is the identity', () => {
        const p = ed25519.multiply(5n, ed25519.BASE);
        assert.deepEqual(ed25519.encode(ed25519.add(p, ed25519.multiply(9n, ed25519.BASE))), ed25519.encode(ed25519.multiply(14n, ed25519.BASE)));
        assert.equal(ed25519.encode(ed25519.multiply(ed25519.L, ed25519.BASE)).toString('hex'), `01${'00'.repeat(31)}`);
    });

    it('refuses a y with no point, agreeing with Euler\'s criterion on x^2', () => {
        const P = ed25519.P;
        const pow = (b, e) => {
            let r = 1n;
            let base = b % P;
            for (let x = e; x > 0n; x >>= 1n) {
                if (x & 1n) r = (r * base) % P;
                base = (base * base) % P;
            }

            return r;
        };
        const d = ((P - 121665n) * pow(121666n, P - 2n)) % P;
        for (let y = 2n; y < 40n; y++) {
            const x2 = ((y * y - 1n) * pow((d * y * y + 1n) % P, P - 2n)) % P;
            const isSquare = x2 === 0n || pow(x2, (P - 1n) / 2n) === 1n;
            const encoded = Buffer.alloc(32);
            encoded[0] = Number(y);
            if (isSquare) {
                assert.doesNotThrow(() => ed25519.decode(encoded), `y = ${y}`);
            } else {
                assert.throws(() => ed25519.decode(encoded), /not on the curve/, `y = ${y}`);
            }
        }
    });

    describe('decodes like the elliptic library the server uses, not like strict RFC 8032', () => {
        it('reduces a y of p or more instead of refusing it', () => {
            // y = p + 1, which elliptic reads as y = 1: the identity.
            const encoded = Buffer.concat([Buffer.from([0xee]), Buffer.alloc(30, 0xff), Buffer.from([0x7f])]);
            assert.equal(ed25519.encode(ed25519.decode(encoded)).toString('hex'), `01${'00'.repeat(31)}`);
        });

        it('refuses x = 0 with the sign bit set', () => {
            assert.throws(() => ed25519.decode(Buffer.concat([Buffer.from([1]), Buffer.alloc(30), Buffer.from([0x80])])), /sign bit/);
        });

        it('multiplies by the scalar as given, without reducing it modulo L', () => {
            // (0, -1) has order 2, so L * it is itself (L is odd), while (L mod L) * it would be the identity.
            const order2 = Buffer.concat([Buffer.from([0xec]), Buffer.alloc(30, 0xff), Buffer.from([0x7f])]);
            assert.deepEqual(ed25519.encode(ed25519.multiply(ed25519.L, ed25519.decode(order2))), order2);
        });

        it('refuses a key that is not 32 bytes', () => {
            assert.throws(() => ed25519.decode(Buffer.alloc(31)), /32 bytes/);
        });
    });
});
