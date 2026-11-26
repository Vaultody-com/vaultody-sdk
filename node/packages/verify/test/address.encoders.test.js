'use strict';

// Each address encoder against published examples, and every chain, network and format against the
// address the server library returns.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { CHAINS, chainNetwork } = require('../src/address/chains');
const { parseExtendedPublicKey, derivePath } = require('../src/address/derive');
const secp256k1 = require('../src/address/crypto/secp256k1');
const base58 = require('../src/address/crypto/base58');
const cashaddr = require('../src/address/crypto/cashaddr');

const ecdsaNode = hex => {
    const key = Buffer.from(hex, 'hex');

    return { key, point: secp256k1.decompress(key) };
};
const encode = (blockchain, network, format, node) => CHAINS[blockchain].formats[format](node, CHAINS[blockchain].networks[network]);

describe('encoders against published examples', () => {
    it('p2pkh: the Bitcoin wiki\'s version 1 address example', () => {
        const node = ecdsaNode('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352');
        assert.equal(encode('bitcoin', 'mainnet', 'p2pkh', node), '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs');
    });

    it('p2wpkh: BIP173\'s P2WPKH example for the key 0279BE66...', () => {
        const node = ecdsaNode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
        assert.equal(encode('bitcoin', 'mainnet', 'p2wpkh', node), 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
    });

    it('p2sh (P2SH-wrapped P2WPKH): BIP49\'s test vector address on testnet', () => {
        const node = ecdsaNode('03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f');
        assert.equal(encode('bitcoin', 'testnet', 'p2sh', node), '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2');
    });

    it('p2pkh-cash and p2sh-cash: the CashAddr translation of the legacy address, as bchaddrjs makes it', () => {
        // The CashAddr encoder itself is checked against the specification's vectors in the crypto tests.
        const node = ecdsaNode('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352');
        for (const [network, prefix] of [['mainnet', 'bitcoincash'], ['testnet', 'bchtest']]) {
            for (const [legacy, cash, type] of [['p2pkh', 'p2pkh-cash', 0], ['p2sh', 'p2sh-cash', 1]]) {
                const hash = base58.decodeCheck(encode('bitcoin-cash', network, legacy, node)).subarray(1);
                assert.equal(encode('bitcoin-cash', network, cash, node), cashaddr.encode(prefix, type, hash), `${network} ${cash}`);
            }
        }
    });

    it('classic: the XRP Ledger genesis account', () => {
        const node = ecdsaNode('0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020');
        assert.equal(encode('xrp', 'mainnet', 'classic', node), 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
    });

    it('standard: the Ethereum addresses of private keys 1 and 2', () => {
        for (const [k, address] of [[1n, '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'], [2n, '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf']]) {
            const point = secp256k1.multiplyG(k);
            assert.equal(encode('ethereum', 'mainnet', 'standard', { key: secp256k1.compress(point), point }), address);
        }
    });

    it('tron base58: the Tron address of private key 1 is the Ethereum one after a 41 byte', () => {
        const point = secp256k1.G;
        const address = encode('tron', 'mainnet', 'base58', { key: secp256k1.compress(point), point });
        assert.equal(base58.decodeCheck(address).toString('hex'), '417e5f4552091a69125d5dfcb7b8c2659029395bdf');
        assert.ok(address.startsWith('T'));
    });

    it('solana base58: 32 zero bytes are the System Program address', () => {
        assert.equal(encode('solana', 'mainnet', 'base58', { key: Buffer.alloc(32) }), '11111111111111111111111111111111');
    });
});

describe('every chain, network and format, as the server library derives them', () => {
    // BIP32 test vector 1, key m/0H (a depth-1 xpub) for ECDSA, and a synthetic depth-1 EdDSA key, both
    // derived to m/7/1/5. Expected addresses: the server's xpub utilities at the version the vault service pins.
    const ECDSA_XPUB = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';
    const EDDSA_XPUB = 'xpub69XRnZc4mqU8jdHmMSzALdxnwCYJip7VLvB9EJv2kqNBtpwrfvXZBRnM2qWSs3aotL7FZ1GrpKYHvwwJFc76cD3g5KRoEb7tPuN1NphRdTw';
    const EVM = '0x48f6e97fc101441e68fb84cda7a86d5b81be89a3';
    const SERVER = [
        ['bitcoin', 'mainnet', 'p2pkh', '19ubYrhTPCLMcx6YxMkoQzfDF36ZXtE2xS'],
        ['bitcoin', 'mainnet', 'p2sh', '34kUgVDxFNJm1qaFXftftFaHH2jcfcRYQJ'],
        ['bitcoin', 'mainnet', 'p2wpkh', 'bc1qvxehnlevqrz7gtpp56tljeq6vstw89enklmr48'],
        ['bitcoin', 'testnet', 'p2pkh', 'mpRYqunSCDmcQ4aAfvjBEusY72hGXKmU5U'],
        ['bitcoin', 'testnet', 'p2sh', '2MvJgkE9yrpp7DdCoCoWYWCZYVNwnXw7Nb9'],
        ['bitcoin', 'testnet', 'p2wpkh', 'tb1qvxehnlevqrz7gtpp56tljeq6vstw89enueqsw5'],
        ['litecoin', 'mainnet', 'p2pkh', 'LU8Yp51HTraQskni8Vk6h1iyTFTqdjYG81'],
        ['litecoin', 'mainnet', 'p2sh', 'MAxczNdvCVABpLr9dYt1htpgbjL4hGv2m5'],
        ['litecoin', 'mainnet', 'p2wpkh', 'ltc1qvxehnlevqrz7gtpp56tljeq6vstw89enjrp8dh'],
        ['litecoin', 'testnet', 'p2pkh', 'mpRYqunSCDmcQ4aAfvjBEusY72hGXKmU5U'],
        ['litecoin', 'testnet', 'p2sh', '2MvJgkE9yrpp7DdCoCoWYWCZYVNwnXw7Nb9'],
        ['litecoin', 'testnet', 'p2wpkh', 'tltc1qvxehnlevqrz7gtpp56tljeq6vstw89en93zw7a'],
        ['dogecoin', 'mainnet', 'p2pkh', 'DE3h67e6gcEe9xH9gwkMxkpp8ApruZe5f3'],
        ['dogecoin', 'mainnet', 'p2sh', '9uVjRLHrKSBevCwiwoZ68PCeyc7eoJtHPe'],
        ['dogecoin', 'testnet', 'p2pkh', 'nd6kp8P1cahN2vrLimPpDAR7N3D9qydKcP'],
        ['dogecoin', 'testnet', 'p2sh', '2MvJgkE9yrpp7DdCoCoWYWCZYVNwnXw7Nb9'],
        ['dash', 'mainnet', 'p2pkh', 'XjbSP7MMLuYwmth8pF52GXM15NgFZ3bvSW'],
        ['dash', 'mainnet', 'p2sh', '7VU7WgW84MQQ1c7CoHZBDdZwCaZzXEsEVo'],
        ['dash', 'testnet', 'p2pkh', 'yVE3Q4RnnTD27dcgP6PRJYmMMfAd4WU1x7'],
        ['dash', 'testnet', 'p2sh', '8hUvU1PzBto2TuXTsYZ8g1PJ66LpgkSiMK'],
        ['bitcoin-cash', 'mainnet', 'p2pkh', '19ubYrhTPCLMcx6YxMkoQzfDF36ZXtE2xS'],
        ['bitcoin-cash', 'mainnet', 'p2sh', '34kUgVDxFNJm1qaFXftftFaHH2jcfcRYQJ'],
        ['bitcoin-cash', 'mainnet', 'p2pkh-cash', 'bitcoincash:qpsmx70l9sqvtepvyxnf07tyrfjpdcuhxvelvhztgv'],
        ['bitcoin-cash', 'mainnet', 'p2sh-cash', 'bitcoincash:pqsclas79pcy69pk4tswgy8scmrw0fpvvql8aqtp87'],
        ['bitcoin-cash', 'testnet', 'p2pkh', 'mpRYqunSCDmcQ4aAfvjBEusY72hGXKmU5U'],
        ['bitcoin-cash', 'testnet', 'p2sh', '2MvJgkE9yrpp7DdCoCoWYWCZYVNwnXw7Nb9'],
        ['bitcoin-cash', 'testnet', 'p2pkh-cash', 'bchtest:qpsmx70l9sqvtepvyxnf07tyrfjpdcuhxvadgsqu0s'],
        ['bitcoin-cash', 'testnet', 'p2sh-cash', 'bchtest:pqsclas79pcy69pk4tswgy8scmrw0fpvvqm4e8fkqz'],
        ['zcash', 'mainnet', 'p2pkh', 't1SnCZC7bMX7xDb9StnZvYom8VhHeKc966F'],
        ['zcash', 'testnet', 'p2pkh', 'tmJcwt2bzkBdTMqLtZWsfQURt6gNTqH4M1V'],
        ['xrp', 'mainnet', 'classic', 'r9ubYi6TPULMcxaYxMkoQzCDEsaZXtNpxS'],
        ['xrp', 'testnet', 'classic', 'r9ubYi6TPULMcxaYxMkoQzCDEsaZXtNpxS'],
        ['tron', 'mainnet', 'base58', 'TGd1SdBa7UJRCndJwjiotbYSQbMd5XKgBB'],
        ['tron', 'nile', 'base58', 'TGd1SdBa7UJRCndJwjiotbYSQbMd5XKgBB'],
        ['solana', 'mainnet', 'base58', 'FQdQ3FPzUYUVg5YwT97nuuf1kV5ThdMU9FMtxLh6GNcB'],
        ['solana', 'devnet', 'base58', 'FQdQ3FPzUYUVg5YwT97nuuf1kV5ThdMU9FMtxLh6GNcB'],
        ...['ethereum:sepolia', 'ethereum-classic:mordor', 'binance-smart-chain:testnet', 'polygon:amoy', 'arbitrum:sepolia',
            'optimism:sepolia', 'base:sepolia', 'avalanche:fuji'].flatMap(pair => {
            const [chain, test] = pair.split(':');

            return [[chain, 'mainnet', 'standard', EVM], [chain, test, 'standard', EVM]];
        }),
    ];

    const nodes = {
        ECDSA: derivePath(parseExtendedPublicKey(ECDSA_XPUB, 'ECDSA'), [7, 1, 5]),
        EDDSA: derivePath(parseExtendedPublicKey(EDDSA_XPUB, 'EDDSA'), [7, 1, 5]),
    };

    for (const [blockchain, network, format, address] of SERVER) {
        it(`${blockchain} ${network} ${format}`, () => {
            assert.equal(encode(blockchain, network, format, nodes[CHAINS[blockchain].algorithm]), address);
        });
    }

    it('covers every chain, network and format the helper knows, and only the 17 live chains', () => {
        const covered = new Set(SERVER.map(([blockchain, network, format]) => `${blockchain}/${network}/${format}`));
        const known = Object.entries(CHAINS).flatMap(([blockchain, chain]) => Object.keys(chain.networks)
            .flatMap(network => Object.keys(chain.formats).map(format => `${blockchain}/${network}/${format}`)));
        assert.deepEqual([...covered].sort(), known.sort());
        assert.equal(Object.keys(CHAINS).length, 17);
    });

    it('knows no other chain or network', () => {
        assert.equal(chainNetwork('stellar', 'mainnet'), null);
        assert.equal(chainNetwork('ethereum', 'goerli'), null);
        assert.equal(chainNetwork('bitcoin', 'sepolia'), null);
        assert.equal(chainNetwork('__proto__', 'mainnet'), null);
        assert.equal(chainNetwork('bitcoin', 'toString'), null);
    });
});
