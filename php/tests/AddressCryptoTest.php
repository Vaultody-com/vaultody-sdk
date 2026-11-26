<?php

declare(strict_types=1);

// Known-answer tests for the cryptography the address check carries itself: the field arithmetic, both
// curves, Keccak-256, Base58, Bech32, CashAddr, the address encoders and the derivation rules. Each block
// names where its expected values come from. Where PHP's own extensions (OpenSSL, sodium, hash) can
// compute the same thing, the code here is also compared with them on random inputs.

use Vaultody\Sdk\Verify\Address\Base58;
use Vaultody\Sdk\Verify\Address\Bech32;
use Vaultody\Sdk\Verify\Address\CashAddr;
use Vaultody\Sdk\Verify\Address\Chains;
use Vaultody\Sdk\Verify\Address\Derivation;
use Vaultody\Sdk\Verify\Address\DerivedNode;
use Vaultody\Sdk\Verify\Address\Ed25519;
use Vaultody\Sdk\Verify\Address\ExtendedPublicKey;
use Vaultody\Sdk\Verify\Address\Field;
use Vaultody\Sdk\Verify\Address\Keccak;
use Vaultody\Sdk\Verify\Address\KeyDerivationError;
use Vaultody\Sdk\Verify\Address\Secp256k1;

$bin = static fn (string $hex): string => (string) hex2bin($hex);

/** Runs $run and returns the message of the KeyDerivationError it throws, or null when it returns. */
$failureOf = static function (callable $run): ?string {
    try {
        $run();
    } catch (KeyDerivationError $error) {
        return $error->getMessage();
    }

    return null;
};

// A scalar as 32 big-endian bytes.
$scalar = static fn (int $k): string => str_pad(pack('J', $k), 32, "\0", STR_PAD_LEFT);

$ecdsaNode = static function (string $compressedHex) use ($bin): DerivedNode {
    $key = $bin($compressedHex);

    return new DerivedNode(Chains::ECDSA, $key, Secp256k1::decompress($key), str_repeat("\0", 32));
};

// Rewrites an extended key's 78 bytes and re-encodes it, for the malformed-key cases.
$reencode = static function (string $text, callable $change): string {
    $bytes = (string) Base58::decodeCheck($text);

    return Base58::encodeCheck($change($bytes));
};

$tests = [];

// ---- the field arithmetic: products, differences and inverses computed with JavaScript BigInt ----------
$fieldCases = [
    ['secp256k1', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e', '0000000000000000000000000000000000000000000000000000000000000001', '0000000000000000000000000000000000000000000000000000000000000000', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e'],
    ['secp256k1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'f8357996a13575edf8357996a13575edf8357996a13575ee0a69d09908c0267d', 'edcba9876f543210edcba9876f543210edcba9876f543210edcba9876f543210', 'be4316dba038daad273e4bda627ecf687c8941a534b5ba270b2a4b24b07e6798'],
    ['secp256k1', 'deadbeefcafebabe0123456789abcdeffedcba9876543210aabbccddeeff0011', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d', '42a482206a028a83fdb97530eca8642002468acf13579bdeaa8866422201f83c', 'deadbeefcafebabe0123456789abcdeffedcba9876543210aabbccddeeff0013', 'fd6b10d88a216d9b48df1defe251e0cb3aab9d0b32be808d10ebf0a6dcb2c5d5'],
    ['secp256k1', '0000000000000000000000000000000000000000000000000000000000000003', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc34', '000000000000000000000000000000000000000000000000000000000000000f', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd75'],
    ['ed25519', '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec', '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec', '0000000000000000000000000000000000000000000000000000000000000001', '0000000000000000000000000000000000000000000000000000000000000000', '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'],
    ['ed25519', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', '21907f6ce8d4c38da1907f6ce8d4c38da1907f6ce8d4c38da1907f6ce8d4c3ea', '6dcba9876f543210edcba9876f543210edcba9876f543210edcba9876f543223', '5d67c8a60dd67c8a60dd67c8a60dd67c8a60dd67c8a60dd67c8a60dd67c8a600'],
    ['ed25519', 'deadbeefcafebabe0123456789abcdeffedcba9876543210aabbccddeeff0011', '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb', '42a482206a028a83fdb97530eca8642002468acf13579bdeaa8866442201ff92', '5eadbeefcafebabe0123456789abcdeffedcba9876543210aabbccddeeff0026', '571a4593190f606521157a5509ef6f5f630ca9cb877c04a55bd7530bca1d05b8'],
    ['ed25519', '0000000000000000000000000000000000000000000000000000000000000003', '7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2', '000000000000000000000000000000000000000000000000000000000000000f', '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb', '5555555555555555555555555555555555555555555555555555555555555549'],
];
foreach ($fieldCases as $index => [$name, $a, $b, $product, $difference, $inverse]) {
    $tests["field {$name} #{$index}: product, difference, sum and inverse"] = static function () use ($name, $a, $b, $product, $difference, $inverse, $bin): void {
        $f = $name === 'secp256k1' ? Field::secp256k1() : Field::ed25519();
        $x = $f->fromBytes($bin($a));
        $y = $f->fromBytes($bin($b));
        check(bin2hex($f->toBytes($f->mul($x, $y))) === $product, 'product');
        check(bin2hex($f->toBytes($f->sub($x, $y))) === $difference, 'difference');
        check($f->equals($f->add($f->sub($x, $y), $y), $x), 'sum undoes the difference');
        check(bin2hex($f->toBytes($f->invert($x))) === $inverse, 'inverse');
        check($f->equals($f->mul($x, $f->invert($x)), $f->one()), 'a * 1/a = 1');
    };
}

$tests += [
    'field: p is zero, values of 2^256 - 1 and below reduce, zero has no inverse' => static function () use ($bin): void {
        foreach ([[Field::secp256k1(), Secp256k1::P_HEX], [Field::ed25519(), '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed']] as [$f, $p]) {
            check($f->isZero($f->fromBytes($bin($p))), 'p reduces to zero');
            check(!$f->isZero($f->sub($f->zero(), $f->one())), '0 - 1 is not 0');
            check(bin2hex($f->toBytes($f->add($f->sub($f->zero(), $f->one()), $f->one()))) === str_repeat('0', 64), '(0 - 1) + 1 = 0');
            check(!$f->isOdd($f->sub($f->zero(), $f->one())), 'p - 1 is even');
            check($f->equals($f->mulSmall($f->one(), 8), $f->fromInt(8)), 'mulSmall');
            check($f->equals($f->neg($f->neg($f->fromInt(12345))), $f->fromInt(12345)), 'neg');
            check($f->equals($f->pow($f->fromInt(3), "\x05"), $f->fromInt(243)), '3^5');
            check($f->equals($f->pow($f->fromInt(3), "\0"), $f->one()), 'a^0 = 1');
            try {
                $f->invert($f->fromBytes($bin($p)));
                check(false, 'p has no inverse');
            } catch (DivisionByZeroError) {
            }
        }
    },

    'field: random products agree with schoolbook multiplication of small values' => static function (): void {
        foreach ([Field::secp256k1(), Field::ed25519()] as $f) {
            for ($i = 0; $i < 50; $i++) {
                $a = random_int(0, 0x7fffffff);
                $b = random_int(0, 0x7fffffff);
                check($f->equals($f->mul($f->fromInt($a), $f->fromInt($b)), $f->fromInt($a * $b)), "{$a} * {$b}");
                check($f->equals($f->sub($f->fromInt($a), $f->fromInt($b)), $a >= $b ? $f->fromInt($a - $b) : $f->neg($f->fromInt($b - $a))), "{$a} - {$b}");
            }
        }
    },

    // ---- Keccak-256 ------------------------------------------------------------------------------------
    // Keccak team, ShortMsgKAT_256.txt from the round 3 SHA-3 submission (Len = 0, 8 and 16 bits), and the
    // Keccak-256 values Ethereum tooling lists for "abc" and the pangram.
    'Keccak-256 known answers' => static function () use ($bin): void {
        $kats = [
            ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
            ['cc', 'eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a'],
            ['41fb', 'a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2'],
            [bin2hex('abc'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
            [bin2hex('The quick brown fox jumps over the lazy dog'), '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'],
        ];
        foreach ($kats as [$input, $digest]) {
            check(bin2hex(Keccak::keccak256($bin($input))) === $digest, "keccak256({$input})");
        }
        check(bin2hex(Keccak::keccak256('')) !== hash('sha3-256', ''), 'Keccak-256 is not SHA3-256');
    },

    'the Keccak sponge with SHA-3 padding is PHP\'s sha3-256 and sha3-512, at every length up to three blocks' => static function (): void {
        $input = random_bytes(3 * 136 + 1);
        for ($length = 0; $length <= 3 * 136 + 1; $length++) {
            $message = substr($input, 0, $length);
            check(bin2hex(Keccak::sponge(136, 0x06, $message, 32)) === hash('sha3-256', $message), "sha3-256 at {$length}");
            if ($length <= 3 * 72 + 1) {
                check(bin2hex(Keccak::sponge(72, 0x06, $message, 64)) === hash('sha3-512', $message), "sha3-512 at {$length}");
            }
        }
    },

    // ---- Base58 ----------------------------------------------------------------------------------------
    // Bitcoin Core, src/test/data/base58_encode_decode.json.
    'Base58 known answers, both ways' => static function () use ($bin): void {
        $kats = [
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
        foreach ($kats as [$bytes, $text]) {
            check(Base58::encode($bin($bytes)) === $text, "encode {$bytes}");
            check(Base58::decode($text) === $bin($bytes), "decode {$text}");
        }
        foreach (['0', 'O', 'I', 'l', '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L '] as $text) {
            check(Base58::decode($text) === null, "refuses {$text}");
        }
        for ($i = 0; $i < 40; $i++) {
            $length = random_int(0, 80);
            // random_bytes refuses a length of 0 on PHP 8.3 and later.
            $bytes = str_repeat("\0", random_int(0, 3)) . ($length === 0 ? '' : random_bytes($length));
            check(Base58::decode(Base58::encode($bytes)) === $bytes, 'round trip');
            check(Base58::decode(Base58::encode($bytes, Base58::RIPPLE_ALPHABET), Base58::RIPPLE_ALPHABET) === $bytes, 'round trip, ripple');
        }
    },

    'Base58Check: a version 1 Bitcoin address (Bitcoin wiki) and the XRP Ledger genesis account' => static function () use ($bin): void {
        $payload = $bin('00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31');
        check(Base58::encodeCheck($payload) === '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs', 'encode');
        check(Base58::decodeCheck('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs') === $payload, 'decode');
        check(Base58::decodeCheck('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAt') === null, 'a changed checksum');
        check(Base58::decodeCheck('1') === null, 'too short for a checksum');
        // Its account ID is RIPEMD-160(SHA-256(public key 0330E7FC...D020)).
        $accountId = Chains::hash160($bin('0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020'));
        check(bin2hex($accountId) === 'b5f762798a53d543a014caf8b297cff8f2f937e8', 'account id');
        check(Base58::encodeCheck("\0" . $accountId, Base58::RIPPLE_ALPHABET) === 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', 'xrp');
    },

    // ---- Bech32 and CashAddr ---------------------------------------------------------------------------
    'Bech32: BIP173 valid strings and version 0 addresses' => static function () use ($bin): void {
        $valid = [
            'A12UEL5L',
            'a12uel5l',
            'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
            'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
            '11' . str_repeat('q', 82) . 'c8247j',
            'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
            '?1ezyfcl',
        ];
        foreach ($valid as $text) {
            $lower = strtolower($text);
            $at = (int) strrpos($lower, '1');
            $hrp = substr($lower, 0, $at);
            $data = array_map(static fn (string $c): int => (int) strpos(Bech32::CHARSET, $c), str_split(substr($lower, $at + 1)));
            check(Bech32::polymod([...Bech32::hrpExpand($hrp), ...$data]) === 1, "checksum of {$text}");
            check(Bech32::encode($hrp, array_slice($data, 0, -6)) === $lower, "encode {$text}");
        }
        $addresses = [
            ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
            ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
            ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
        ];
        foreach ($addresses as [$address, $script]) {
            $hrp = substr(strtolower($address), 0, 2);
            check(Bech32::segwitV0Address($hrp, substr($bin($script), 2)) === strtolower($address), $address);
        }
    },

    // The CashAddr specification (bitcoincash.org spec/cashaddr.md), "Test vectors" and "Examples of
    // address translation".
    'CashAddr: specification vectors and legacy translations' => static function () use ($bin): void {
        $encodings = [
            [0, 'bitcoincash', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2'],
            [1, 'bchtest', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t'],
            [1, 'pref', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5'],
            [15, 'prefix', 'f5bf48b397dae70be82b3cca4793f8eb2b6cdac9', 'prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf'],
            [0, 'bitcoincash', '7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea', 'bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0'],
            [1, 'bchtest', '7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea', 'bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr'],
        ];
        foreach ($encodings as [$type, $prefix, $hash, $address]) {
            check(CashAddr::encode($prefix, $type, $bin($hash)) === $address, $address);
        }
        $translations = [
            ['1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu', 'bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'],
            ['1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR', 'bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy'],
            ['16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb', 'bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r'],
            ['3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC', 'bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq'],
            ['3LDsS579y7sruadqu11beEJoTjdFiFCdX4', 'bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e'],
            ['31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw', 'bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37'],
        ];
        foreach ($translations as [$legacy, $address]) {
            $payload = (string) Base58::decodeCheck($legacy);
            $type = $payload[0] === "\x05" ? CashAddr::TYPE_P2SH : CashAddr::TYPE_P2PKH;
            check(CashAddr::encode('bitcoincash', $type, substr($payload, 1)) === $address, $legacy);
        }
    },

    // ---- secp256k1 -------------------------------------------------------------------------------------
    // SEC 2 v2.0 section 2.4.1 (G), and the multiples of G in Chuck Batson's "secp256k1 test vectors".
    'secp256k1: G, 2G and 3G, through OpenSSL and here' => static function () use ($scalar): void {
        $g = Secp256k1::generator();
        check(bin2hex(Secp256k1::compress($g)) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'compress G');
        check(Secp256k1::decompress(Secp256k1::compress($g)) === $g, 'decompress G');
        $multiples = [
            [1, '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'],
            [2, 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'],
            [3, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'],
        ];
        foreach ($multiples as [$k, $x, $y]) {
            foreach ([Secp256k1::multiplyG($scalar($k)), Secp256k1::multiplyGPure($scalar($k))] as $point) {
                check(bin2hex($point['x']) === $x && bin2hex($point['y']) === $y, "{$k}G");
            }
        }
    },

    'secp256k1: (n - 1)G is -G, nG and 0G are infinity' => static function () use ($bin, $scalar): void {
        $order = Secp256k1::order();
        $nMinus1 = $bin(substr(Secp256k1::N_HEX, 0, 62) . '40');
        $g = Secp256k1::generator();
        $minusG = ['x' => $g['x'], 'y' => Field::secp256k1()->toBytes(Field::secp256k1()->neg(Field::secp256k1()->fromBytes($g['y'])))];
        check(Secp256k1::multiplyG($nMinus1) === $minusG, '(n - 1)G through multiplyG');
        check(Secp256k1::multiplyGPure($nMinus1) === $minusG, '(n - 1)G here');
        check(Secp256k1::multiplyG($order) === null, 'nG');
        check(Secp256k1::multiplyG($scalar(0)) === null, '0G');
    },

    'secp256k1: adds P + P = 2P, P + (-P) = infinity, infinity + P = P' => static function () use ($scalar): void {
        $f = Field::secp256k1();
        $p = Secp256k1::multiplyGPure($scalar(7));
        check(Secp256k1::add($p, $p) === Secp256k1::multiplyGPure($scalar(14)), 'P + P');
        check(Secp256k1::add($p, ['x' => $p['x'], 'y' => $f->toBytes($f->neg($f->fromBytes($p['y'])))]) === null, 'P - P');
        check(Secp256k1::add(null, $p) === $p, 'infinity + P');
        check(Secp256k1::add($p, Secp256k1::multiplyGPure($scalar(5))) === Secp256k1::multiplyGPure($scalar(12)), '7G + 5G');
    },

    'secp256k1: multiplies and decompresses exactly as OpenSSL does, on random keys' => static function (): void {
        $made = 0;
        for ($i = 0; $i < 8; $i++) {
            $key = @openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
            while (openssl_error_string() !== false) {
            }
            if ($key === false) {
                // This OpenSSL build has no secp256k1; multiplyG then always computes here.
                check(!Secp256k1::opensslAvailable(), 'OpenSSL refuses secp256k1 keys, so it is not used');
                break;
            }
            $details = openssl_pkey_get_details($key);
            $d = str_pad($details['ec']['d'], 32, "\0", STR_PAD_LEFT);
            $expected = ['x' => str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT), 'y' => str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)];
            check(Secp256k1::multiplyGPure($d) === $expected, 'pure k * G');
            check(Secp256k1::multiplyG($d) === $expected, 'k * G');
            check(Secp256k1::decompress(Secp256k1::compress($expected)) === $expected, 'decompress');
            $made++;
        }
        check($made === 0 || Secp256k1::opensslAvailable(), 'OpenSSL makes secp256k1 keys, so multiplyG uses it');
    },

    'secp256k1: refuses what is not a compressed point' => static function () use ($bin, $failureOf, $scalar): void {
        check(str_contains((string) $failureOf(fn () => Secp256k1::decompress(str_repeat("\0", 33))), '02 or 03'), 'prefix 00');
        check(str_contains((string) $failureOf(fn () => Secp256k1::decompress($bin('04' . str_repeat('11', 32)))), '02 or 03'), 'prefix 04');
        check(str_contains((string) $failureOf(fn () => Secp256k1::decompress(str_repeat("\x02", 32))), '33 bytes'), '32 bytes');
        check(str_contains((string) $failureOf(fn () => Secp256k1::decompress("\x02" . $bin(Secp256k1::P_HEX))), 'field prime'), 'x = p');
        // Small x values: whether a point exists must match Euler's criterion on x^3 + 7.
        $f = Field::secp256k1();
        $halfExponent = $bin('7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17');
        for ($x = 0; $x < 40; $x++) {
            $c = $f->add($f->mul($f->sqr($f->fromInt($x)), $f->fromInt($x)), $f->fromInt(7));
            $isSquare = $f->isZero($c) || $f->equals($f->pow($c, $halfExponent), $f->one());
            $refused = $failureOf(fn () => Secp256k1::decompress("\x02" . $scalar($x)));
            check(($refused === null) === $isSquare, "x = {$x}");
        }
    },

    // ---- Ed25519 ---------------------------------------------------------------------------------------
    // RFC 8032 section 7.1, TEST 1 and TEST 2 (secret key -> public key), and sodium on random seeds.
    'Ed25519: RFC 8032 public keys, and sodium\'s on random seeds' => static function () use ($bin): void {
        $scalarOf = static function (string $seed): string {
            $h = substr(hash('sha512', $seed, true), 0, 32);
            $h[0] = chr(ord($h[0]) & 248);
            $h[31] = chr((ord($h[31]) & 127) | 64);

            return strrev($h);
        };
        $rfc = [
            ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
            ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'],
        ];
        foreach ($rfc as [$secret, $publicKey]) {
            check(bin2hex(Ed25519::encode(Ed25519::multiply($scalarOf($bin($secret)), Ed25519::base()))) === $publicKey, "RFC 8032 {$publicKey}");
            check(bin2hex(Ed25519::encode(Ed25519::decode($bin($publicKey)))) === $publicKey, "decode {$publicKey}");
        }
        for ($i = 0; $i < 8; $i++) {
            $seed = random_bytes(32);
            $expected = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
            check(Ed25519::encode(Ed25519::multiply($scalarOf($seed), Ed25519::base())) === $expected, 'sodium public key');
            check(Ed25519::encode(Ed25519::decode($expected)) === $expected, 'decode round trip');
        }
    },

    'Ed25519: adds consistently with multiplication, and L * B is the identity' => static function () use ($bin): void {
        $k = static fn (int $value): string => pack('J', $value);
        $p = Ed25519::multiply($k(5), Ed25519::base());
        check(Ed25519::encode(Ed25519::addPoints($p, Ed25519::multiply($k(9), Ed25519::base()))) === Ed25519::encode(Ed25519::multiply($k(14), Ed25519::base())), '5B + 9B');
        $l = $bin('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
        check(bin2hex(Ed25519::encode(Ed25519::multiply($l, Ed25519::base()))) === '01' . str_repeat('00', 31), 'L * B');
        check(bin2hex(Ed25519::encode(Ed25519::base())) === '58' . str_repeat('66', 31), 'B');
    },

    'Ed25519: refuses a y with no point, agreeing with Euler\'s criterion on x^2' => static function () use ($bin, $failureOf): void {
        $f = Field::ed25519();
        $d = $f->fromBytes($bin('52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3'));
        $halfExponent = $bin('3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6');
        for ($y = 2; $y < 40; $y++) {
            $yy = $f->sqr($f->fromInt($y));
            $x2 = $f->mul($f->sub($yy, $f->one()), $f->invert($f->add($f->mul($d, $yy), $f->one())));
            $isSquare = $f->isZero($x2) || $f->equals($f->pow($x2, $halfExponent), $f->one());
            $refused = $failureOf(fn () => Ed25519::decode(chr($y) . str_repeat("\0", 31)));
            check($isSquare ? $refused === null : str_contains((string) $refused, 'not on the curve'), "y = {$y}");
        }
    },

    'Ed25519 decodes like the elliptic library the server uses, not like strict RFC 8032' => static function () use ($bin, $failureOf): void {
        // y = p + 1, which elliptic reads as y = 1: the identity.
        $yAboveP = "\xee" . str_repeat("\xff", 30) . "\x7f";
        check(bin2hex(Ed25519::encode(Ed25519::decode($yAboveP))) === '01' . str_repeat('00', 31), 'y of p or more is reduced');
        check(str_contains((string) $failureOf(fn () => Ed25519::decode("\x01" . str_repeat("\0", 30) . "\x80")), 'sign bit'), 'x = 0 with the sign bit');
        // (0, -1) has order 2, so L * it is itself (L is odd), while (L mod L) * it would be the identity.
        $order2 = "\xec" . str_repeat("\xff", 30) . "\x7f";
        $l = $bin('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
        check(Ed25519::encode(Ed25519::multiply($l, Ed25519::decode($order2))) === $order2, 'the scalar is not reduced modulo L');
        check(str_contains((string) $failureOf(fn () => Ed25519::decode(str_repeat("\0", 31))), '32 bytes'), '31 bytes');
    },

    // ---- the address encoders --------------------------------------------------------------------------
    'encoders against published examples' => static function () use ($ecdsaNode, $scalar): void {
        check(Chains::encode('bitcoin', 'mainnet', 'p2pkh', $ecdsaNode('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')) === '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs', 'p2pkh, Bitcoin wiki');
        check(Chains::encode('bitcoin', 'mainnet', 'p2wpkh', $ecdsaNode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')) === 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'p2wpkh, BIP173');
        check(Chains::encode('bitcoin', 'testnet', 'p2sh', $ecdsaNode('03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f')) === '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2', 'p2sh, BIP49');
        $node = $ecdsaNode('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352');
        foreach ([['mainnet', 'bitcoincash'], ['testnet', 'bchtest']] as [$network, $prefix]) {
            foreach ([['p2pkh', 'p2pkh-cash', 0], ['p2sh', 'p2sh-cash', 1]] as [$legacy, $cash, $type]) {
                $hash = substr((string) Base58::decodeCheck(Chains::encode('bitcoin-cash', $network, $legacy, $node)), 1);
                check(Chains::encode('bitcoin-cash', $network, $cash, $node) === CashAddr::encode($prefix, $type, $hash), "{$network} {$cash}");
            }
        }
        check(Chains::encode('xrp', 'mainnet', 'classic', $ecdsaNode('0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020')) === 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', 'xrp genesis');
        foreach ([[1, '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'], [2, '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf']] as [$k, $address]) {
            $point = Secp256k1::multiplyG($scalar($k));
            check(Chains::encode('ethereum', 'mainnet', 'standard', new DerivedNode(Chains::ECDSA, Secp256k1::compress($point), $point, '')) === $address, "ethereum key {$k}");
        }
        $g = Secp256k1::generator();
        $tron = Chains::encode('tron', 'mainnet', 'base58', new DerivedNode(Chains::ECDSA, Secp256k1::compress($g), $g, ''));
        check(bin2hex((string) Base58::decodeCheck($tron)) === '417e5f4552091a69125d5dfcb7b8c2659029395bdf' && $tron[0] === 'T', 'tron key 1');
        $zero = ['x' => str_repeat("\0", 32), 'y' => str_repeat("\0", 32)];
        check(Chains::encode('solana', 'mainnet', 'base58', new DerivedNode(Chains::EDDSA, str_repeat("\0", 32), $zero, '')) === '11111111111111111111111111111111', 'solana system program');
    },

    // BIP32 test vector 1, key m/0H (a depth-1 xpub) for ECDSA, and a synthetic depth-1 EdDSA key, both
    // derived to m/7/1/5. Expected addresses: the server's xpub utilities library at the version the vault
    // service pins.
    'every chain, network and format, as the server library derives them' => static function (): void {
        $evm = '0x48f6e97fc101441e68fb84cda7a86d5b81be89a3';
        $server = [
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
        ];
        foreach (['ethereum' => 'sepolia', 'ethereum-classic' => 'mordor', 'binance-smart-chain' => 'testnet', 'polygon' => 'amoy', 'arbitrum' => 'sepolia', 'optimism' => 'sepolia', 'base' => 'sepolia', 'avalanche' => 'fuji'] as $chain => $test) {
            $server[] = [$chain, 'mainnet', 'standard', $evm];
            $server[] = [$chain, $test, 'standard', $evm];
        }
        $nodes = [
            Chains::ECDSA => Derivation::derivePath(ExtendedPublicKey::parse('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw', Chains::ECDSA), [7, 1, 5]),
            Chains::EDDSA => Derivation::derivePath(ExtendedPublicKey::parse('xpub69XRnZc4mqU8jdHmMSzALdxnwCYJip7VLvB9EJv2kqNBtpwrfvXZBRnM2qWSs3aotL7FZ1GrpKYHvwwJFc76cD3g5KRoEb7tPuN1NphRdTw', Chains::EDDSA), [7, 1, 5]),
        ];
        $covered = [];
        foreach ($server as [$blockchain, $network, $format, $address]) {
            $derived = Chains::encode($blockchain, $network, $format, $nodes[Chains::algorithmOf($blockchain)]);
            check($derived === $address, "{$blockchain} {$network} {$format}: {$derived}");
            $covered[] = "{$blockchain}/{$network}/{$format}";
        }
        $known = [];
        foreach (Chains::blockchains() as $blockchain) {
            foreach (array_keys(Chains::describe($blockchain)['networks']) as $network) {
                foreach (Chains::formats($blockchain) as $format) {
                    $known[] = "{$blockchain}/{$network}/{$format}";
                }
            }
        }
        sort($covered);
        sort($known);
        check($covered === $known, 'every chain, network and format is covered');
    },

    // ---- derivation ------------------------------------------------------------------------------------
    // BIP32, "Test vector 1" (seed 000102030405060708090a0b0c0d0e0f). Only the non-hardened steps can be
    // derived from a public key: m/0H -> m/0H/1, and m/0H/1/2H -> /2 -> /1000000000.
    'derivation: BIP32 test vector 1, the public steps' => static function (): void {
        $tv1 = [
            'm/0H' => 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
            'm/0H/1' => 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
            'm/0H/1/2H' => 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
            'm/0H/1/2H/2' => 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
            'm/0H/1/2H/2/1000000000' => 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
        ];
        $parse = static fn (string $path): DerivedNode => ExtendedPublicKey::parse($tv1[$path], Chains::ECDSA);
        $same = static fn (DerivedNode $a, DerivedNode $b): bool => $a->key === $b->key && $a->chainCode === $b->chainCode && $a->point === $b->point;
        check($same(Derivation::derivePath($parse('m/0H'), [1]), $parse('m/0H/1')), 'm/0H -> m/0H/1');
        $two = Derivation::derivePath($parse('m/0H/1/2H'), [2]);
        check($same($two, $parse('m/0H/1/2H/2')), '-> /2');
        check($same(Derivation::derivePath($two, [1000000000]), $parse('m/0H/1/2H/2/1000000000')), '-> /1000000000');
    },

    'derivation: ECDSA keys as Vaultody stores them (depth 0, a tpub, depth 1)' => static function () use ($reencode): void {
        $master = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
        // Child keys the server library (the xpub utilities at the version the vault service pins) derives.
        $server = [
            ['m/0/0/0', '03d1b98e4f183a60bff312ac4d9ae32a9cac73ff5dd9ed6b4244f7e1c586a42d2d'],
            ['m/1/1/1', '02104fd976d89ab932358e84e770accaa81636d74ff78bf3d62c389f4b0a4735a9'],
            ['m/7/0/2147483647', '0386ecd288d9171a30ba2fbee3eff358a5320950021d552afbf35c63a55f9fb4ee'],
        ];
        $indexesOf = static fn (string $path): array => array_map('intval', array_slice(explode('/', $path), 1));
        // The version bytes are ignored, as the server rewrites them to xpub.
        $tpub = $reencode($master, static fn (string $bytes): string => "\x04\x35\x87\xcf" . substr($bytes, 4));
        check(str_starts_with($tpub, 'tpub'), 'a tpub');
        foreach ([$master, $tpub] as $xpub) {
            foreach ($server as [$path, $key]) {
                check(bin2hex(Derivation::derivePath(ExtendedPublicKey::parse($xpub, Chains::ECDSA), $indexesOf($path))->key) === $key, $path);
            }
        }
        $m0h = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';
        $expected = [
            ['m/0/0/0', '0241927ca610a44197de2d0492ba921c7f59224f4fd0eab7923f39f2bd4c6f5918'],
            ['m/1/1/1', '0369fcea70e095894c18f9cee0c0975939bfe20d61e89177472cdcc6847eaf6fdd'],
            ['m/7/0/2147483647', '033aa1eb2c5662292ad3713a54d3ea89cf38410a577ace0ae4155ce082d79a084a'],
        ];
        foreach ($expected as [$path, $key]) {
            check(bin2hex(Derivation::derivePath(ExtendedPublicKey::parse($m0h, Chains::ECDSA), $indexesOf($path))->key) === $key, "depth 1 {$path}");
        }
        // Depth, fingerprint and child number play no part: zeroing them changes nothing.
        $zeroed = $reencode($m0h, static fn (string $bytes): string => substr($bytes, 0, 4) . str_repeat("\0", 9) . substr($bytes, 13));
        check(
            Derivation::derivePath(ExtendedPublicKey::parse($zeroed, Chains::ECDSA), [0, 0, 0])->key === Derivation::derivePath(ExtendedPublicKey::parse($m0h, Chains::ECDSA), [0, 0, 0])->key,
            'depth, fingerprint and child number are ignored',
        );
    },

    'derivation: refuses a malformed ECDSA key' => static function () use ($reencode, $failureOf): void {
        $master = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
        $ecdsa = static fn (string $text): DerivedNode => ExtendedPublicKey::parse($text, Chains::ECDSA);
        check(str_contains((string) $failureOf(fn () => $ecdsa('xpub-not-base58')), 'Base58Check'), 'not base58');
        check(str_contains((string) $failureOf(fn () => $ecdsa(substr($master, 0, -1) . '9')), 'Base58Check'), 'checksum');
        check(str_contains((string) $failureOf(fn () => $ecdsa(Base58::encodeCheck(str_repeat("\0", 77)))), '78 bytes'), 'length');
        check(str_contains((string) $failureOf(fn () => $ecdsa($reencode($master, static fn (string $b): string => substr($b, 0, 45) . "\0" . substr($b, 46)))), '02 or 03'), 'prefix');
        check(str_contains((string) $failureOf(fn () => $ecdsa($reencode($master, static fn (string $b): string => substr($b, 0, 46) . str_repeat("\xff", 32)))), 'field prime'), 'x >= p');
        check(str_contains((string) $failureOf(fn () => ExtendedPublicKey::parse($master, 'RSA')), 'unknown algorithm'), 'algorithm');
    },

    // A parent whose private key is 1, so its public key is G and the "point at infinity" case can be built.
    'derivation: the invalid-child rule, as hdkey applies it' => static function () use ($bin, $failureOf): void {
        $g = Secp256k1::generator();
        $parent = new DerivedNode(Chains::ECDSA, Secp256k1::compress($g), $g, random_bytes(32));
        $real = static fn (string $key, string $data): string => hash_hmac('sha512', $data, $key, true);
        $forcing = static fn (int $atIndex, string $il) => static fn (string $key, string $data): string => unpack('N', substr($data, -4))[1] === $atIndex
            ? $il . random_bytes(32)
            : $real($key, $data);
        $n = Secp256k1::order();
        $nMinus1 = $bin(substr(Secp256k1::N_HEX, 0, 62) . '40');
        $nPlus1 = $bin(substr(Secp256k1::N_HEX, 0, 62) . '42');
        foreach ([$n, $nPlus1, str_repeat("\xff", 32)] as $il) {
            $child = Derivation::deriveEcdsaChild($parent, 5, $forcing(5, $il));
            check($child == Derivation::deriveEcdsaChild($parent, 6), 'I_L not below n skips to the next index');
        }
        // (n - 1) * G + G = infinity
        check(Derivation::deriveEcdsaChild($parent, 3, $forcing(3, $nMinus1)) == Derivation::deriveEcdsaChild($parent, 4), 'infinity skips to the next index');
        check(Derivation::deriveEcdsaChild($parent, 9, $forcing(9, str_repeat("\0", 32)))->key === $parent->key, 'I_L = 0 gives the parent key');
        check(str_contains((string) $failureOf(fn () => Derivation::deriveEcdsaChild($parent, Derivation::MAX_INDEX, $forcing(Derivation::MAX_INDEX, $n))), 'non-hardened'), 'past the last index');
        check(str_contains((string) $failureOf(fn () => Derivation::deriveEcdsaChild($parent, Derivation::MAX_INDEX + 1)), 'non-hardened'), 'a hardened index');
    },

    // Synthetic test keys: RFC 8032 TEST 1 and TEST 2 public keys with made-up chain codes, at depth 0 and
    // at depth 1 with a parent fingerprint. Expected child keys, chain codes and Solana addresses are what
    // the server library (eddsaXpubHelper.derive and SolanaUtils) returns for them.
    'derivation: EdDSA keys, Vaultody\'s scheme' => static function (): void {
        $d0 = 'xpub661MyMwAqRbcGdpmzahNP9BjYRTDgrzjhVAFUgwYv4FfCrFDDpQvoiwRf93e7MXL1L5Tj87hqNH3WTvkn9KjqL3jnuurE7Daz2wZuXsCbbB';
        $d1 = 'xpub69XRnZc4mqU8jdHmMSzALdxnwCYJip7VLvB9EJv2kqNBtpwrfvXZBRnM2qWSs3aotL7FZ1GrpKYHvwwJFc76cD3g5KRoEb7tPuN1NphRdTw';
        $server = [
            [$d0, 'm/0/0/0', 'aef3a309f6936acbfda5218439398737e7e53e7d45d47b498c2d03e36964239e', '8839f0123be47e85924a9ef92aa1fcd92f2d2943cca9a8751ced0649e9e82386', 'CmwQxecGmHKpMieaF1iP1FdbvQYpfvViKFNEyX584XoK'],
            [$d0, 'm/1/0/5', '311dcde4dcbd2d1aa06c60e8a34a29914e606d2a6899fa6525882d16b3740f87', 'c8b6d4687658f454082b6b4e51494a056d49d8950838b728c2d3d8b04758dea6', '4JjLW7ccV6Mb1tvM3BLV5CTKuBkAGfSfNGvwbYCPMf5g'],
            [$d0, 'm/7/1/2147483647', 'fae8360cbe965e6d91edbbea1027a66dff8cdb9bfed021758b0de7421e0c153e', '0fac658a3c6777a760a8bcabadeb8471b9667c6171ffafa63fe1b328937b97b9', 'HtSJ18dw4PaLdVWvHQZdn4gNJ8CDVv4ZQoBSJwZXxS6Z'],
            [$d1, 'm/0/0/0', '8051ca3aae1494f7ac944096c98331bd74fbbad882d16f6fb32c9fa7eec918ff', '0aac4b710a2e20e84ac86a26a2dc0b5afd8f1e55b807f8f5d3065042d7c49a5d', '9duXCrrckRx8xpo55acCEtGMmB3C16nhSNKLLaGM7kMU'],
            [$d1, 'm/1/0/5', '69248dca1878521cfef0d3d75e29f84b24c530a0da180e573c650f7425114074', 'bbadf4aa23ef07b6091cb06049ac0c81ea3edaf7a7bc2911d8b75091034b615c', '85S8vpZ413pe4a4pFBHEyDJUx7RTkEwu8u8mfvwJo355'],
            [$d1, 'm/7/1/2147483647', 'f8c80c59451693cbc8604f5899faba086337b19a3ee86079ca195d398b865aae', '07aec85adb5c490a47cd793e713a3d5039591fd4ae9d63643628eb9d26d3e546', 'Hk92u531BQrZNd4AfWypL3GV2ziFc4cPthgLk2myu1yX'],
        ];
        foreach ($server as [$xpub, $path, $key, $chainCode, $address]) {
            $node = Derivation::derivePath(ExtendedPublicKey::parse($xpub, Chains::EDDSA), array_map('intval', array_slice(explode('/', $path), 1)));
            check(bin2hex($node->key) === $key, "{$path} key");
            check(bin2hex($node->chainCode) === $chainCode, "{$path} chain code");
            check(Chains::encode('solana', 'mainnet', 'base58', $node) === $address, "{$path} address");
        }
    },

    'derivation: EdDSA writes the index little-endian and reads the HMAC big-endian' => static function (): void {
        // Rebuild one step by hand from the description, independent of deriveEddsaChild's code.
        $parent = ExtendedPublicKey::parse('xpub661MyMwAqRbcGdpmzahNP9BjYRTDgrzjhVAFUgwYv4FfCrFDDpQvoiwRf93e7MXL1L5Tj87hqNH3WTvkn9KjqL3jnuurE7Daz2wZuXsCbbB', Chains::EDDSA);
        $hmac = static fn (int $prefix): string => hash_hmac('sha256', chr($prefix) . $parent->key . "\x05\x00\x00\x00", $parent->chainCode, true);
        $child = Derivation::deriveEddsaChild($parent, 5);
        check($child->chainCode === $hmac(0x03), 'chain code');
        check($child->key === Ed25519::encode(Ed25519::multiply($hmac(0x02), $parent->point)), 'key');
    },

    'derivation: refuses an EdDSA index above 2^31 - 1 and malformed EdDSA keys' => static function () use ($reencode, $failureOf): void {
        $d0 = 'xpub661MyMwAqRbcGdpmzahNP9BjYRTDgrzjhVAFUgwYv4FfCrFDDpQvoiwRf93e7MXL1L5Tj87hqNH3WTvkn9KjqL3jnuurE7Daz2wZuXsCbbB';
        $eddsa = static fn (string $text): DerivedNode => ExtendedPublicKey::parse($text, Chains::EDDSA);
        check(str_contains((string) $failureOf(fn () => Derivation::deriveEddsaChild($eddsa($d0), Derivation::MAX_INDEX + 1)), 'hardened'), 'index');
        check(str_contains((string) $failureOf(fn () => $eddsa($reencode($d0, static fn (string $b): string => substr($b, 0, 45) . "\x02" . substr($b, 46)))), '00 followed by'), 'prefix');
        // y = 2 has no x on ed25519.
        check(str_contains((string) $failureOf(fn () => $eddsa($reencode($d0, static fn (string $b): string => substr($b, 0, 46) . "\x02" . str_repeat("\0", 31)))), 'not on the curve'), 'not on the curve');
        // An ECDSA key read as EdDSA, and the other way round.
        $tv1 = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
        check(str_contains((string) $failureOf(fn () => $eddsa($tv1)), '00 followed by'), 'ECDSA key as EdDSA');
        check(str_contains((string) $failureOf(fn () => ExtendedPublicKey::parse($d0, Chains::ECDSA)), '02 or 03'), 'EdDSA key as ECDSA');
    },

    'a derived node keeps its chain code out of var_dump' => static function (): void {
        $node = ExtendedPublicKey::parse('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8', Chains::ECDSA);
        $dump = print_r($node, true);
        check(!str_contains($dump, bin2hex($node->chainCode)) && !str_contains($dump, $node->chainCode), 'chain code in print_r');
    },
];

return $tests;
