<?php

declare(strict_types=1);

// The server-generated address vectors, test-vectors/address-v1.json, made by the vault service from its
// real derivation code. Every case must verify exactly: its xpub is the
// pinned key of a main and a test vault, and AddressVerifier::verify must return the case's path, address
// and format, with the format as stored and with none. Formats the server refuses on a chain are not
// cases; they are in the file's rejected list, and must be refused as unsupported. No rejected input may
// ever verify.

use Vaultody\Sdk\Verify\Address\AddressVerificationError;
use Vaultody\Sdk\Verify\Address\AddressVerifier;
use Vaultody\Sdk\Verify\Address\Chains;
use Vaultody\Sdk\Verify\Address\Derivation;
use Vaultody\Sdk\Verify\Address\DerivedNode;
use Vaultody\Sdk\Verify\Address\ExtendedPublicKey;
use Vaultody\Sdk\Verify\Address\Secp256k1;

$vectors = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/test-vectors/address-v1.json'), true, 512, JSON_THROW_ON_ERROR);

// One main and one test vault per xpub, holding it under its algorithm, as the pin store keeps them.
$vaults = [];
foreach ($vectors['xpubs'] as $xpub) {
    foreach (['main', 'test'] as $type) {
        $keys = [Chains::ECDSA => null, Chains::EDDSA => null];
        $keys[$xpub['algorithm']] = $xpub['xpub'];
        $vaults["{$xpub['name']}/{$type}"] = ['type' => $type, 'keys' => $keys];
    }
}
$vaultOf = static function (string $xpubName, string $blockchain, string $network) use ($vectors, $vaults): ?array {
    $type = strtolower($vectors['chains'][$blockchain]['networks'][$network]['vaultType'] ?? 'TEST');

    return $vaults["{$xpubName}/{$type}"] ?? null;
};
$paramsOf = static fn (array $c): array => [
    'vaultId' => "{$c['xpubName']}",
    'blockchain' => $c['blockchain'],
    'network' => $c['network'],
    'accountIndex' => $c['accountIndex'],
    'isChange' => $c['change'],
    'addressIndex' => $c['addressIndex'],
    'addressFormat' => $c['addressFormat'],
    'address' => $c['address'],
];
$verifier = new AddressVerifier();

/**
 * Runs $run and returns the AddressVerificationError reason it throws, 'invalid_argument' for an
 * InvalidArgumentException, or 'verified' when it returns.
 */
$outcomeOf = static function (callable $run): string {
    try {
        $result = $run();

        return $result['verified'] === true ? 'verified' : 'returned ' . $result['reason'];
    } catch (AddressVerificationError $error) {
        return $error->reason;
    } catch (InvalidArgumentException $error) {
        return 'invalid_argument';
    }
};

$tests = [
    'address-v1.json is the v1 format, with cases and refused inputs' => static function () use ($vectors): void {
        check($vectors['format'] === 'vaultody address derivation vectors v1', 'format');
        check(count($vectors['cases']) === 511, 'expected 511 cases, found ' . count($vectors['cases']));
        check(count($vectors['rejected']) === 13, 'expected 13 rejected inputs, found ' . count($vectors['rejected']));
    },

    'the chain table is the server\'s: chains, algorithms, wire formats, networks and prefixes' => static function () use ($vectors): void {
        $theirs = array_keys($vectors['chains']);
        $ours = Chains::blockchains();
        sort($theirs);
        sort($ours);
        check($theirs === $ours, 'chains differ: ' . json_encode([$theirs, $ours]));
        check(count($ours) === 17, 'expected the 17 live chains');
        foreach ($vectors['chains'] as $blockchain => $chain) {
            $mine = Chains::describe($blockchain);
            check($mine !== null, $blockchain);
            check($mine['algorithm'] === $chain['algorithm'], "{$blockchain} algorithm");
            check(Chains::algorithmOf($blockchain) === $chain['algorithm'], "{$blockchain} algorithmOf");
            $formats = $mine['formats'];
            $wire = $chain['addressFormatsWire'];
            sort($formats);
            sort($wire);
            check($formats === $wire, "{$blockchain} formats");
            check(array_map('strtolower', $chain['addressFormats']) === $chain['addressFormatsWire'], "{$blockchain} format case");
            $networks = array_keys($mine['networks']);
            $theirNetworks = array_keys($chain['networks']);
            sort($networks);
            sort($theirNetworks);
            check($networks === $theirNetworks, "{$blockchain} networks");
            foreach ($chain['networks'] as $network => $settings) {
                $own = $mine['networks'][$network];
                check($own['main'] === ($settings['vaultType'] === 'MAIN'), "{$blockchain} {$network} main");
                check(($settings['vaultType'] === 'MAIN') === ($network === 'mainnet'), "{$blockchain} {$network} vault type");
                check(Chains::isMainNetwork($blockchain, $network) === $own['main'], "{$blockchain} {$network} isMainNetwork");
                check(Chains::networkFor($blockchain, $own['main'] ? 'main' : 'test') === $network, "{$blockchain} {$network} networkFor");
                // Every prefix encoded with must be the server's. (The server also lists some no format of
                // that chain uses, such as XRP's and Zcash's script hash bytes.)
                foreach (['pubKeyHash', 'scriptHash', 'bech32'] as $field) {
                    if (isset($own[$field])) {
                        check($own[$field] === $settings[$field], "{$blockchain} {$network} {$field}");
                    }
                }
            }
        }
        check(Chains::isKnown('stellar', 'mainnet') === false, 'stellar');
        check(Chains::isKnown('ethereum', 'goerli') === false, 'goerli');
        check(Chains::isKnown('bitcoin', 'sepolia') === false, 'bitcoin sepolia');
        check(Chains::networkFor('bitcoin', 'MAIN') === null, 'vault types are lower case');
        check(Chains::algorithmOf('Bitcoin') === null, 'chain names are exact');
    },

    'the vectors cover every chain, network and format' => static function () use ($vectors): void {
        $covered = [];
        foreach ($vectors['cases'] as $c) {
            $covered["{$c['blockchain']}/{$c['network']}/{$c['addressFormatWire']}"] = true;
        }
        foreach ($vectors['rejected'] as $r) {
            if (Chains::isRefusedFormat($r['blockchain'], $r['addressFormatWire'])) {
                $covered["{$r['blockchain']}/{$r['network']}/{$r['addressFormatWire']}"] = true;
            }
        }
        foreach (Chains::blockchains() as $blockchain) {
            foreach (array_keys(Chains::describe($blockchain)['networks']) as $network) {
                foreach (Chains::formats($blockchain) as $format) {
                    check(isset($covered["{$blockchain}/{$network}/{$format}"]), "{$blockchain}/{$network}/{$format}");
                }
            }
        }
    },
];

// Every case verifies, with the format as stored and with no format at all, and derives the server's
// child key. Account/change nodes for the key comparison are derived separately from the verifier's.
$roots = [];
$parents = [];
$parentOf = static function (array $c) use (&$roots, &$parents): DerivedNode {
    $key = "{$c['xpub']}/{$c['accountIndex']}/" . ($c['change'] ? 1 : 0);
    if (!isset($parents[$key])) {
        $roots[$c['xpub']] ??= ExtendedPublicKey::parse($c['xpub'], $c['algorithm']);
        $parents[$key] = Derivation::derivePath($roots[$c['xpub']], [$c['accountIndex'], $c['change'] ? 1 : 0]);
    }

    return $parents[$key];
};
foreach ($vectors['cases'] as $c) {
    $tests["case {$c['name']}"] = static function () use ($c, $verifier, $vaultOf, $paramsOf, $parentOf): void {
        $vault = $vaultOf($c['xpubName'], $c['blockchain'], $c['network']);
        $params = $paramsOf($c);
        $expected = ['verified' => true, 'algorithm' => $c['algorithm'], 'path' => $c['path'], 'address' => $c['address'], 'addressFormat' => $c['addressFormatWire']];
        $withFormat = $verifier->verify($vault, $params);
        check($withFormat === $expected, 'with the format: ' . json_encode($withFormat));
        $withoutFormat = $verifier->verify($vault, ['addressFormat' => null] + $params);
        check($withoutFormat === $expected, 'without a format: ' . json_encode($withoutFormat));
        $key = bin2hex(Derivation::derivePath($parentOf($c), [$c['addressIndex']])->key);
        check($key === $c['publicKey'], "child key {$key}");
    };
}

$tests += [
    'a changed address is mismatch, for one case of every chain, network and format' => static function () use ($vectors, $verifier, $vaultOf, $paramsOf, $outcomeOf): void {
        $seen = [];
        foreach ($vectors['cases'] as $c) {
            $group = "{$c['blockchain']}/{$c['network']}/{$c['addressFormatWire']}";
            if (isset($seen[$group])) {
                continue;
            }
            $seen[$group] = true;
            $last = substr($c['address'], -1);
            $changed = substr($c['address'], 0, -1) . ($last === 'a' ? 'b' : 'a');
            $outcome = $outcomeOf(fn () => $verifier->verify($vaultOf($c['xpubName'], $c['blockchain'], $c['network']), ['address' => $changed] + $paramsOf($c)));
            check($outcome === AddressVerificationError::MISMATCH, "{$group}: {$outcome}");
        }
        check(count($seen) >= 40, 'expected every chain, network and format, found ' . count($seen));
    },

    'an EVM address verifies in any letter case; other chains are case-sensitive' => static function () use ($vectors, $verifier, $vaultOf, $paramsOf, $outcomeOf): void {
        foreach (['ethereum', 'bitcoin', 'tron'] as $blockchain) {
            foreach ($vectors['cases'] as $c) {
                if ($c['blockchain'] !== $blockchain || strtoupper($c['address']) === $c['address']) {
                    continue;
                }
                $upper = str_starts_with($c['address'], '0x') ? '0x' . strtoupper(substr($c['address'], 2)) : strtoupper($c['address']);
                $outcome = $outcomeOf(fn () => $verifier->verify($vaultOf($c['xpubName'], $c['blockchain'], $c['network']), ['address' => $upper] + $paramsOf($c)));
                check($outcome === ($blockchain === 'ethereum' ? 'verified' : AddressVerificationError::MISMATCH), "{$blockchain}: {$outcome}");
                break;
            }
        }
    },

    'formats refused on chains without SegWit are in rejected and have no cases' => static function () use ($vectors): void {
        $refused = [];
        foreach ($vectors['rejected'] as $r) {
            if (Chains::isRefusedFormat($r['blockchain'], $r['addressFormatWire'])) {
                $refused["{$r['blockchain']}/{$r['addressFormatWire']}"] = true;
            }
        }
        $refused = array_keys($refused);
        sort($refused);
        check($refused === ['bitcoin-cash/p2sh', 'bitcoin-cash/p2sh-cash', 'dash/p2sh', 'dogecoin/p2sh'], json_encode($refused));
        foreach ($vectors['cases'] as $c) {
            check(!Chains::isRefusedFormat($c['blockchain'], $c['addressFormatWire']), $c['name']);
        }
    },

    'refused formats are unsupported when the format is given, in either case' => static function () use ($vectors, $verifier, $vaultOf, $outcomeOf): void {
        foreach ($vectors['rejected'] as $r) {
            if (!Chains::isRefusedFormat($r['blockchain'], $r['addressFormatWire'])) {
                continue;
            }
            // An address the same vault really has, so only the refused format can stop it.
            $sample = null;
            foreach ($vectors['cases'] as $c) {
                if ($c['xpubName'] === $r['xpubName'] && $c['blockchain'] === $r['blockchain']) {
                    $sample = $c;
                    break;
                }
            }
            check($sample !== null, "a sample for {$r['name']}");
            foreach ([$r['addressFormatWire'], $r['addressFormat']] as $format) {
                $outcome = $outcomeOf(fn () => $verifier->verify($vaultOf($r['xpubName'], $r['blockchain'], $r['network']), [
                    'blockchain' => $r['blockchain'], 'network' => $r['network'], 'accountIndex' => $r['accountIndex'],
                    'isChange' => $r['change'], 'addressIndex' => $r['addressIndex'], 'addressFormat' => $format, 'address' => $sample['address'],
                ]));
                check($outcome === AddressVerificationError::UNSUPPORTED, "{$r['name']} {$format}: {$outcome}");
            }
        }
    },

    'formats that stay supported verify, with and without the format' => static function () use ($vectors, $verifier, $vaultOf, $paramsOf): void {
        $wanted = [
            ['bitcoin', 'mainnet', 'p2sh'], ['bitcoin', 'testnet', 'p2sh'], ['litecoin', 'mainnet', 'p2sh'], ['litecoin', 'testnet', 'p2sh'],
            ['bitcoin-cash', 'mainnet', 'p2pkh-cash'], ['bitcoin-cash', 'mainnet', 'p2pkh'], ['dogecoin', 'mainnet', 'p2pkh'], ['dash', 'mainnet', 'p2pkh'],
        ];
        foreach ($wanted as [$blockchain, $network, $format]) {
            $found = null;
            foreach ($vectors['cases'] as $c) {
                if ($c['blockchain'] === $blockchain && $c['network'] === $network && $c['addressFormatWire'] === $format) {
                    $found = $c;
                    break;
                }
            }
            check($found !== null, "a vector for {$blockchain} {$network} {$format}");
            $vault = $vaultOf($found['xpubName'], $blockchain, $network);
            check($verifier->verify($vault, ['addressFormat' => $format] + $paramsOf($found))['addressFormat'] === $format, "{$blockchain} {$network} {$format}");
            check($verifier->verify($vault, ['addressFormat' => null] + $paramsOf($found))['verified'] === true, "{$blockchain} {$network} without a format");
        }
    },
];

// No input the server refuses is ever reported as verified.
foreach ($vectors['rejected'] as $r) {
    $tests["rejected {$r['name']} ({$r['reason']})"] = static function () use ($r, $vectors, $verifier, $vaultOf, $outcomeOf): void {
        // Any address will do: none may verify. Use one the same key derives.
        $sample = $vectors['cases'][0];
        foreach ($vectors['cases'] as $c) {
            if ($c['xpubName'] === $r['xpubName'] && $c['blockchain'] === $r['blockchain']) {
                $sample = $c;
                break;
            }
        }
        $outcome = $outcomeOf(fn () => $verifier->verify($vaultOf($r['xpubName'], $r['blockchain'], $r['network']), [
            'blockchain' => $r['blockchain'], 'network' => $r['network'], 'accountIndex' => $r['accountIndex'],
            'isChange' => $r['change'], 'addressIndex' => $r['addressIndex'], 'addressFormat' => $r['addressFormat'], 'address' => $sample['address'],
        ]));
        check(in_array($outcome, ['invalid_argument', AddressVerificationError::UNSUPPORTED, AddressVerificationError::MISMATCH], true), "outcome {$outcome}");
    };
}

$tests += [
    'the checks run in their fixed order' => static function () use ($vectors, $verifier, $vaultOf, $paramsOf, $outcomeOf): void {
        $c = null;
        foreach ($vectors['cases'] as $candidate) {
            if ($candidate['blockchain'] === 'bitcoin' && $candidate['network'] === 'mainnet' && $candidate['addressFormatWire'] === 'p2wpkh') {
                $c = $candidate;
                break;
            }
        }
        check($c !== null, 'a bitcoin mainnet p2wpkh case');
        $main = $vaultOf($c['xpubName'], 'bitcoin', 'mainnet');
        $test = $vaultOf($c['xpubName'], 'bitcoin', 'testnet');
        $params = $paramsOf($c);
        $cases = [
            // 0. argument types and ranges, before anything else
            ['invalid_argument', null, ['accountIndex' => 2147483648] + $params],
            ['invalid_argument', $main, ['accountIndex' => -1] + $params],
            ['invalid_argument', $main, ['accountIndex' => '07'] + $params],
            ['invalid_argument', $main, ['accountIndex' => 1.0] + $params],
            ['invalid_argument', $main, ['accountIndex' => true] + $params],
            ['invalid_argument', $main, ['isChange' => 2] + $params],
            ['invalid_argument', $main, ['isChange' => 'true'] + $params],
            ['invalid_argument', $main, ['address' => ''] + $params],
            ['invalid_argument', $main, ['addressFormat' => 5] + $params],
            ['invalid_argument', ['type' => 'MAIN', 'keys' => $main['keys']], $params],
            ['invalid_argument', ['type' => 'main', 'keys' => ['ECDSA' => '']], $params],
            // 1. the chain and network
            [AddressVerificationError::UNSUPPORTED, null, ['blockchain' => 'stellar'] + $params],
            [AddressVerificationError::UNSUPPORTED, null, ['network' => 'sepolia'] + $params],
            [AddressVerificationError::UNSUPPORTED, $main, ['blockchain' => 'Bitcoin'] + $params],
            // 2. the vault
            [AddressVerificationError::UNKNOWN_VAULT, null, $params],
            // 3. the network belongs with the vault type
            [AddressVerificationError::NETWORK_MISMATCH, $test, $params],
            [AddressVerificationError::NETWORK_MISMATCH, $main, ['network' => 'testnet', 'accountIndex' => null] + $params],
            // 4. the derivation path
            [AddressVerificationError::NOT_VERIFIABLE, $main, ['accountIndex' => null] + $params],
            [AddressVerificationError::NOT_VERIFIABLE, $main, ['isChange' => null, 'addressFormat' => 'p2sh-cash'] + $params],
            [AddressVerificationError::NOT_VERIFIABLE, ['type' => 'main', 'keys' => []], ['addressIndex' => null] + $params],
            // 5. the format
            [AddressVerificationError::UNSUPPORTED, $main, ['addressFormat' => 'p2pkh-cash'] + $params],
            [AddressVerificationError::UNSUPPORTED, ['type' => 'main', 'keys' => []], ['addressFormat' => 'standard'] + $params],
            // 6. the key
            [AddressVerificationError::MISSING_KEY, ['type' => 'main', 'keys' => ['EDDSA' => $main['keys']['ECDSA']]], $params],
            [AddressVerificationError::MISSING_KEY, ['type' => 'main', 'keys' => ['ECDSA' => 'xpub-not-base58']], $params],
            [AddressVerificationError::MISSING_KEY, ['type' => 'main', 'keys' => ['ECDSA' => $vectors['xpubs'][3]['xpub']]], $params],
            // 7. the address
            [AddressVerificationError::MISMATCH, $main, ['addressIndex' => $c['addressIndex'] === 0 ? 1 : 0] + $params],
            ['verified', $main, ['accountIndex' => (string) $c['accountIndex'], 'addressIndex' => (string) $c['addressIndex'], 'isChange' => $c['change'] ? 1 : 0] + $params],
            ['verified', $main, ['addressFormat' => 'P2WPKH', 'unknownField' => 'ignored'] + $params],
        ];
        foreach ($cases as $index => [$expected, $vault, $input]) {
            $outcome = $outcomeOf(fn () => $verifier->verify($vault, $input));
            check($outcome === $expected, "case {$index}: expected {$expected}, got {$outcome}");
        }
        $returned = $verifier->verify($main, ['accountIndex' => null] + $params, true);
        check($returned === ['verified' => false, 'reason' => AddressVerificationError::NOT_VERIFIABLE], 'allowUnverifiable returns not_verifiable');
    },

    'every ECDSA case also verifies where OpenSSL has no secp256k1 (k * G computed here)' => static function () use ($vectors, $vaultOf, $paramsOf): void {
        $usable = new ReflectionProperty(Secp256k1::class, 'opensslUsable');
        $before = $usable->getValue();
        $usable->setValue(null, false);
        try {
            $pure = new AddressVerifier();
            foreach ($vectors['cases'] as $c) {
                if ($c['algorithm'] !== Chains::ECDSA) {
                    continue;
                }
                $result = $pure->verify($vaultOf($c['xpubName'], $c['blockchain'], $c['network']), $paramsOf($c));
                check($result['verified'] === true && $result['path'] === $c['path'], $c['name']);
            }
        } finally {
            $usable->setValue(null, $before);
        }
    },

    'no xpub ever appears in an error message' => static function () use ($vectors, $verifier, $paramsOf): void {
        $c = $vectors['cases'][0];
        foreach ($vectors['xpubs'] as $xpub) {
            foreach ([Chains::ECDSA, Chains::EDDSA] as $algorithm) {
                try {
                    $verifier->verify(['type' => 'main', 'keys' => [$algorithm => $xpub['xpub']]], ['address' => 'not-it'] + $paramsOf($c));
                } catch (AddressVerificationError $error) {
                    check(!str_contains($error->getMessage(), $xpub['xpub']), 'an xpub in ' . $error->reason);
                }
            }
        }
    },

    'the cache stays within its limit' => static function () use ($vectors, $vaultOf, $paramsOf): void {
        $small = new AddressVerifier(2);
        foreach (array_slice($vectors['cases'], 0, 12) as $c) {
            check($small->verify($vaultOf($c['xpubName'], $c['blockchain'], $c['network']), $paramsOf($c))['verified'] === true, $c['name']);
        }
        $nodes = (new ReflectionProperty(AddressVerifier::class, 'nodes'))->getValue($small);
        $roots = (new ReflectionProperty(AddressVerifier::class, 'roots'))->getValue($small);
        check(count($nodes) <= 2 && count($roots) <= 2, 'cache size');
        try {
            new AddressVerifier(0);
            check(false, 'a zero cache is refused');
        } catch (InvalidArgumentException) {
        }
    },
];

return $tests;
