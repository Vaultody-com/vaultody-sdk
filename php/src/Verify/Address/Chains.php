<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Every chain the address check knows, with its signing algorithm, its networks and the address formats
 * the server can issue on it.
 *
 * Chain and network names are those of the public API paths. The version bytes, Bech32 prefixes and
 * format names come from the Vaultody server's xpub utilities library; the server stores format names in
 * upper case and the API returns them in lower case. The algorithm per chain comes from the server's protocol settings: Solana uses EdDSA and every
 * other chain ECDSA.
 */
final class Chains
{
    public const ECDSA = 'ECDSA';
    public const EDDSA = 'EDDSA';

    private const BITCOIN_FORMATS = ['p2pkh' => 'p2pkh', 'p2sh' => 'p2sh', 'p2wpkh' => 'p2wpkh'];
    private const LEGACY_FORMATS = ['p2pkh' => 'p2pkh', 'p2sh' => 'p2sh'];
    private const EVM_FORMATS = ['standard' => 'standard'];

    /**
     * chain => algorithm, caseInsensitive (true where addresses are hex and may be written with EIP-55
     * capitals: the EVM chains), formats (format name as the API returns it => encoder) and networks
     * (name => main, and the prefixes the encoders use, as hex).
     */
    private const CHAINS = [
        'bitcoin' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => self::BITCOIN_FORMATS,
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '00', 'scriptHash' => '05', 'bech32' => 'bc'],
                'testnet' => ['main' => false, 'pubKeyHash' => '6f', 'scriptHash' => 'c4', 'bech32' => 'tb'],
            ],
        ],
        'litecoin' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => self::BITCOIN_FORMATS,
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '30', 'scriptHash' => '32', 'bech32' => 'ltc'],
                'testnet' => ['main' => false, 'pubKeyHash' => '6f', 'scriptHash' => 'c4', 'bech32' => 'tltc'],
            ],
        ],
        'dogecoin' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => self::LEGACY_FORMATS,
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '1e', 'scriptHash' => '16'],
                'testnet' => ['main' => false, 'pubKeyHash' => '71', 'scriptHash' => 'c4'],
            ],
        ],
        'dash' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => self::LEGACY_FORMATS,
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '4c', 'scriptHash' => '10'],
                'testnet' => ['main' => false, 'pubKeyHash' => '8c', 'scriptHash' => '13'],
            ],
        ],
        // CashAddr forms are the legacy address re-encoded; the prefix follows the network, as bchaddrjs
        // picks it from the legacy version byte.
        'bitcoin-cash' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false,
            'formats' => ['p2pkh' => 'p2pkh', 'p2sh' => 'p2sh', 'p2pkh-cash' => 'p2pkh-cash', 'p2sh-cash' => 'p2sh-cash'],
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '00', 'scriptHash' => '05', 'cashPrefix' => 'bitcoincash'],
                'testnet' => ['main' => false, 'pubKeyHash' => '6f', 'scriptHash' => 'c4', 'cashPrefix' => 'bchtest'],
            ],
        ],
        // Transparent Zcash addresses carry a two-byte version.
        'zcash' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => ['p2pkh' => 'p2pkh'],
            'networks' => [
                'mainnet' => ['main' => true, 'pubKeyHash' => '1cb8'],
                'testnet' => ['main' => false, 'pubKeyHash' => '1d25'],
            ],
        ],
        'xrp' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => ['classic' => 'classic'],
            'networks' => ['mainnet' => ['main' => true], 'testnet' => ['main' => false]],
        ],
        'tron' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => false, 'formats' => ['base58' => 'tron-base58'],
            'networks' => ['mainnet' => ['main' => true], 'nile' => ['main' => false]],
        ],
        'solana' => [
            'algorithm' => self::EDDSA, 'caseInsensitive' => false, 'formats' => ['base58' => 'solana-base58'],
            'networks' => ['mainnet' => ['main' => true], 'devnet' => ['main' => false]],
        ],
        'ethereum' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'sepolia' => ['main' => false]],
        ],
        'ethereum-classic' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'mordor' => ['main' => false]],
        ],
        'binance-smart-chain' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'testnet' => ['main' => false]],
        ],
        'polygon' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'amoy' => ['main' => false]],
        ],
        'arbitrum' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'sepolia' => ['main' => false]],
        ],
        'optimism' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'sepolia' => ['main' => false]],
        ],
        'base' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'sepolia' => ['main' => false]],
        ],
        'avalanche' => [
            'algorithm' => self::ECDSA, 'caseInsensitive' => true, 'formats' => self::EVM_FORMATS,
            'networks' => ['mainnet' => ['main' => true], 'fuji' => ['main' => false]],
        ],
    ];

    // Formats refused per chain. Bitcoin Cash, Dogecoin and Dash have no SegWit, but the server library
    // once derived their `p2sh` (and Bitcoin Cash's `p2sh-cash`) as P2SH-wrapped P2WPKH. Anyone can spend
    // coins sent to such an address, so it must never be reported as genuine. The server no longer
    // derives these and none exist in production.
    private const REFUSED_FORMATS = [
        'bitcoin-cash' => ['p2sh', 'p2sh-cash'],
        'dogecoin' => ['p2sh'],
        'dash' => ['p2sh'],
    ];

    /** @return list<string> every chain name, as in the API paths */
    public static function blockchains(): array
    {
        return array_keys(self::CHAINS);
    }

    /** The signing algorithm of a chain, or null for a chain this module does not know. */
    public static function algorithmOf(string $blockchain): ?string
    {
        return self::chain($blockchain)['algorithm'] ?? null;
    }

    /** Whether the chain and network pair is one this module knows. */
    public static function isKnown(string $blockchain, string $network): bool
    {
        return self::network($blockchain, $network) !== null;
    }

    /** Whether a known network of a chain is its main network (null when the pair is not known). */
    public static function isMainNetwork(string $blockchain, string $network): ?bool
    {
        $settings = self::network($blockchain, $network);

        return $settings === null ? null : $settings['main'] === true;
    }

    /**
     * The network an address of this chain has in a vault of this type: "mainnet" in a main vault, the
     * chain's one test network in a test vault. Null for an unknown chain or vault type.
     */
    public static function networkFor(string $blockchain, string $vaultType): ?string
    {
        $chain = self::chain($blockchain);
        if ($chain === null || ($vaultType !== 'main' && $vaultType !== 'test')) {
            return null;
        }
        foreach ($chain['networks'] as $name => $settings) {
            if ($settings['main'] === ($vaultType === 'main')) {
                return $name;
            }
        }

        return null;
    }

    /**
     * The table entry of one chain, for the tests that compare it with the server's vectors: algorithm,
     * the format names as the API returns them, and per network whether it is a main network and its
     * prefixes (hex) and Bech32 / CashAddr prefixes.
     *
     * @return array{algorithm: string, caseInsensitive: bool, formats: list<string>, networks: array<string, array<string, bool|string>>}|null
     */
    public static function describe(string $blockchain): ?array
    {
        $chain = self::chain($blockchain);
        if ($chain === null) {
            return null;
        }

        return [
            'algorithm' => $chain['algorithm'],
            'caseInsensitive' => $chain['caseInsensitive'],
            'formats' => array_keys($chain['formats']),
            'networks' => $chain['networks'],
        ];
    }

    /** @return list<string> the address formats of a chain as the API names them; empty when unknown */
    public static function formats(string $blockchain): array
    {
        return array_keys(self::chain($blockchain)['formats'] ?? []);
    }

    public static function isRefusedFormat(string $blockchain, string $format): bool
    {
        return in_array($format, self::REFUSED_FORMATS[$blockchain] ?? [], true);
    }

    /** Whether the chain's addresses compare without regard to letter case (the hex EVM addresses). */
    public static function isCaseInsensitive(string $blockchain): bool
    {
        return self::chain($blockchain)['caseInsensitive'] ?? false;
    }

    /**
     * The address of a derived key in one format of a chain and network.
     *
     * @throws \InvalidArgumentException for a chain, network or format this module does not know
     */
    public static function encode(string $blockchain, string $network, string $format, DerivedNode $node): string
    {
        $chain = self::chain($blockchain);
        $settings = self::network($blockchain, $network);
        if ($chain === null || $settings === null || !array_key_exists($format, $chain['formats'])) {
            throw new \InvalidArgumentException('unknown chain, network or address format');
        }
        if ($node->algorithm !== $chain['algorithm']) {
            throw new \InvalidArgumentException('the key is not of the chain\'s algorithm');
        }
        $prefix = static fn (string $field): string => (string) hex2bin((string) $settings[$field]);

        return match ($chain['formats'][$format]) {
            'p2pkh' => Base58::encodeCheck($prefix('pubKeyHash') . self::hash160($node->key)),
            // The server's "P2SH" is P2SH wrapping P2WPKH (bitcoinjs payments.p2sh({ redeem: p2wpkh })) on
            // every chain that offers it, including those without SegWit.
            'p2sh' => Base58::encodeCheck($prefix('scriptHash') . self::hash160(self::p2wpkhScript(self::hash160($node->key)))),
            'p2wpkh' => Bech32::segwitV0Address((string) $settings['bech32'], self::hash160($node->key)),
            'p2pkh-cash' => CashAddr::encode((string) $settings['cashPrefix'], CashAddr::TYPE_P2PKH, self::hash160($node->key)),
            'p2sh-cash' => CashAddr::encode((string) $settings['cashPrefix'], CashAddr::TYPE_P2SH, self::hash160(self::p2wpkhScript(self::hash160($node->key)))),
            // XRP: the account ID (hash160 of the compressed key) after a 00 type byte, in XRP's Base58
            // alphabet.
            'classic' => Base58::encodeCheck("\0" . self::hash160($node->key), Base58::RIPPLE_ALPHABET),
            // Ethereum and its relatives: 0x, then the last 20 bytes of Keccak-256 over the uncompressed
            // x || y, in lower case as the server returns them.
            'standard' => '0x' . bin2hex(substr(Keccak::keccak256(Secp256k1::rawXY($node->point)), 12)),
            // Tron: the Ethereum-style 20 bytes after a 41 byte, Base58Check.
            'tron-base58' => Base58::encodeCheck("\x41" . substr(Keccak::keccak256(Secp256k1::rawXY($node->point)), 12)),
            // Solana: the 32-byte ed25519 public key itself, in Base58.
            'solana-base58' => Base58::encode($node->key),
        };
    }

    /** RIPEMD-160 of SHA-256: the key hash of the UTXO chains and XRP. */
    public static function hash160(string $bytes): string
    {
        return hash('ripemd160', hash('sha256', $bytes, true), true);
    }

    // The redeem script of P2SH-P2WPKH: OP_0, push 20 bytes, the key hash.
    private static function p2wpkhScript(string $keyHash): string
    {
        return "\x00\x14" . $keyHash;
    }

    /** @return array{algorithm: string, caseInsensitive: bool, formats: array<string, string>, networks: array<string, array<string, bool|string>>}|null */
    private static function chain(string $blockchain): ?array
    {
        return array_key_exists($blockchain, self::CHAINS) ? self::CHAINS[$blockchain] : null;
    }

    /** @return array<string, bool|string>|null */
    private static function network(string $blockchain, string $network): ?array
    {
        $chain = self::chain($blockchain);
        if ($chain === null || !array_key_exists($network, $chain['networks'])) {
            return null;
        }

        return $chain['networks'][$network];
    }
}
