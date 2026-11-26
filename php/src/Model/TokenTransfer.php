<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A token transfer of a blockchain transaction. */
final class TokenTransfer extends Model
{
    /**
     * @param ?string $amount The amount of tokens transferred.
     * @param ?string $amountUnit The token's symbol, for example USDT or USDC.
     * @param ?string $contractAddress The token's contract address.
     * @param ?int $decimals The number of decimal places the token uses.
     * @param ?string $fromAddress The address that sent the tokens.
     * @param ?string $toAddress The address that received the tokens.
     * @param ?string $tokenName The token's name, for example Tether USD.
     * @param ?string $type The token standard, for example ERC-20, BEP-20 or TRC-20.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        public readonly ?string $contractAddress = null,
        public readonly ?int $decimals = null,
        public readonly ?string $fromAddress = null,
        public readonly ?string $toAddress = null,
        public readonly ?string $tokenName = null,
        public readonly ?string $type = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
