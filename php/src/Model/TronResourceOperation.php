<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The staking operation requested (tronResourceManagement). */
final class TronResourceOperation extends Model
{
    protected const LISTS = [
        'destination' => TronResourceDestination::class,
    ];

    /**
     * @param ?string $blockchain The blockchain of the address.
     * @param list<TronResourceDestination> $destination Where the resources go.
     * @param ?string $id The ID of the transaction request.
     * @param ?string $network The Tron network: `mainnet`, or the `nile` test network.
     * @param ?string $resource The resource to stake for or delegate: `bandwidth` or `energy`.
     * @param ?TronResourceSource $source The address the operation is made from.
     * @param ?string $status The status of the transaction request, for example `created`, or `await-approval-l2` while it waits for a second-level approval.
     * @param ?string $type The staking operation: `freeze`, `unfreeze`, `withdraw-resource`, `delegate` or `undelegate`.
     * @param ?string $vaultId The ID of the Vault that holds `fromAddress`.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $blockchain = null,
        public readonly array $destination = [],
        public readonly ?string $id = null,
        public readonly ?string $network = null,
        public readonly ?string $resource = null,
        public readonly ?TronResourceSource $source = null,
        public readonly ?string $status = null,
        public readonly ?string $type = null,
        public readonly ?string $vaultId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
