<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

/**
 * What the transport needs to know about one documented operation to build, sign, retry, page and check
 * it. The endpoint methods are thin wrappers that pass one of these and the caller's flat params.
 *
 * @internal
 */
final class Operation
{
    /** The address in each answer item derives from the vault's xpub; vault, chain and network in the path. */
    public const ADDRESSES_IN_PATH = 'path';
    /** List of addresses: vault in the path, chain in each item, network in the item or from the vault type. */
    public const ADDRESSES_IN_ITEMS = 'items';
    /** Add asset: the answer's address must be the one sent, and derives like the others. */
    public const ADDRESSES_ADD_ASSET = 'add_asset';

    /**
     * @param 'GET'|'POST'|'PUT' $method
     * @param 'read'|'write' $retry read: retried and re-signed freely (GET and the POSTs that change nothing);
     *        write: never re-signed with a new nonce once it may have reached the gateway
     * @param list<string> $pathParams the {names} of $path
     * @param list<string> $queryParams query parameters, in the order they are sent
     * @param bool $hasBody POST/PUT: every other param goes in data.item, and context next to data
     * @param 'none'|'cursor'|'offset' $paging
     * @param ?string $addresses one of the ADDRESSES_* constants when the answer carries vault addresses
     * @param bool $vaultList the answer lists vaults with their xpubs: compared with the pins, new ones pinned
     */
    public function __construct(
        public readonly string $operationId,
        public readonly string $method,
        public readonly string $path,
        public readonly string $retry,
        public readonly array $pathParams = [],
        public readonly array $queryParams = [],
        public readonly bool $hasBody = false,
        public readonly string $paging = 'none',
        public readonly ?string $cursorField = null,
        public readonly int $maxLimit = 50,
        public readonly ?string $addresses = null,
        public readonly bool $vaultList = false,
    ) {
        if (!in_array($retry, ['read', 'write'], true)) {
            throw new \InvalidArgumentException('retry must be read or write');
        }
    }
}
