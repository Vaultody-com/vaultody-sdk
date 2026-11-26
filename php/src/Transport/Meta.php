<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

/** What the SDK knows about an answer besides its data. */
final class Meta
{
    /**
     * @param 'verified'|'absent' $signature whether the response signature was checked against a pinned
     *        root ('absent': no signature headers at all, accepted only before the client has seen a signed
     *        response from this API origin, and never in 'required' mode)
     * @param list<array{vaultId: string, address: string, status: 'verified'|'unverified'|'not_verifiable'}> $addressChecks
     *        one per address in the answer, in order (the same entries in every language), status: verified (derives from a pin a signed answer confirmed), unverified (derives from a pin
     *        trusted on first use from an unsigned answer), not_verifiable (no derivation path, or a vault
     *        without MPC keys); a mismatch is an error, never a status
     * @param list<array{vaultId: string, status: 'verified'|'unverified'|'not_verifiable', outcome: 'pinned'|'unchanged'|'upgraded'|'not_verifiable'}> $vaultKeys
     *        listVaults only: one per vault of the answer, in order. status: the vault's pin after the answer
     *        (verified, unverified) or not_verifiable (no MPC keys: SMART, AUTOMATION); outcome: what the
     *        answer did to the pin. An xpub that differs from its pin is never a result: VaultKeyChangedError
     */
    public function __construct(
        public readonly ?string $requestId,
        public readonly ?string $apiVersion,
        public readonly ?string $context,
        public readonly bool $replayed,
        public readonly string $signature,
        public readonly array $addressChecks = [],
        public readonly array $vaultKeys = [],
    ) {
    }

    /** @param list<array{vaultId: string, address: string, status: string}> $addressChecks */
    public function withAddressChecks(array $addressChecks): self
    {
        return new self($this->requestId, $this->apiVersion, $this->context, $this->replayed, $this->signature, $addressChecks, $this->vaultKeys);
    }

    /** @param list<array{vaultId: string, status: string, outcome: string}> $vaultKeys */
    public function withVaultKeys(array $vaultKeys): self
    {
        return new self($this->requestId, $this->apiVersion, $this->context, $this->replayed, $this->signature, $this->addressChecks, $vaultKeys);
    }
}
