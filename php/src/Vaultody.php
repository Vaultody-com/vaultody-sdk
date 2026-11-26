<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Api\ApiKeys;
use Vaultody\Sdk\Api\AssetsAddresses;
use Vaultody\Sdk\Api\Transactions;
use Vaultody\Sdk\Api\VaultAccounts;
use Vaultody\Sdk\Api\Vaults;
use Vaultody\Sdk\Transport\Transport;

/**
 * The Vaultody API client.
 *
 *   $vaultody = new Vaultody\Sdk\Vaultody([
 *       'apiKey' => ..., 'apiSecret' => ..., 'passphrase' => ...,
 *       'privateKeyFile' => '/etc/vaultody/private.pem',        // when the API key holds a key pair
 *       'vaultKeysFile' => '/var/lib/vaultody/vault-keys.json',  // writable by every PHP worker
 *   ]);
 *
 *   $page = $vaultody->vaults->listVaults(['networkType' => 'main']);
 *   foreach ($page as $vault) { ... }                            // every page, fetched as needed
 *   $request = $vaultody->transactions->createSingleTransfer([...], ['context' => 'order-7']);
 *
 * One group per docs group, one method per documented operation, named by its operationId. Every call is
 * signed, every response is verified before it is read, and every vault address is checked against the
 * vault's pinned xpub. The methods are the only way in: each checks its params against the documented
 * contract before anything is sent, so the client hands out no lower-level request call.
 */
final class Vaultody
{
    public readonly Vaults $vaults;
    public readonly VaultAccounts $vaultAccounts;
    public readonly AssetsAddresses $assetsAddresses;
    public readonly Transactions $transactions;
    public readonly ApiKeys $apiKeys;
    public readonly Webhooks $webhooks;
    private Transport $transport;

    /**
     * @param array<string, mixed> $options see Transport::__construct
     * @throws Exception\ConfigurationError
     */
    public function __construct(#[\SensitiveParameter] array $options)
    {
        $this->transport = new Transport($options);
        $this->vaults = new Vaults($this->transport);
        $this->vaultAccounts = new VaultAccounts($this->transport);
        $this->assetsAddresses = new AssetsAddresses($this->transport);
        $this->transactions = new Transactions($this->transport);
        $this->apiKeys = new ApiKeys($this->transport);
        $this->webhooks = new Webhooks();
    }

    /**
     * The response-signature mode in force: 'required', or 'when-present' while unsigned answers are accepted until
     * the first signed one. Always 'required' with response-signing roots, whatever the responseSignature option says.
     */
    public function responseSignature(): string
    {
        return $this->transport->responseSignature();
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['transport' => $this->transport->__debugInfo()];
    }
}
