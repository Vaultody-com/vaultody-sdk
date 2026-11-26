<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\ApiKeySigningKey;
use Vaultody\Sdk\Model\Page;

/**
 * API keys: `$vaultody->apiKeys`.
 */
final class ApiKeys extends Group
{
    /**
     * Lists the public keys registered for request signing on the API key that makes the call, so you can
     * confirm they are your own: compare each fingerprint with your key's, and check that
     * `$page->meta->signature` is 'verified' before you trust the answer.
     *
     * The request takes no parameters: the list holds at most two keys, all on one page.
     *
     * @param array{} $params none
     * @param array{context?: string} $options
     * @return Page<ApiKeySigningKey>
     * @throws VaultodyError
     */
    #[Operation('listApiKeySigningKeys')]
    public function listApiKeySigningKeys(array $params = [], array $options = []): Page
    {
        return $this->page('listApiKeySigningKeys', ApiKeySigningKey::class, $params, $options);
    }
}
