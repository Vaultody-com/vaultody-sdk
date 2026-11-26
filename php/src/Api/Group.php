<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\Model;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Operations;
use Vaultody\Sdk\Transport\Item;
use Vaultody\Sdk\Transport\Meta;
use Vaultody\Sdk\Transport\Page as TransportPage;
use Vaultody\Sdk\Transport\Transport;

/**
 * The base of the client's endpoint groups (one per docs group). Every method of a group is a thin
 * wrapper: it names its operation, and this checks the params against the operation table, sends the call
 * through the transport (signed, verified, retried by the rules, addresses checked) and builds the models.
 */
abstract class Group
{
    /** @internal the client builds its groups */
    public function __construct(private readonly Transport $transport)
    {
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [];
    }

    /**
     * Calls an operation that answers one item.
     *
     * @template T of Model
     * @param class-string<T> $model the operation's model, as the operation table names it
     * @param array<array-key, mixed> $params
     * @param array<array-key, mixed> $options
     * @return T
     * @throws VaultodyError
     */
    protected function item(string $operationId, string $model, array $params, array $options): Model
    {
        $operation = self::operation($operationId, $model);
        $result = $this->transport->call(Operations::transportOperation($operationId), Params::prepare($operation, $params, $options));
        if (!$result instanceof Item) {
            throw self::unexpected($result->meta, sprintf('%s answered a list where one item was expected', $operationId));
        }

        return $model::fromArray($result->data, $result->meta);
    }

    /**
     * Calls a list operation: its first page (or the page after startingAfter), from which every later
     * page can be reached.
     *
     * @template T of Model
     * @param class-string<T> $model the model of each item, as the operation table names it
     * @param array<array-key, mixed> $params
     * @param array<array-key, mixed> $options
     * @return Page<T>
     * @throws VaultodyError
     */
    protected function page(string $operationId, string $model, array $params, array $options): Page
    {
        $operation = self::operation($operationId, $model);

        return $this->fetchPage($operation, Params::prepare($operation, $params, $options));
    }

    /**
     * @param class-string<Model> $model
     * @return array<string, mixed>
     */
    private static function operation(string $operationId, string $model): array
    {
        $operation = Operations::get($operationId);
        if ($operation['model'] !== $model) {
            throw new \LogicException(sprintf('%s answers %s in the operation table, not %s', $operationId, $operation['model'], $model));
        }

        return $operation;
    }

    /**
     * @param array<string, mixed> $operation
     * @param array<string, mixed> $sent
     * @return Page<Model>
     */
    private function fetchPage(array $operation, array $sent): Page
    {
        $operationId = $operation['operationId'];
        $result = $this->transport->call(Operations::transportOperation($operationId), $sent);
        if (!$result instanceof TransportPage) {
            throw self::unexpected($result->meta, sprintf('%s answered one item where a list was expected', $operationId));
        }

        $items = [];
        foreach ($result->items as $raw) {
            if (!is_array($raw) || ($raw !== [] && array_is_list($raw))) {
                throw self::unexpected($result->meta, sprintf('an item of the %s list is not an object', $operationId));
            }
            $items[] = $operation['model']::fromArray($raw);
        }

        $hasMore = $result->hasMore;
        if ($operation['paging'] === 'offset') {
            // The answer says how many there are in all; this operation takes no offset, so this is the first page.
            $hasMore = (is_int($result->total) || is_float($result->total)) && count($items) < $result->total;
        }
        $cursorField = $operation['cursorField'];
        $continue = $operation['paging'] === 'cursor' && $cursorField !== null
            ? fn (string $cursor): Page => $this->fetchPage($operation, ['startingAfter' => $cursor] + $sent)
            : null;

        return new Page(
            $items,
            $result->items,
            $hasMore,
            $result->limit,
            $result->startingAfter,
            $result->total,
            $result->meta,
            $cursorField,
            is_int($sent['limit'] ?? null) ? $sent['limit'] : null,
            is_string($sent['startingAfter'] ?? null) ? $sent['startingAfter'] : null,
            $continue,
        );
    }

    private static function unexpected(Meta $meta, string $message): ApiError
    {
        return new ApiError(200, null, $message, $meta->requestId, $meta->apiVersion, $meta->replayed);
    }
}
