<?php

declare(strict_types=1);

// The SDK's own vector sets: envelope-errors-v1.json (its sdkErrors too), pagination-v1.json, path-encoding-v1.json,
// retry-v1.json and the php rows of transport-errors-v1.json.

use Vaultody\Sdk\Envelope;
use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\PaginationError;
use Vaultody\Sdk\Exception\ParameterError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Http\HttpClient;
use Vaultody\Sdk\Http\HttpRequest;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Pagination;
use Vaultody\Sdk\RequestTarget;
use Vaultody\Sdk\Retry;
use Vaultody\Sdk\TransportErrors;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\Webhooks;

$tests = [];

foreach (vectors('envelope-errors-v1.json')['cases'] as $vector) {
    $tests['envelope-errors-v1.json ' . $vector['name']] = static function () use ($vector): void {
        $expected = $vector['expected'];
        if ($expected['kind'] !== 'error') {
            $result = Envelope::read($vector['status'], $vector['headers'], $vector['body']);
            $actual = $result;
            unset($actual['item'], $actual['items']);
            if ($result['kind'] === 'page') {
                $actual['count'] = count($result['items']);
            }
            ksort($actual);
            ksort($expected);
            check($actual === $expected, 'got ' . json_encode($actual));

            return;
        }
        $error = thrown(static fn () => Envelope::read($vector['status'], $vector['headers'], $vector['body']), ApiError::class);
        $class = 'Vaultody\\Sdk\\Exception\\' . $expected['class'];
        check(get_class($error) === $class, 'class ' . get_class($error));
        check($error instanceof VaultodyError, 'a VaultodyError');
        check($error->status === $vector['status'], 'status');
        check($error->code === $expected['code'], 'code ' . var_export($error->code, true));
        if ($expected['message'] !== null) {
            check($error->getMessage() === $expected['message'], 'message');
        } else {
            check($error->getMessage() !== '', 'a message');
        }
        check($error->requestId === $expected['requestId'], 'requestId');
        check($error->apiVersion === $expected['apiVersion'], 'apiVersion');
        check($error->replayed === $expected['replayed'], 'replayed');
        check($error->retryable === $expected['retryable'], 'retryable');
        check($error->hasDetails === array_key_exists('details', $expected), 'hasDetails');
        if (array_key_exists('details', $expected)) {
            check($error->details === $expected['details'], 'details');
        }
    };
}

$tests['envelope: an empty JSON object as item is an item, an empty array is not'] = static function (): void {
    check(Envelope::read(200, [], '{"data":{"item":{}}}')['item'] === [], 'empty item');
    thrown(static fn () => Envelope::read(200, [], '{"data":{"item":[]}}'), ApiError::class);
};
$tests['envelope: big integers stay strings'] = static function (): void {
    $item = Envelope::read(200, [], '{"data":{"item":{"amount":123456789012345678901234567890}}}')['item'];
    check($item['amount'] === '123456789012345678901234567890', 'amount ' . var_export($item['amount'], true));
};

foreach (vectors('pagination-v1.json')['cases'] as $vector) {
    $tests['pagination-v1.json ' . $vector['name']] = static function () use ($vector): void {
        $requests = [];
        $fetchPage = static function (array $request) use ($vector, &$requests): array {
            $page = $vector['pages'][count($requests)] ?? null;
            $requests[] = $request;
            check($page !== null, 'an extra request: ' . json_encode($request));
            check($request == $page['request'] && array_keys($request) == array_keys($page['request']), 'request ' . json_encode($request));

            return $page['response'];
        };
        $field = $vector['paging'] === 'offset' ? $vector['itemField'] : $vector['cursorField'];
        $generator = Pagination::paginate([
            'paging' => $vector['paging'],
            'cursorField' => $vector['cursorField'] ?? null,
            'limit' => $vector['limit'] ?? null,
            'maxLimit' => $vector['maxLimit'],
            'maxItems' => $vector['maxItems'] ?? null,
        ], $fetchPage);
        $items = [];
        $error = null;
        try {
            foreach ($generator as $item) {
                $items[] = $item[$field] ?? null;
            }
        } catch (PaginationError $e) {
            $error = $e->code;
        }
        check($items === $vector['expected']['items'], 'items ' . json_encode($items));
        check(count($requests) === count($vector['pages']), 'every page and no more');
        if (isset($vector['expected']['error'])) {
            check($error === $vector['expected']['error'], 'error ' . var_export($error, true));
        } else {
            check($error === null, 'no error');
            check($generator->getReturn() === $vector['expected']['stop'], 'stop ' . $generator->getReturn());
        }
    };
}

foreach (vectors('path-encoding-v1.json')['cases'] as $vector) {
    $tests['path-encoding-v1.json ' . $vector['name']] = static function () use ($vector): void {
        $build = static fn () => RequestTarget::build($vector['template'], $vector['pathParams'], $vector['query']);
        if (isset($vector['expected']['error'])) {
            check(thrown($build, ParameterError::class)->code === $vector['expected']['error'], 'code');

            return;
        }
        $target = $build();
        check($target === $vector['expected']['target'], 'target ' . $target);
    };
}
$tests['path-encoding: text with no UTF-8 form is refused in the path and in the query'] = static function (): void {
    check(thrown(static fn () => RequestTarget::build('/vaults/{vaultId}/utxos', ['vaultId' => "\xed\xa0\x80"]), ParameterError::class)->code === 'invalid_path_param', 'path');
    check(thrown(static fn () => RequestTarget::build('/supported-assets', [], [['assetUnit', "a\xff"]]), ParameterError::class)->code === 'invalid_query_param', 'query');
    check(thrown(static fn () => RequestTarget::build('/supported-assets', [], [['limit', 2.0]]), ParameterError::class)->code === 'invalid_query_param', 'a float');
    check(thrown(static fn () => RequestTarget::build('/supported-assets', [], [['limit', PHP_INT_MAX]]), ParameterError::class)->code === 'invalid_query_param', 'beyond 2^53');
};

// envelope-errors-v1.json sdkErrors: the errors the SDK raises with no answer of the API, in the
// Vaultody\Sdk\Exception namespace, each a VaultodyError, raised for real with the class and fields of Node and Python.
$sdkErrors = vectors('envelope-errors-v1.json')['sdkErrors'];
foreach ($sdkErrors['classes'] as $name) {
    $tests['envelope-errors-v1.json sdkErrors class ' . $name] = static function () use ($name): void {
        $class = 'Vaultody\\Sdk\\Exception\\' . $name;
        check(class_exists($class), 'exists');
        check(is_subclass_of($class, VaultodyError::class), 'a VaultodyError');
    };
}
foreach ($sdkErrors['cases'] as $vector) {
    $tests['envelope-errors-v1.json sdkErrors ' . $vector['name']] = static function () use ($vector): void {
        $class = 'Vaultody\\Sdk\\Exception\\' . $vector['expected']['class'];
        if (isset($vector['call'])) {
            $refuse = new class () implements HttpClient {
                public function send(HttpRequest $request): HttpResponse
                {
                    throw new RuntimeException('nothing may be sent');
                }
            };
            $client = new Vaultody([
                'apiKey' => 'TEST-ONLY-key', 'apiSecret' => 'VEVTVC1PTkxZ', 'passphrase' => 'TEST-ONLY-passphrase',
                'vaultKeyStore' => new MemoryVaultKeyStore(), 'httpClient' => $refuse,
            ]);
            $call = $vector['call'];
            $error = thrown(static fn () => $client->{$call['group']}->{$call['operationId']}($call['params']), $class);
        } else {
            $webhook = $vector['webhook'];
            $error = thrown(static fn () => (new Webhooks())->verify((string) base64_decode($webhook['bodyBase64'], true), $webhook['headers'], $webhook['secrets']), $class);
        }
        check(get_class($error) === $class, 'class ' . get_class($error));
        check($error instanceof VaultodyError, 'a VaultodyError');
        foreach ($vector['expected']['fields'] as $field => $value) {
            check($error->{$field} === $value, $field . ' ' . var_export($error->{$field}, true));
        }
    };
}

$retry = vectors('retry-v1.json');
$tests['retry-v1.json uses the constants of the vectors'] = static function () use ($retry): void {
    check(Retry::constants() === $retry['constants'], 'constants');
};
foreach ($retry['cases'] as $vector) {
    $tests['retry-v1.json ' . $vector['name']] = static function () use ($vector): void {
        $decision = Retry::decide($vector['input']);
        check($decision === $vector['expected'], 'got ' . json_encode($decision));
    };
}

foreach (vectors('transport-errors-v1.json')['php'] as $vector) {
    $tests['transport-errors-v1.json (php) ' . $vector['name']] = static function () use ($vector): void {
        check(TransportErrors::classifyCurlErrno($vector['curlErrno']) === $vector['expected'], 'classification');
        // PHP names errno 60 CURLE_SSL_CACERT (the older libcurl name of CURLE_PEER_FAILED_VERIFICATION)
        $name = $vector['name'] === 'CURLE_PEER_FAILED_VERIFICATION' ? 'CURLE_SSL_CACERT' : $vector['name'];
        check(constant($name) === $vector['curlErrno'], 'the curl constant has this number');
    };
}

return $tests;
