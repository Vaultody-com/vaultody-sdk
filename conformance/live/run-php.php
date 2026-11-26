<?php

/*
 * The live conformance cases through the PHP SDK: php run-php.php <out-dir>.
 *
 * Reads cases.json and <out-dir>/fixture.json, writes <out-dir>/results-php.json. It records what happened, as
 * run-node.js does; report.js judges every language by the same rules. Nothing secret is written or printed.
 * Same environment as the Node runner (conformance/live/README.md).
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/php/src/autoload.php';

use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\ResponseVerificationError;
use Vaultody\Sdk\Exception\VaultKeyStoreError;
use Vaultody\Sdk\Http\CurlHttpClient;
use Vaultody\Sdk\Http\HttpClient;
use Vaultody\Sdk\Http\HttpRequest;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\Version;

const CLIENT = 'php';
const CONTEXT = 'sdk-conformance';
const MAX_PAGE = 50;
const PRODUCTION_ORIGINS = ['https://rest.vaultody.com'];

/** Sends with curl, recording each request: method, path, nonce, status (and the limit a 429 names). */
final class CountingHttpClient implements HttpClient
{
    /** @var list<array<string, mixed>> */
    public array $log = [];
    private CurlHttpClient $inner;

    public function __construct()
    {
        $this->inner = new CurlHttpClient();
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $record = [
            'method' => $request->method,
            'path' => (string) parse_url($request->url, PHP_URL_PATH),
            'nonce' => $request->headers['x-api-nonce'] ?? null,
            'at' => microtime(true),
        ];
        $index = count($this->log);
        $this->log[] = $record;
        try {
            $response = $this->inner->send($request);
        } catch (\Throwable $error) {
            $this->log[$index]['error'] = (new \ReflectionClass($error))->getShortName();
            throw $error;
        }
        $this->log[$index]['status'] = $response->status;
        if ($response->status === 429) {
            $body = json_decode($response->body, true);
            $this->log[$index]['limit'] = is_array($body) ? ($body['error']['details'] ?? null) : null;
        }

        return $response;
    }
}

/** The client's logger: keeps each warning (they carry no secret), as the Node runner's logger does. */
final class CollectingLogger
{
    /** @var array<string, true> */
    public array $warnings = [];

    public function warning(string $message): void
    {
        $this->warnings[substr($message, 0, 200)] = true;
    }
}

function env(string $name): string
{
    $value = getenv($name);
    if (!is_string($value) || $value === '') {
        fwrite(STDERR, "$name is not set (conformance/live/README.md)\n");
        exit(1);
    }

    return $value;
}

function short(mixed $value): mixed
{
    return is_string($value) && strlen($value) > 12 ? substr($value, 0, 6) . '…' . substr($value, -4) : $value;
}

/** lib.js wrongPassphrase: the same length, the last character changed. */
function wrongPassphrase(string $passphrase): string
{
    return substr($passphrase, 0, -1) . (substr($passphrase, -1) === 'x' ? 'y' : 'x');
}

/**
 * lib.js resolveParams: "$name" from the fixture, "@caseId.field" from an earlier item, "{client}" and "{run}"
 * replaced. Returns [params, missing].
 *
 * @return array{0: mixed, 1: ?string}
 */
function resolveParams(mixed $value, array $fixture, array $items, string $run): array
{
    $missing = null;
    $walk = function (mixed $v) use (&$walk, &$missing, $fixture, $items, $run): mixed {
        if (is_string($v)) {
            if (str_starts_with($v, '$')) {
                $name = substr($v, 1);
                if (!isset($fixture[$name])) {
                    $missing ??= "fixture.$name";
                    return null;
                }
                return $fixture[$name];
            }
            if (str_starts_with($v, '@')) {
                [$caseId, $field] = explode('.', substr($v, 1), 2);
                $item = $items[$caseId] ?? null;
                if (!is_array($item) || !array_key_exists($field, $item)) {
                    $missing ??= "$caseId.$field";
                    return null;
                }
                return $item[$field];
            }
            return str_replace(['{client}', '{run}'], [CLIENT, $run], $v);
        }
        if (is_array($v)) {
            return array_map($walk, $v);
        }
        return $v;
    };
    $params = $walk($value);

    return [$params, $missing];
}

function errorOf(\Throwable $error): array
{
    $code = property_exists($error, 'code') ? (new \ReflectionProperty($error, 'code'))->getValue($error) : null;

    return [
        'class' => (new \ReflectionClass($error))->getShortName(),
        'apiError' => $error instanceof ApiError,
        'status' => $error instanceof ApiError ? $error->status : null,
        'code' => is_string($code) ? $code : null,
        'reason' => $error instanceof ResponseVerificationError ? $error->reason : null,
        'message' => substr($error->getMessage(), 0, 200),
    ];
}

function envelopeOf(object $meta): array
{
    return [
        'requestId' => is_string($meta->requestId) && $meta->requestId !== '',
        'apiVersion' => $meta->apiVersion,
        'context' => $meta->context === CONTEXT,
        'replayed' => $meta->replayed === true,
        'signature' => $meta->signature,
    ];
}

/** @param list<array{vaultId: string, address: string, status: string}> $checks */
function countStatuses(array $checks): array
{
    $out = [];
    foreach (array_column($checks, 'status') as $status) {
        $out[$status] = ($out[$status] ?? 0) + 1;
    }

    return $out;
}

/** The TEST-ONLY current root of test-vectors/v1.json, as SPKI PEM: a root no live origin signs with. */
function testRoot(): string
{
    $v1 = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/test-vectors/v1.json'), true, 512, JSON_THROW_ON_ERROR);

    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split($v1['keys']['roots']['current']['publicKeySpkiDerBase64'], 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** lib.js SEED: the vectors' canonical two_origins document, the pin file every client starts from. */
function seed(): array
{
    $vectors = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/test-vectors/vault-keys-file-v1.json'), true, 512, JSON_THROW_ON_ERROR);
    foreach ($vectors['canonical'] as $case) {
        if ($case['name'] === 'two_origins') {
            return $case;
        }
    }
    throw new \RuntimeException('no two_origins case in vault-keys-file-v1.json');
}

function seedPinFile(string $file, array $seed): void
{
    $previous = umask(0077);
    try {
        file_put_contents($file, $seed['text']);
    } finally {
        umask($previous);
    }
    chmod($file, 0600);
}

/** lib.js pinFileFacts: mode, hash, and whether the file is still the seed. */
function pinFileFacts(string $file, array $seed): array
{
    clearstatcache(true, $file);
    if (!is_file($file)) {
        return ['file' => basename($file), 'exists' => false];
    }
    $hash = hash('sha256', (string) file_get_contents($file));

    return ['file' => basename($file), 'exists' => true, 'mode' => decoct(fileperms($file) & 0777), 'sha256' => $hash, 'unchangedSinceSeed' => $hash === hash('sha256', $seed['text'])];
}

/** lib.js summarizeRead over what this SDK's own store reads: latch set or not, and each pin without its xpubs. */
function readPins(FileVaultKeyStore $store, array $origins): array
{
    try {
        $out = [];
        foreach ($origins as $origin) {
            $state = $store->read($origin);
            $pins = array_values($state['vaults']);
            usort($pins, fn (array $a, array $b): int => strcmp($a['vaultId'], $b['vaultId']));
            $out[$origin] = [
                'latch' => $state['responseSignature'] !== null ? 'set' : null,
                'vaults' => array_map(function (array $pin): array {
                    $algorithms = array_keys(array_filter($pin['keys'], fn ($xpub) => $xpub !== null));
                    sort($algorithms);

                    return ['vaultId' => short($pin['vaultId']), 'type' => $pin['type'], 'status' => $pin['status'], 'algorithms' => $algorithms];
                }, $pins),
            ];
        }

        return ['ok' => true, 'origins' => $out];
    } catch (VaultKeyStoreError $error) {
        return ['ok' => false, 'error' => $error->code];
    }
}

function shortClass(object $value): string
{
    return (new \ReflectionClass($value))->getShortName();
}

$out = $argv[1] ?? null;
if ($out === null) {
    fwrite(STDERR, "usage: php run-php.php <out-dir>\n");
    exit(1);
}
$baseUrl = env('VAULTODY_BASE_URL');
$parts = parse_url($baseUrl);
$origin = ($parts['scheme'] ?? '') . '://' . ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');
if (in_array($origin, PRODUCTION_ORIGINS, true)) {
    fwrite(STDERR, "the live conformance run never targets the production API\n");
    exit(1);
}
$apiKey = env('VAULTODY_API_KEY');
$apiSecret = env('VAULTODY_API_SECRET');
$passphrase = env('VAULTODY_PASSPHRASE');
$burst = (int) (getenv('VAULTODY_CONFORMANCE_BURST') ?: '0');
$rps = getenv('VAULTODY_CONFORMANCE_RPS') ? (float) getenv('VAULTODY_CONFORMANCE_RPS') : null;
$runId = getenv('VAULTODY_CONFORMANCE_RUN_ID') ?: (string) (int) (microtime(true) * 1000);
$cases = json_decode((string) file_get_contents(__DIR__ . '/cases.json'), true, 512, JSON_THROW_ON_ERROR);
$fixture = json_decode((string) file_get_contents("$out/fixture.json"), true, 512, JSON_THROW_ON_ERROR);
$pinFile = "$out/pins-php.json";
$seed = seed();
seedPinFile($pinFile, $seed);
$http = new CountingHttpClient();
$events = [];
$logger = new CollectingLogger();

$make = function (?string $pass = null, ?float $rate = null, array $extra = []) use ($apiKey, $apiSecret, $passphrase, $baseUrl, $pinFile, $http, $rps, $logger, $origin, &$events): Vaultody {
    $rate ??= $rps;
    $options = [
        'apiKey' => $apiKey,
        'apiSecret' => $apiSecret,
        'passphrase' => $pass ?? $passphrase,
        'baseUrl' => $baseUrl,
        'vaultKeysFile' => $pinFile,
        'httpClient' => $http,
        'logger' => $logger,
        'onSecurityEvent' => function (array $event) use (&$events, $origin): void {
            $kept = array_intersect_key($event, array_flip(['type', 'vaultId', 'outcome', 'status', 'reason', 'code', 'operationId']));
            if (isset($kept['vaultId'])) {
                $kept['vaultId'] = short($kept['vaultId']);
            }
            if (($event['type'] ?? null) === 'unsigned_response_accepted') {
                // The unsigned notice must carry exactly these fields in every language.
                $fields = array_keys($event);
                sort($fields);
                $kept += ['fields' => $fields, 'originIsRun' => ($event['origin'] ?? null) === $origin];
            }
            $events[] = $kept;
        },
    ];
    if ($rate !== null) {
        $options['maxRequestsPerSecond'] = $rate;
    }
    if (isset($extra['vaultKeyStore'])) {
        unset($options['vaultKeysFile']);
    }

    return new Vaultody($extra + $options);
};
$call = fn (Vaultody $client, string $group, string $op, array $params, array $options = []) => $client->{$group}->{$op}($params, $options);

$client = $make();
$items = [];
$results = [];
$log = &$http->log;

$only = getenv('VAULTODY_CONFORMANCE_CASES') ? explode(',', (string) getenv('VAULTODY_CONFORMANCE_CASES')) : null;
foreach ($cases['cases'] as $spec) {
    if ($only !== null && !in_array($spec['id'], $only, true)) {
        continue;
    }
    $result = ['id' => $spec['id'], 'group' => $spec['group'] ?? null, 'op' => $spec['op'] ?? null, 'class' => $spec['class']];
    if ($spec['class'] === 'negative') {
        $result['check'] = $spec['check'];
        if ($spec['check'] === 'burst') {
            [$read, $m1] = resolveParams($spec['read']['params'], $fixture, $items, $runId);
            [$write, $m2] = resolveParams($spec['write']['params'], $fixture, $items, $runId);
            [$count, $m3] = resolveParams($spec['count']['params'], $fixture, $items, $runId);
            if ($burst <= 0) {
                $result['skipped'] = 'VAULTODY_CONFORMANCE_BURST is 0';
            } elseif ($m1 || $m2 || $m3) {
                $result['skipped'] = 'no ' . ($m1 ?? $m2 ?? $m3);
            } else {
                // PHP has no concurrency here: the reads go one after another, as fast as the API answers.
                usleep(1500000);
                $fast = $make(null, 1000.0);
                $before = count($log);
                $started = microtime(true);
                $reads = [];
                for ($i = 0; $i < $burst; $i++) {
                    try {
                        $call($fast, $spec['read']['group'], $spec['read']['op'], $read);
                        $reads[] = 'ok';
                    } catch (\Throwable $error) {
                        $reads[] = shortClass($error) . ':' . (errorOf($error)['code'] ?? '');
                    }
                }
                try {
                    $answer = $call($fast, $spec['write']['group'], $spec['write']['op'], $write);
                    $writeResult = ['outcome' => 'ok', 'addressChecks' => countStatuses($answer->meta->addressChecks)];
                } catch (\Throwable $error) {
                    $writeResult = ['outcome' => 'error', 'error' => errorOf($error)];
                }
                $window = array_slice($log, $before);
                $writes = array_values(array_filter($window, fn ($r) => $r['method'] === 'POST'));
                $gets = array_values(array_filter($window, fn ($r) => $r['method'] === 'GET'));
                $limits = array_values(array_unique(array_map('json_encode', array_filter(array_column($window, 'limit')))));
                usleep(1500000);
                $labelled = 0;
                foreach ($call($client, $spec['count']['group'], $spec['count']['op'], $count + ['limit' => MAX_PAGE])->autoPaging(1000) as $address) {
                    if (($address->raw['label'] ?? null) === $write['label']) {
                        $labelled++;
                    }
                }
                $result['burst'] = [
                    'size' => $burst,
                    'workers' => 1,
                    'ms' => (int) ((microtime(true) - $started) * 1000),
                    'readsOk' => count(array_filter($reads, fn ($r) => $r === 'ok')),
                    'readErrors' => array_values(array_filter($reads, fn ($r) => $r !== 'ok')),
                    'readAttempts' => count($gets),
                    'read429' => count(array_filter($gets, fn ($r) => ($r['status'] ?? null) === 429)),
                    'limits' => array_map(fn ($l) => json_decode($l, true), $limits),
                    'write' => $writeResult + [
                        'attempts' => count($writes),
                        'statuses' => array_map(fn ($r) => $r['status'] ?? $r['error'] ?? null, $writes),
                        'distinctNonces' => count(array_unique(array_column($writes, 'nonce'))),
                        'addressesWithLabel' => $labelled,
                    ],
                ];
                $result['outcome'] = 'ok';
                $result['requests'] = count($log) - $before;
            }
        } else {
            $target = match ($spec['check']) {
                'wrongPassphrase' => $make(wrongPassphrase($passphrase)),
                // The TEST-ONLY root, so the client is strict from its first answer, and a pin store of its own: the
                // run's pin file is not touched.
                'rootsOnUnsignedOrigin' => $make(null, null, ['roots' => testRoot(), 'vaultKeyStore' => new MemoryVaultKeyStore()]),
                default => $client,
            };
            $before = count($log);
            try {
                $call($target, $spec['group'], $spec['op'], $spec['params']);
                $result['outcome'] = 'ok';
            } catch (\Throwable $error) {
                $result['outcome'] = 'error';
                $result['error'] = errorOf($error);
            }
            $result['requests'] = count($log) - $before;
            $result['statuses'] = array_map(fn ($r) => $r['status'] ?? $r['error'] ?? null, array_slice($log, $before));
        }
    } else {
        $result['kind'] = $spec['kind'];
        [$params, $missing] = resolveParams($spec['params'], $fixture, $items, $runId);
        if ($missing !== null) {
            $result['skipped'] = "no $missing";
        } else {
            $expected = array_key_exists('equals', $spec) ? resolveParams(['v' => $spec['equals']], $fixture, $items, $runId)[0]['v'] : null;
            $before = count($log);
            try {
                if ($spec['kind'] === 'item') {
                    $answer = $call($client, $spec['group'], $spec['op'], $params, ['context' => CONTEXT]);
                    $result['outcome'] = 'ok';
                    $result['envelope'] = envelopeOf($answer->meta);
                    $result['typed'] = shortClass($answer);
                    if (isset($spec['field'])) {
                        $field = $spec['field'];
                        // Present in the answer (raw) and read into the model's typed property of that name.
                        $value = property_exists($answer, $field) ? $answer->{$field} : null;
                        $present = property_exists($answer, $field) && is_array($answer->raw) && ($answer->raw[$field] ?? null) !== null;
                        $result['field'] = ['name' => $field, 'present' => $present];
                        if (array_key_exists('equals', $spec)) {
                            $result['field']['equalsExpected'] = $value === $expected;
                        }
                    }
                    if ($answer->meta->addressChecks !== []) {
                        $result['addressChecks'] = countStatuses($answer->meta->addressChecks);
                    }
                    $items[$spec['id']] = $answer->raw;
                } else {
                    $paging = $spec['paging'] ?? [];
                    $first = $call($client, $spec['group'], $spec['op'], isset($paging['limit']) ? $params + ['limit' => $paging['limit']] : $params, ['context' => CONTEXT]);
                    $pages = [$first];
                    $page = $first;
                    while (count($pages) < ($paging['maxPages'] ?? 1) && $page->hasMore) {
                        $page = $page->nextPage();
                        if ($page === null) {
                            break;
                        }
                        $pages[] = $page;
                    }
                    $all = array_merge(...array_map(fn (Page $p) => $p->items, $pages));
                    $ids = array_map(fn ($item) => $item->raw[$paging['idField']] ?? null, $all);
                    $result['outcome'] = 'ok';
                    $result['envelope'] = envelopeOf($first->meta);
                    $result['typed'] = shortClass($first) . '[' . ($all === [] ? 'empty' : shortClass($all[0])) . ']';
                    $result['paging'] = [
                        'limit' => $paging['limit'] ?? null,
                        'pages' => count($pages),
                        'items' => count($all),
                        'hasMoreAfter' => $page !== null && $page->hasMore,
                        'duplicates' => count($ids) - count(array_unique($ids)),
                        'missingIds' => count(array_filter($ids, fn ($id) => !is_string($id) || $id === '')),
                    ];
                    if (!empty($spec['vaultKeys'])) {
                        // The per-vault pin results of every page fetched: {vaultId, status, outcome}.
                        $result['vaultKeys'] = [];
                        foreach ($pages as $p) {
                            foreach ($p->meta->vaultKeys as $entry) {
                                $result['vaultKeys'][] = ['vaultId' => short($entry['vaultId']), 'status' => $entry['status'], 'outcome' => $entry['outcome']];
                            }
                        }
                    }
                    $checks = array_merge(...array_map(fn (Page $p) => $p->meta->addressChecks, $pages));
                    if ($checks !== [] || !empty($spec['addressChecks'])) {
                        $result['addressChecks'] = countStatuses($checks);
                    }
                    if (!empty($paging['everyItem'])) {
                        $small = $call($client, $spec['group'], $spec['op'], $params + ['limit' => $paging['limit']], ['context' => CONTEXT]);
                        $iterator = $small->autoPaging(MAX_PAGE);
                        $iterated = [];
                        foreach ($iterator as $item) {
                            $iterated[] = $item->raw[$paging['idField']] ?? null;
                        }
                        $single = $call($client, $spec['group'], $spec['op'], $params + ['limit' => MAX_PAGE], ['context' => CONTEXT]);
                        $singleIds = array_map(fn ($item) => $item->raw[$paging['idField']] ?? null, $single->items);
                        $result['everyItem'] = [
                            'iterator' => count($iterated),
                            'singlePage' => count($singleIds),
                            'singleHasMore' => $single->hasMore,
                            'stop' => $iterator->getReturn(),
                            'equal' => $iterated === $singleIds,
                        ];
                    }
                    $items[$spec['id']] = $all === [] ? null : $all[0]->raw;
                }
            } catch (\Throwable $error) {
                $result['outcome'] = 'error';
                $result['error'] = errorOf($error);
            }
            $result['requests'] = count($log) - $before;
            $result['statuses'] = array_map(fn ($r) => $r['status'] ?? $r['error'] ?? null, array_slice($log, $before));
            $limits = array_values(array_filter(array_column(array_slice($log, $before), 'limit')));
            if ($limits !== []) {
                $result['limits'] = $limits;
            }
        }
    }
    $results[] = $result;
    $error = $result['error'] ?? null;
    fwrite(STDERR, sprintf("%s %s: %s%s\n", CLIENT, $spec['id'], isset($result['skipped']) ? "skip ({$result['skipped']})" : $result['outcome'],
        $error ? " {$error['class']} {$error['code']} {$error['status']}" : ''));
}

$file = "$out/results-php.json";
touch($file);
chmod($file, 0600);
file_put_contents($file, json_encode([
    'client' => CLIENT,
    'runtime' => 'php ' . PHP_VERSION . ' (' . strtolower(PHP_OS_FAMILY) . ')',
    'sdkVersion' => Version::SDK_VERSION,
    'apiVersion' => Version::API_VERSION,
    'origin' => $origin,
    'runId' => $runId,
    'finishedAt' => gmdate('Y-m-d\TH:i:s\Z'),
    'requests' => count($log),
    'cases' => $results,
    'pins' => pinFileFacts($pinFile, $seed) + ['read' => readPins(new FileVaultKeyStore($pinFile), [...array_keys($seed['document']['origins']), $origin])],
    'securityEvents' => $events,
    'warnings' => array_keys($logger->warnings),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
