<?php

declare(strict_types=1);

// Every shared vector set is there and readable from PHP, with the big integers and non-ASCII text PHP must
// decode the same way as Node and Python. Each set is run by its own *Test.php file.

$vectors = dirname(__DIR__, 2) . '/test-vectors';

return [
    'every vector set decodes' => static function () use ($vectors): void {
        $files = glob($vectors . '/*.json') ?: [];
        check(count($files) >= 15, 'expected the 15 vector sets, found ' . count($files));
        foreach ($files as $file) {
            $data = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            check(is_array($data), basename($file) . ' is not a JSON object');
        }
    },
];
