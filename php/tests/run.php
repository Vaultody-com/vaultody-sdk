<?php

declare(strict_types=1);

// A minimal test runner, so the tests need nothing but PHP: every tests/*Test.php returns a list of
// name => closure; a closure passes when it returns without throwing.

require __DIR__ . '/../src/autoload.php';
require __DIR__ . '/support/vectors.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$failed = 0;
$passed = 0;
foreach (glob(__DIR__ . '/*Test.php') ?: [] as $file) {
    /** @var array<string, callable(): void> $tests */
    $tests = require $file;
    foreach ($tests as $name => $test) {
        try {
            $test();
            $passed++;
            echo "ok - ", basename($file, '.php'), ": ", $name, "\n";
        } catch (Throwable $error) {
            $failed++;
            echo "not ok - ", basename($file, '.php'), ": ", $name, "\n    ", get_class($error), ": ", $error->getMessage(), "\n";
        }
    }
}

echo "\n", $passed, " passed, ", $failed, " failed (PHP ", PHP_VERSION, ")\n";
exit($failed === 0 && $passed > 0 ? 0 : 1);
