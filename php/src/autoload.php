<?php

declare(strict_types=1);

// The PSR-4 autoloader composer.json declares, for running from a checkout without composer (the tests
// and bin/surface.php). An installed package uses composer's own.
spl_autoload_register(static function (string $class): void {
    $prefix = 'Vaultody\\Sdk\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
