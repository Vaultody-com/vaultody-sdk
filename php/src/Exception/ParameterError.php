<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * Arguments of a call that can't be turned into a request. $code says why; $param, when set, names the field
 * (nested ones as recipients[0].amount), never its value.
 */
final class ParameterError extends VaultodyError
{
    /** @var string missing_param, unknown_param, invalid_param, missing_path_param, invalid_path_param, invalid_query_param, body_too_large, ... */
    public $code;

    public function __construct(string $code, string $message, public readonly ?string $param = null)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
