<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/** A list that can't be paged through safely. $code is missing_cursor or pagination_loop. */
final class PaginationError extends VaultodyError
{
    /** @var string */
    public $code;

    public function __construct(string $code, string $message)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
