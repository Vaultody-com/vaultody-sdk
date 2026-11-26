<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/** A webhook delivery whose X-Signature checked out, but whose body is not a JSON object with data.event. */
final class WebhookPayloadError extends VaultodyError
{
}
