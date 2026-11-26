<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * The API version this SDK release is written for, and the SDK's own version.
 *
 * API_VERSION is sent, and signed, as x-api-version on every request, so the API answers in exactly the
 * shape the SDK describes, whatever default version the API key has. It is info.version of the published
 * OpenAPI document the release was checked against (contract/openapi.json); scripts/coverage.mjs fails
 * when the two differ. SDK_VERSION is the one version number of the SDK in every language (VERSION).
 */
final class Version
{
    public const API_VERSION = '2026-03-20';

    public const SDK_VERSION = '0.1.0';
}
