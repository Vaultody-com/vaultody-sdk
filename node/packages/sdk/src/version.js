'use strict';

/**
 * The API version this SDK release is written for. It is sent, and signed, as x-api-version on every
 * request, so the API answers in exactly the shape the SDK's methods and types describe, whatever default
 * version the API key has. It is info.version of the published OpenAPI document the release was checked
 * against (contract/openapi.json); scripts/coverage.mjs fails when the two differ.
 */
const API_VERSION = '2026-03-20';

/** This package's version: one version number for the SDK in every language (the VERSION file). */
const SDK_VERSION = require('../package.json').version;

module.exports = {
    API_VERSION,
    SDK_VERSION,
};
