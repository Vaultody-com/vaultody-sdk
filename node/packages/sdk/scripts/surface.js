#!/usr/bin/env node
'use strict';

// Prints this SDK's surface as JSON for scripts/coverage.mjs: the methods of a real client, found by walking
// it, and the operation table. The client is built with throwaway credentials and an in-memory pin store; it
// makes no request.

const { describeSurface } = require('../src/surface');
const { Vaultody } = require('../src/client');
const { MemoryVaultKeyStore } = require('../src/vaultKeyStore');

const client = new Vaultody({ apiKey: 'surface', apiSecret: 'c3VyZmFjZQ==', passphrase: 'surface', vaultKeyStore: new MemoryVaultKeyStore() });

process.stdout.write(`${JSON.stringify(describeSurface(client), null, 2)}\n`);
