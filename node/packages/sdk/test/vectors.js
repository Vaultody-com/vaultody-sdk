'use strict';

// Loads a shared vector set from test-vectors/. node --test also loads this file, finds no tests in it
// and moves on.

const path = require('node:path');

const VECTORS_DIR = path.resolve(__dirname, '..', '..', '..', '..', 'test-vectors');

const load = name => require(path.join(VECTORS_DIR, name));

module.exports = { VECTORS_DIR, load };
