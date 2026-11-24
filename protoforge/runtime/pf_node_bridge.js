#!/usr/bin/env node
// ProtoForge node signer bridge.
// Usage: node pf_node_bridge.js <signer-module.js> <export-name>
// Reads the signer view (JSON) from stdin, calls the export, writes a JSON object to stdout.
// The export may return a value or a Promise. Anything written to stdout by the
// signer module itself would corrupt the result, so console.log is redirected to stderr.
'use strict';
const path = require('path');

console.log = (...args) => process.stderr.write(args.join(' ') + '\n');

const [, , modulePath, exportName = 'sign'] = process.argv;
if (!modulePath) {
  process.stderr.write('usage: pf_node_bridge.js <module> [export]\n');
  process.exit(2);
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    const mod = require(path.resolve(modulePath));
    const fn = typeof mod === 'function' && exportName === 'default' ? mod : mod[exportName];
    if (typeof fn !== 'function') throw new Error(`export ${exportName} is not a function`);
    const result = await fn(JSON.parse(input));
    if (result === null || typeof result !== 'object' || Array.isArray(result)) {
      throw new Error('signer must return a plain object of outputs');
    }
    process.stdout.write(JSON.stringify(result));
  } catch (err) {
    process.stderr.write(String(err && err.stack ? err.stack : err));
    process.exit(1);
  }
});
