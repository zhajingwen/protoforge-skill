// Signer for POST /api/search on the demo site (route R2: extracted JS run in Node).
// In a real target this file is the function extracted with scripts(action="save"),
// trimmed to its inputs and outputs. Contract: sign(view) -> { x_sign }.
'use strict';
const crypto = require('crypto');

const SALT = process.env.DEMO_SIGN_KEY || 'pf-demo-secret';

function canonical(body) {
  const out = {};
  for (const k of Object.keys(body).sort()) out[k] = body[k];
  return JSON.stringify(out);
}

exports.sign = function sign(view) {
  const digest = crypto.createHash('sha256').update(canonical(view.body) + '|' + SALT).digest('hex');
  return { x_sign: digest.slice(0, 32) };
};
