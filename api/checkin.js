// api/checkin.js
// This is the "judge" — it checks every tap and logs valid ones.

const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const TAG_KEY = Buffer.from(process.env.TAG_AES_KEY_HEX, 'hex');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function decryptPicc(piccHex) {
  try {
    const piccBytes = Buffer.from(piccHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-128-cbc', TAG_KEY, Buffer.alloc(16, 0));
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(piccBytes), decipher.final()]);
    const uid = plain.subarray(1, 8).toString('hex').toUpperCase();
    const counter = plain[8] | (plain[9] << 8) | (plain[10] << 16);
    return { uid, counter, plain };
  } catch {
    return null;
  }
}

function aesEcbEncryptBlock(key, block) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function shl1(b) {
  const out = Buffer.alloc(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    const v = (b[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (v >> 8) & 1;
  }
  return out;
}

function xor(a, b) {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

function cmac(key, data) {
  const L = aesEcbEncryptBlock(key, Buffer.alloc(16, 0));
  let K1 = shl1(L);
  if (L[0] & 0x80) K1[15] ^= 0x87;
  let K2 = shl1(K1);
  if (K1[0] & 0x80) K2[15] ^= 0x87;

  const n = Math.max(1, Math.ceil(data.length / 16));
  const complete = data.length > 0 && data.length % 16 === 0;
  const blocks = [];
  for (let i = 0; i < n - 1; i++) blocks.push(data.subarray(i * 16, (i + 1) * 16));

  let lastBlock;
  if (complete) {
    lastBlock = xor(data.subarray((n - 1) * 16), K1);
  } else {
    const rem = data.subarray((n - 1) * 16);
    const padded = Buffer.alloc(16, 0);
    rem.copy(padded);
    padded[rem.length] = 0x80;
    lastBlock = xor(padded, K2);
  }

  let X = Buffer.alloc(16, 0);
  for (const blk of blocks) X = aesEcbEncryptBlock(key, xor(X, blk));
  return aesEcbEncryptBlock(key, xor(X, lastBlock));
}

module.exports = async (req, res) => {
  const { picc_data, cmac: cmacParam, email } = req.query;

  if (!picc_data || !cmacParam) return html(res, 'Invalid Scan', 'Missing tag data.', '#d9534f');

  const decrypted = decryptPicc(picc_data);
  if (!decrypted) return html(res, 'Verification Failed', 'Could not read tag.', '#d9534f');

  const expected = cmac(TAG_KEY, decrypted.plain).subarray(0, 8).toString('hex').toUpperCase();
  if (expected !== cmacParam.toUpperCase()) {
    return html(res, 'Fraud Alert', 'This does not match a real tag.', '#d9534f');
  }

  const { data: tagRow } = await supabase.from('tags').select('*').eq('uid', decrypted.uid).single();
  if (!tagRow) return html(res, 'Unknown Tag', 'This tag is not registered.', '#d9534f');
  if (decrypted.counter <= tagRow.last_counter) {
    return html(res, 'Already Used', 'This link has already been used.', '#d9534f');
  }

  if (!email) return html(res, 'Login Required', 'Please sign in with your Google account first.', '#f0ad4e');

  const { data: rosterRow } = await supabase.from('roster').select('*').eq('email', email).single();
  if (!rosterRow) return html(res, 'Not on Roster', `${email} is not recognized.`, '#f0ad4e');

  await supabase.from('tags').update({ last_counter: decrypted.counter }).eq('uid', decrypted.uid);
  await supabase.from('attendance_log').insert({
    email, uid: decrypted.uid, tap_counter: decrypted.counter, status: 'verified',
  });

  return html(res, 'Attendance Confirmed', `Welcome, ${rosterRow.full_name || email}!`, '#5cb85c');
};

function html(res, title, message, color) {
  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(`<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body{font-family:-apple-system,sans-serif;text-align:center;padding:40px 20px;background:#f9f9f9}
  .card{max-width:400px;margin:auto;background:#fff;padding:30px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.08)}
  h2{color:${color}}</style></head><body><div class="card"><h2>${title}</h2><p>${message}</p></div></body></html>`);
}
