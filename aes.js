// NIU KQi tuning tool - self-contained crypto and frame core (no dependencies).
// Copyright (c) 2026 Laufbursche42
//
// Contains: AES-128-ECB (fixed Rijndael S-box, no p/q scheme), CRC16 (poly 0xA1E8), the additive
// frame checksum, the block-write frame (0122 + counter + AES16 + checksum) and the handshake
// building blocks firstKey/verifyPwd1/verifyPwd2.
//
// All protocol knowledge is from static analysis of the app com.niu.manager 5.12.2 (jadx plus
// apktool smali), documented in the project's work/notes. Not verified on a vehicle.
//
// The file runs in Node (for the self-tests, via module.exports) and in the browser (window.NIU).

'use strict';

// --------------------------- hex helpers ---------------------------

function hexToBytes(h) {
  h = String(h || '').replace(/[^0-9a-fA-F]/g, '');
  if (h.length % 2 !== 0) h = h.slice(0, h.length - 1);
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(b) { let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
function hexSpaced(b) { const a = []; for (let i = 0; i < b.length; i++) a.push(b[i].toString(16).padStart(2, '0').toUpperCase()); return a.join(' '); }
function toHex4(v) { return ((v & 0xFFFF) >>> 0).toString(16).padStart(4, '0'); }

// --------------------------- AES-128-ECB ---------------------------
// Fixed Rijndael S-box (FIPS-197 Figure 7), one clean hex literal per row. The inverse S-box is
// derived from it (INV[SBOX[i]] = i) - that is not a p/q generation, only the inversion of the fixed
// table. The FIPS-197 self-test (selfTestAES) proves the table is correct.
const SBOX = hexToBytes(
  '637c777bf26b6fc53001672bfed7ab76' +   // 00-0f
  'ca82c97dfa5947f0add4a2af9ca472c0' +   // 10-1f
  'b7fd9326363ff7cc34a5e5f171d83115' +   // 20-2f
  '04c723c31896059a071280e2eb27b275' +   // 30-3f
  '09832c1a1b6e5aa0523bd6b329e32f84' +   // 40-4f
  '53d100ed20fcb15b6acbbe394a4c58cf' +   // 50-5f
  'd0efaafb434d338545f9027f503c9fa8' +   // 60-6f
  '51a3408f929d38f5bcb6da2110fff3d2' +   // 70-7f
  'cd0c13ec5f974417c4a77e3d645d1973' +   // 80-8f
  '60814fdc222a908846eeb814de5e0bdb' +   // 90-9f
  'e0323a0a4906245cc2d3ac629195e479' +   // a0-af
  'e7c8376d8dd54ea96c56f4ea657aae08' +   // b0-bf
  'ba78252e1ca6b4c6e8dd741f4bbd8b8a' +   // c0-cf
  '703eb5664803f60e613557b986c11d9e' +   // d0-df
  'e1f8981169d98e949b1e87e9ce5528df' +   // e0-ef
  '8ca1890dbfe6426841992d0fb054bb16'     // f0-ff
);
const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1;
  }
  return p & 0xff;
}
function aesKeyExpansion(key) {
  const w = new Array(44);
  for (let i = 0; i < 4; i++) w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  let rcon = 1;
  for (let i = 4; i < 44; i++) {
    let tmp = w[i - 1].slice();
    if (i % 4 === 0) { tmp = [tmp[1], tmp[2], tmp[3], tmp[0]].map(x => SBOX[x]); tmp[0] ^= rcon; rcon = gmul(rcon, 2); }
    w[i] = w[i - 4].map((x, j) => x ^ tmp[j]);
  }
  return w;
}
function aesEncryptBlock(inp, w) {
  const s = new Uint8Array(16); for (let i = 0; i < 16; i++) s[i] = inp[i];
  const ark = r => { for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) s[c * 4 + row] ^= w[r * 4 + c][row]; };
  const sub = () => { for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]; };
  const shift = () => { const o = s.slice(); for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) s[c * 4 + row] = o[((c + row) % 4) * 4 + row]; };
  const mix = () => { for (let c = 0; c < 4; c++) { const s0 = s[c * 4], s1 = s[c * 4 + 1], s2 = s[c * 4 + 2], s3 = s[c * 4 + 3];
    s[c * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3; s[c * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
    s[c * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3); s[c * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2); } };
  ark(0);
  for (let r = 1; r < 10; r++) { sub(); shift(); mix(); ark(r); }
  sub(); shift(); ark(10);
  return s;
}
function aesDecryptBlock(inp, w) {
  const s = new Uint8Array(16); for (let i = 0; i < 16; i++) s[i] = inp[i];
  const ark = r => { for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) s[c * 4 + row] ^= w[r * 4 + c][row]; };
  const invsub = () => { for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]]; };
  const invshift = () => { const o = s.slice(); for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) s[c * 4 + row] = o[((c - row + 4) % 4) * 4 + row]; };
  const invmix = () => { for (let c = 0; c < 4; c++) { const s0 = s[c * 4], s1 = s[c * 4 + 1], s2 = s[c * 4 + 2], s3 = s[c * 4 + 3];
    s[c * 4] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9); s[c * 4 + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
    s[c * 4 + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11); s[c * 4 + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14); } };
  ark(10);
  for (let r = 9; r >= 1; r--) { invshift(); invsub(); ark(r); invmix(); }
  invshift(); invsub(); ark(0);
  return s;
}
function aesEcbEncrypt(data, key) {
  const w = aesKeyExpansion(key);
  const pad = (16 - (data.length % 16)) % 16;
  const buf = new Uint8Array(data.length + pad); buf.set(data);   // zero padding, like the app
  const out = new Uint8Array(buf.length);
  for (let off = 0; off < buf.length; off += 16) out.set(aesEncryptBlock(buf.subarray(off, off + 16), w), off);
  return out;
}
function aesEcbDecrypt(data, key) {
  const w = aesKeyExpansion(key);
  const out = new Uint8Array(data.length - (data.length % 16));
  for (let off = 0; off + 16 <= data.length; off += 16) out.set(aesDecryptBlock(data.subarray(off, off + 16), w), off);
  return out;
}

// --------------------------- CRC16 and checksum ---------------------------
// CRC16 in the plaintext block of the handshake frames: init 0xFFFF, polynomial 0xA1E8, MSB-first,
// no final XOR (from krypto-pairing.md: k0/a.f(0xA1E8, bytes), seed 0xFFFF). Not cross-checked on a
// device.
function crc16(bytes) {
  let crc = 0xFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= (bytes[i] << 8); crc &= 0xFFFF;
    for (let b = 0; b < 8; b++) {
      if (crc & 0x8000) crc = ((crc << 1) ^ 0xA1E8) & 0xFFFF;
      else crc = (crc << 1) & 0xFFFF;
    }
  }
  return crc & 0xFFFF;
}
// Additive 1-byte checksum over all frame bytes, mod 256 (from n0.L/n0.M).
function checksumByte(bytes) { let s = 0; for (let i = 0; i < bytes.length; i++) s = (s + bytes[i]) & 0xff; return s; }
function checksumHex(bytes) { return checksumByte(bytes).toString(16).padStart(2, '0'); }

// --------------------------- key from secret ---------------------------
// secret/aesSecret are either 16 ASCII chars (used directly as UTF-8 bytes) or 32 hex chars
// (from krypto-pairing.md: length 16 -> UTF-8 bytes, length 32 -> hex). Anything else is invalid.
function keyBytesFromSecret(str) {
  const s = String(str || '').trim();
  if (/^[0-9a-fA-F]{32}$/.test(s)) return hexToBytes(s);
  if (s.length === 16) { const a = new Uint8Array(16); for (let i = 0; i < 16; i++) a[i] = s.charCodeAt(i) & 0xff; return a; }
  throw new Error('secret must be 16 ASCII chars or 32 hex chars');
}
// MAC as 6 bytes: "AA:BB:.." or "AABB.." (12 hex). Otherwise 000000000000.
function macBytes(mac) {
  const h = String(mac || '').replace(/[^0-9a-fA-F]/g, '');
  if (h.length === 12) return hexToBytes(h);
  return new Uint8Array(6);
}

// --------------------------- command frame (block-write, Action 1) ---------------------------
// fields = [[codeHex(6), value(int)], ...]. Data area = code + U16(value BE), concatenated, right
// padded with "0" to a multiple of 16 bytes, each block AES-ECB(sessionKey). Frame =
// "0122" + rest-counter(1 byte) + AES16 + checksum. From protokoll-final.md section 1.
function buildDataAreaHex(fields) {
  let hex = '';
  for (const [code, value] of fields) hex += String(code).toLowerCase() + toHex4(value);
  const blockChars = 32;                                   // 16 bytes per block
  const need = Math.max(blockChars, Math.ceil(hex.length / blockChars) * blockChars);
  while (hex.length < need) hex += '0';                    // pad right with "0" characters
  return hex;
}
function buildBlockFrame(fields, sessionKeyBytes) {
  const plainHex = buildDataAreaHex(fields);
  const plainBytes = hexToBytes(plainHex);
  // Every command used here fits in ONE 16-byte block. A multi-block frame would be "0122" (first) /
  // "0102" (following) with its own checksum per block - not needed here, we build the single block.
  const cipher = aesEcbEncrypt(plainBytes.subarray(0, 16), sessionKeyBytes);   // 16 bytes
  const head = hexToBytes('0122');                          // header, first (and only) block
  const body = new Uint8Array(head.length + 1 + cipher.length);
  body.set(head, 0); body[head.length] = 0x00; body.set(cipher, head.length + 1);   // rest-counter 00
  const cs = checksumByte(body);
  const frame = new Uint8Array(body.length + 1);
  frame.set(body, 0); frame[body.length] = cs;
  return { frame, plainHex, cipherHex: bytesToHex(cipher) };
}

// --------------------------- handshake ---------------------------
// firstKey = AES-ECB( rand4 + BE4(unixtime_s + 604800) + mac6 + crc16(block[0..13]), key=secret ).
// From protokoll-final.md 2.1 / krypto-pairing.md 3. 604800 = 7 days (0x93A80).
function buildFirstKey(secretBytes, macBytesArr, nowSec, rand4) {
  const block = new Uint8Array(16);
  block.set(rand4.subarray(0, 4), 0);
  const t = (Number(nowSec) + 604800) >>> 0;
  block[4] = (t >>> 24) & 0xff; block[5] = (t >>> 16) & 0xff; block[6] = (t >>> 8) & 0xff; block[7] = t & 0xff;
  block.set(macBytesArr.subarray(0, 6), 8);
  const crc = crc16(block.subarray(0, 14));
  block[14] = (crc >>> 8) & 0xff; block[15] = crc & 0xff;
  const cipher = aesEcbEncrypt(block, secretBytes);
  return { firstKeyHex: bytesToHex(cipher), random1Hex: bytesToHex(rand4.subarray(0, 4)), blockHex: bytesToHex(block) };
}
// verifyPwd1 = "013401" + firstKey(32 hex) + checksum, sent UNENCRYPTED.
function buildVerifyPwd1(firstKeyHex) {
  const body = hexToBytes('013401' + firstKeyHex);
  const cs = checksumHex(body);
  return hexToBytes('013401' + firstKeyHex + cs);
}
// verifyPwd2 = "011400" + AES16( resp1[8:16) + random2(8 hex) + "000000000000" + crc16, sessionKey )
//            + checksum. resp1[8:16) = bytes 4..7 of the verifyPwd1 answer.
function buildVerifyPwd2(resp1Hex, random2Hex, sessionKeyBytes) {
  const part1 = String(resp1Hex).replace(/[^0-9a-fA-F]/g, '').substr(8, 8);   // 4 bytes
  const blockHex = (part1 + random2Hex + '000000000000').padEnd(28, '0').substr(0, 28);
  const full = new Uint8Array(16); full.set(hexToBytes(blockHex).subarray(0, 14), 0);   // 14 bytes + CRC
  const crc = crc16(full.subarray(0, 14));
  full[14] = (crc >>> 8) & 0xff; full[15] = crc & 0xff;
  const cipher = aesEcbEncrypt(full, sessionKeyBytes);
  const body = new Uint8Array(3 + 16);
  body.set(hexToBytes('011400'), 0); body.set(cipher, 3);
  const cs = checksumByte(body);
  const frame = new Uint8Array(20); frame.set(body, 0); frame[19] = cs;
  return { frame, blockHex: bytesToHex(full), cipherHex: bytesToHex(cipher) };
}

// --------------------------- self-tests ---------------------------
function selfTestAES() {
  const k = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const p = hexToBytes('00112233445566778899aabbccddeeff');
  const w = aesKeyExpansion(k);
  const ct = bytesToHex(aesEncryptBlock(p, w));
  const encOk = ct === '69c4e0d86a7b0430d8cdb78070b4c55a';
  const back = bytesToHex(aesDecryptBlock(hexToBytes('69c4e0d86a7b0430d8cdb78070b4c55a'), w));
  const decOk = back === '00112233445566778899aabbccddeeff';
  return { ok: encOk && decOk, ct, encOk, decOk };
}
// Builds the speed frame for 25.0 km/h (prefix 10) with a test session key and checks that the data
// area, after AES decryption, is 210016000A21003C00FA000000000000 again.
function selfTestFrame(testKeyHex) {
  const key = hexToBytes(testKeyHex || '00112233445566778899aabbccddeeff');
  const built = buildBlockFrame([['210016', 10], ['21003C', 250]], key);
  const wantPlain = '210016000a21003c00fa000000000000';
  const cipher = hexToBytes(built.cipherHex);
  const back = bytesToHex(aesEcbDecrypt(cipher, key));
  return { ok: built.plainHex === wantPlain && back === wantPlain, plainHex: built.plainHex, back, frame: bytesToHex(built.frame) };
}

const NIU = {
  hexToBytes, bytesToHex, hexSpaced, toHex4,
  SBOX, aesEcbEncrypt, aesEcbDecrypt, aesEncryptBlock, aesDecryptBlock, aesKeyExpansion,
  crc16, checksumByte, checksumHex,
  keyBytesFromSecret, macBytes,
  buildDataAreaHex, buildBlockFrame,
  buildFirstKey, buildVerifyPwd1, buildVerifyPwd2,
  selfTestAES, selfTestFrame
};

if (typeof module !== 'undefined' && module.exports) module.exports = NIU;
if (typeof window !== 'undefined') window.NIU = NIU;
