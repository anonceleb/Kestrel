/**
 * Browser shim for the exact subset of `node:crypto` the CFP sources use.
 *
 * Pure JS, synchronous, zero dependencies — no WebCrypto (crypto.subtle is
 * async and missing ChaCha20-Poly1305/BLAKE2b anyway), so the transformed
 * modules keep their synchronous call shape and run anywhere, including
 * file://.
 *
 * This file is NOT part of the donated artifact. It exists so the browser
 * demo can execute the real repo sources unmodified. It is verified for
 * interoperability against node:crypto itself every time `npm run build:web`
 * runs — see tools/web-build/build.ts (selftest section): digests compared
 * byte-for-byte, AEAD round-tripped in both directions, Ed25519 signatures
 * cross-verified both ways, DER exports compared. The build refuses to emit
 * if any check fails.
 *
 * Implemented against: FIPS 180-4 (SHA-256/512), RFC 2104 (HMAC), RFC 5869
 * (HKDF), RFC 8439 (ChaCha20-Poly1305), RFC 8032 (Ed25519), RFC 7693
 * (BLAKE2b).
 */

/* ------------------------------------------------------------- Buffer-lite */

const TD = new TextDecoder();
const TE = new TextEncoder();

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function bytesToBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | (b === undefined ? 0 : b >> 4)];
    out += b === undefined ? "=" : B64[((b & 15) << 2) | (c === undefined ? 0 : c >> 6)];
    out += c === undefined ? "=" : B64[c & 63];
  }
  return out;
}

function base64ToBytes(str) {
  const clean = str.replace(/-/g, "+").replace(/_/g, "/").replace(/[^A-Za-z0-9+/]/g, "");
  const out = [];
  for (let i = 0; i < clean.length; i += 4) {
    const n = [0, 1, 2, 3].map((j) => {
      const ch = clean[i + j];
      return ch === undefined ? -1 : B64.indexOf(ch);
    });
    out.push((n[0] << 2) | (n[1] >> 4));
    if (n[2] >= 0) out.push(((n[1] & 15) << 4) | (n[2] >> 2));
    if (n[3] >= 0) out.push(((n[2] & 3) << 6) | n[3]);
  }
  return new Uint8Array(out);
}

export class Buffer extends Uint8Array {
  static from(value, encOrOffset) {
    if (typeof value === "string") {
      const enc = encOrOffset ?? "utf8";
      if (enc === "utf8" || enc === "utf-8") return new Buffer(TE.encode(value));
      if (enc === "hex") {
        const out = new Buffer(value.length >> 1);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
        return out;
      }
      if (enc === "base64" || enc === "base64url") return new Buffer(base64ToBytes(value));
      throw new Error(`Buffer.from: unsupported encoding ${enc}`);
    }
    if (value instanceof ArrayBuffer) return new Buffer(new Uint8Array(value));
    if (ArrayBuffer.isView(value)) {
      return new Buffer(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (Array.isArray(value)) return new Buffer(Uint8Array.from(value));
    throw new Error("Buffer.from: unsupported input");
  }

  static alloc(n) {
    return new Buffer(n);
  }

  static concat(list) {
    const total = list.reduce((s, b) => s + b.length, 0);
    const out = new Buffer(total);
    let off = 0;
    for (const b of list) {
      out.set(b, off);
      off += b.length;
    }
    return out;
  }

  static isBuffer(v) {
    return v instanceof Buffer;
  }

  toString(enc = "utf8") {
    if (enc === "utf8" || enc === "utf-8") return TD.decode(this);
    if (enc === "hex") return [...this].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (enc === "base64") return bytesToBase64(this);
    if (enc === "base64url") {
      return bytesToBase64(this).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    throw new Error(`Buffer.toString: unsupported encoding ${enc}`);
  }

  writeUInt16BE(value, offset) {
    this[offset] = (value >> 8) & 0xff;
    this[offset + 1] = value & 0xff;
    return offset + 2;
  }

  writeUInt32BE(value, offset) {
    this[offset] = (value >>> 24) & 0xff;
    this[offset + 1] = (value >>> 16) & 0xff;
    this[offset + 2] = (value >>> 8) & 0xff;
    this[offset + 3] = value & 0xff;
    return offset + 4;
  }

  readUInt8(offset) {
    return this[offset];
  }

  readUInt16BE(offset) {
    return (this[offset] << 8) | this[offset + 1];
  }

  readUInt32BE(offset) {
    return ((this[offset] << 24) | (this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3]) >>> 0;
  }

  equals(other) {
    if (this.length !== other.length) return false;
    let d = 0;
    for (let i = 0; i < this.length; i++) d |= this[i] ^ other[i];
    return d === 0;
  }
}

function toBytes(data, enc) {
  if (typeof data === "string") return Buffer.from(data, enc ?? "utf8");
  return Buffer.from(data);
}

/* ------------------------------------------------------------------ random */

export function randomBytes(n) {
  const b = new Buffer(n);
  crypto.getRandomValues(b);
  return b;
}

export function randomUUID() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) throw new RangeError("Input buffers must have the same byte length");
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/* ----------------------------------------------------------------- SHA-256 */

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(bytes) {
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const len = bytes.length;
  const bitLen = len * 8;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Buffer(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
  return out;
}

/* ----------------------------------------------------------------- SHA-512 */

const K512 = [
  "428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
  "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
  "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
  "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
  "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
  "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
  "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
  "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
  "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
  "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
  "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
  "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
  "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
  "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
  "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
  "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
  "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
  "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
  "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
  "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817",
].map((h) => BigInt("0x" + h));

const M64 = (1n << 64n) - 1n;
const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

function sha512(bytes) {
  const H = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
  ];
  const len = bytes.length;
  const padded = new Uint8Array((((len + 16) >> 7) + 1) << 7);
  padded.set(bytes);
  padded[len] = 0x80;
  // 128-bit length; message sizes here fit comfortably in Number
  const bitLen = BigInt(len) * 8n;
  const dv = new DataView(padded.buffer);
  dv.setBigUint64(padded.length - 16, bitLen >> 64n);
  dv.setBigUint64(padded.length - 8, bitLen & M64);
  const w = new Array(80);
  for (let off = 0; off < padded.length; off += 128) {
    for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(off + i * 8);
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
      const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ (~e & g & M64);
      const t1 = (h + S1 + ch + K512[i] + w[i]) & M64;
      const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & M64;
      h = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
    }
    H[0] = (H[0] + a) & M64; H[1] = (H[1] + b) & M64; H[2] = (H[2] + c) & M64; H[3] = (H[3] + d) & M64;
    H[4] = (H[4] + e) & M64; H[5] = (H[5] + f) & M64; H[6] = (H[6] + g) & M64; H[7] = (H[7] + h) & M64;
  }
  const out = new Buffer(64);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, H[i]);
  return out;
}

/* ------------------------------------------------------------- BLAKE2b-512 */

const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function blake2b512(bytes) {
  const h = BLAKE2B_IV.slice();
  h[0] ^= 0x01010000n ^ 64n; // digest length 64, no key
  const blocks = Math.max(1, Math.ceil(bytes.length / 128));
  const m = new Array(16);

  const G = (v, a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & M64;
    v[d] = rotr64(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & M64;
    v[b] = rotr64(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & M64;
    v[d] = rotr64(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & M64;
    v[b] = rotr64(v[b] ^ v[c], 63n);
  };

  for (let bi = 0; bi < blocks; bi++) {
    const isLast = bi === blocks - 1;
    const block = new Uint8Array(128);
    block.set(bytes.subarray(bi * 128, bi * 128 + 128));
    const dv = new DataView(block.buffer);
    for (let i = 0; i < 16; i++) m[i] = dv.getBigUint64(i * 8, true);
    const t = BigInt(isLast ? bytes.length : (bi + 1) * 128);
    const v = h.concat(BLAKE2B_IV.slice());
    v[12] ^= t & M64;
    v[13] ^= 0n; // high word of t — inputs here never exceed 2^64 bytes
    if (isLast) v[14] ^= M64;
    for (let r = 0; r < 12; r++) {
      const s = BLAKE2B_SIGMA[r];
      G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = new Buffer(64);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, h[i], true);
  return out;
}

/* ------------------------------------------------------- createHash / HMAC */

const HASHES = {
  sha256: { fn: sha256, block: 64 },
  sha512: { fn: sha512, block: 128 },
  blake2b512: { fn: blake2b512, block: 128 },
};

export function createHash(name) {
  const spec = HASHES[name];
  if (!spec) throw new Error(`createHash: unsupported algorithm ${name}`);
  const chunks = [];
  const api = {
    update(data, enc) {
      chunks.push(toBytes(data, enc));
      return api;
    },
    digest(enc) {
      const d = spec.fn(Buffer.concat(chunks));
      return enc ? d.toString(enc) : d;
    },
  };
  return api;
}

function hmac(name, key, msg) {
  const { fn, block } = HASHES[name];
  let k = toBytes(key);
  if (k.length > block) k = fn(k);
  const ipad = new Uint8Array(block).fill(0x36);
  const opad = new Uint8Array(block).fill(0x5c);
  for (let i = 0; i < k.length; i++) {
    ipad[i] ^= k[i];
    opad[i] ^= k[i];
  }
  return fn(Buffer.concat([Buffer.from(opad), fn(Buffer.concat([Buffer.from(ipad), msg]))]));
}

export function createHmac(name, key) {
  if (!HASHES[name]) throw new Error(`createHmac: unsupported algorithm ${name}`);
  const chunks = [];
  const api = {
    update(data, enc) {
      chunks.push(toBytes(data, enc));
      return api;
    },
    digest(enc) {
      const d = hmac(name, key, Buffer.concat(chunks));
      return enc ? d.toString(enc) : d;
    },
  };
  return api;
}

/* -------------------------------------------------------------------- HKDF */

export function hkdfSync(digest, ikm, salt, info, keylen) {
  if (!HASHES[digest]) throw new Error(`hkdfSync: unsupported digest ${digest}`);
  const hashLen = HASHES[digest].fn(new Uint8Array(0)).length;
  const saltB = toBytes(salt);
  const prk = hmac(digest, saltB.length ? saltB : new Uint8Array(hashLen), toBytes(ikm));
  const infoB = toBytes(info);
  let t = new Buffer(0);
  const okm = [];
  for (let i = 1; okm.reduce((s, b) => s + b.length, 0) < keylen; i++) {
    t = hmac(digest, prk, Buffer.concat([t, infoB, Buffer.from([i])]));
    okm.push(t);
  }
  // Node returns an ArrayBuffer here; callers wrap it in Buffer.from().
  return Buffer.concat(okm).slice(0, keylen).buffer.slice(0, keylen);
}

/* -------------------------------------------------- ChaCha20-Poly1305 AEAD */

const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

function chachaBlock(key32, counter, nonce12) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  const kdv = new DataView(key32.buffer, key32.byteOffset);
  for (let i = 0; i < 8; i++) s[4 + i] = kdv.getUint32(i * 4, true);
  s[12] = counter;
  const ndv = new DataView(nonce12.buffer, nonce12.byteOffset);
  for (let i = 0; i < 3; i++) s[13 + i] = ndv.getUint32(i * 4, true);
  const w = Uint32Array.from(s);
  const qr = (a, b, c, d) => {
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 16);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 12);
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 8);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) odv.setUint32(i * 4, (w[i] + s[i]) >>> 0, true);
  return out;
}

function chacha20Xor(key, nonce, data, initialCounter) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const ks = chachaBlock(key, initialCounter + (i >> 6), nonce);
    for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}

function poly1305(key32, msg) {
  const le = (bytes) => {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  };
  const P = (1n << 130n) - 5n;
  const r = le(key32.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = le(key32.subarray(16, 32));
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const block = msg.subarray(i, i + 16);
    const n = le(block) | (1n << BigInt(block.length * 8));
    acc = ((acc + n) * r) % P;
  }
  acc = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return out;
}

function pad16(len) {
  return new Uint8Array((16 - (len % 16)) % 16);
}

function le64(n) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

function aeadTag(key, nonce, aad, ct) {
  const polyKey = chachaBlock(key, 0, nonce).subarray(0, 32);
  const macData = Buffer.concat(
    [aad, pad16(aad.length), ct, pad16(ct.length), le64(aad.length), le64(ct.length)].map((b) => Buffer.from(b)),
  );
  return poly1305(polyKey, macData);
}

export function createCipheriv(alg, key, nonce, _opts) {
  if (alg !== "chacha20-poly1305") throw new Error(`createCipheriv: unsupported algorithm ${alg}`);
  const k = toBytes(key), n = toBytes(nonce);
  let aad = new Uint8Array(0);
  const chunks = [];
  let tag;
  return {
    setAAD(data) {
      aad = toBytes(data);
    },
    update(data, enc) {
      chunks.push(toBytes(data, enc));
      return Buffer.alloc(0);
    },
    final() {
      const pt = Buffer.concat(chunks);
      const ct = chacha20Xor(k, n, pt, 1);
      tag = aeadTag(k, n, aad, ct);
      return Buffer.from(ct);
    },
    getAuthTag() {
      return Buffer.from(tag);
    },
  };
}

export function createDecipheriv(alg, key, nonce, _opts) {
  if (alg !== "chacha20-poly1305") throw new Error(`createDecipheriv: unsupported algorithm ${alg}`);
  const k = toBytes(key), n = toBytes(nonce);
  let aad = new Uint8Array(0);
  let expectedTag;
  const chunks = [];
  return {
    setAAD(data) {
      aad = toBytes(data);
    },
    setAuthTag(t) {
      expectedTag = toBytes(t);
    },
    update(data, enc) {
      chunks.push(toBytes(data, enc));
      return Buffer.alloc(0);
    },
    final() {
      const ct = Buffer.concat(chunks);
      const tag = aeadTag(k, n, aad, ct);
      if (!expectedTag || expectedTag.length !== 16 || !timingSafeEqual(Buffer.from(tag), Buffer.from(expectedTag))) {
        throw new Error("Unsupported state or unable to authenticate data");
      }
      return Buffer.from(chacha20Xor(k, n, ct, 1));
    },
  };
}

/* ----------------------------------------------------------------- Ed25519 */

const ED_P = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

const mod = (a, m = ED_P) => ((a % m) + m) % m;

function pow(base, exp, m) {
  let r = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return r;
}

const inv = (a) => pow(a, ED_P - 2n, ED_P);

// Extended coordinates (x, y, z, t), t = xy/z
function edAdd(p, q) {
  const [x1, y1, z1, t1] = p, [x2, y2, z2, t2] = q;
  const A = mod((y1 - x1) * (y2 - x2));
  const B = mod((y1 + x1) * (y2 + x2));
  const C = mod(2n * ED_D * t1 * t2);
  const D = mod(2n * z1 * z2);
  const E = B - A, F = D - C, G = D + C, H = B + A;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

function edScalarMul(k, point) {
  let r = [0n, 1n, 1n, 0n]; // identity
  let p = point;
  while (k > 0n) {
    if (k & 1n) r = edAdd(r, p);
    p = edAdd(p, p);
    k >>= 1n;
  }
  return r;
}

const ED_BY = mod(4n * inv(5n));
const ED_BX = (() => {
  // recover x for base point y with sign bit 0
  const y2 = mod(ED_BY * ED_BY);
  const u = mod(y2 - 1n), v = mod(ED_D * y2 + 1n);
  let x = mod(pow(mod(u * pow(v, 7n, ED_P)), (ED_P - 5n) / 8n, ED_P) * u * pow(v, 3n, ED_P));
  if (mod(v * x * x) === mod(-u)) x = mod(x * pow(2n, (ED_P - 1n) / 4n, ED_P));
  if (x & 1n) x = ED_P - x;
  return x;
})();
const ED_B = [ED_BX, ED_BY, 1n, mod(ED_BX * ED_BY)];

function edEncode(p) {
  const [x, y, z] = p;
  const zi = inv(z);
  const xa = mod(x * zi), ya = mod(y * zi);
  const out = new Buffer(32);
  let n = ya | ((xa & 1n) << 255n);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function edDecode(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  const sign = (y >> 255n) & 1n;
  y &= (1n << 255n) - 1n;
  if (y >= ED_P) return null;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n), v = mod(ED_D * y2 + 1n);
  let x = mod(pow(mod(u * pow(v, 7n, ED_P)), (ED_P - 5n) / 8n, ED_P) * u * pow(v, 3n, ED_P));
  if (mod(v * x * x) === mod(-u)) x = mod(x * pow(2n, (ED_P - 1n) / 4n, ED_P));
  else if (mod(v * x * x) !== u) return null;
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = ED_P - x;
  return [x, y, 1n, mod(x * y)];
}

function leToBigInt(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function edClamp(h) {
  let a = leToBigInt(h.subarray(0, 32));
  a &= (1n << 254n) - 8n;
  a |= 1n << 254n;
  return a;
}

function edPublicFromSeed(seed) {
  const h = sha512(seed);
  return edEncode(edScalarMul(edClamp(h), ED_B));
}

function edSignDetached(msg, seed) {
  const h = sha512(seed);
  const a = edClamp(h);
  const prefix = h.subarray(32);
  const A = edEncode(edScalarMul(a, ED_B));
  const r = mod(leToBigInt(sha512(Buffer.concat([Buffer.from(prefix), msg]))), ED_L);
  const R = edEncode(edScalarMul(r, ED_B));
  const k = mod(leToBigInt(sha512(Buffer.concat([R, A, msg]))), ED_L);
  const S = mod(r + k * a, ED_L);
  const sBytes = new Buffer(32);
  let s = S;
  for (let i = 0; i < 32; i++) {
    sBytes[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return Buffer.concat([R, sBytes]);
}

function edVerifyDetached(msg, sig, pubBytes) {
  if (sig.length !== 64) return false;
  const A = edDecode(pubBytes);
  if (!A) return false;
  const R = edDecode(sig.subarray(0, 32));
  if (!R) return false;
  const S = leToBigInt(sig.subarray(32));
  if (S >= ED_L) return false;
  const k = mod(leToBigInt(sha512(Buffer.concat([Buffer.from(sig.subarray(0, 32)), Buffer.from(pubBytes), msg]))), ED_L);
  const left = edScalarMul(S, ED_B);
  const right = edAdd(R, edScalarMul(k, A));
  return edEncode(left).equals(edEncode(right));
}

/* --------------------------------------------- KeyObject facade (Ed25519) */

// Fixed DER prefixes for Ed25519 (RFC 8410): the only key serialization the
// CFP sources use.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

class PublicKeyObject {
  constructor(raw) {
    this.raw = raw;
    this.type = "public";
    this.asymmetricKeyType = "ed25519";
  }
  export({ type, format }) {
    if (type !== "spki" || format !== "der") throw new Error("only spki/der export is supported");
    return Buffer.concat([SPKI_PREFIX, this.raw]);
  }
}

class PrivateKeyObject {
  constructor(seed) {
    this.seed = seed;
    this.type = "private";
    this.asymmetricKeyType = "ed25519";
  }
  export({ type, format }) {
    if (type !== "pkcs8" || format !== "der") throw new Error("only pkcs8/der export is supported");
    return Buffer.concat([PKCS8_PREFIX, this.seed]);
  }
}

function startsWith(buf, prefix) {
  if (buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (buf[i] !== prefix[i]) return false;
  return true;
}

export function createPublicKey(input) {
  const key = Buffer.from(input.key ?? input);
  if (input.format === "der" && input.type === "spki" && startsWith(key, SPKI_PREFIX) && key.length === 44) {
    return new PublicKeyObject(Buffer.from(key.subarray(12)));
  }
  throw new Error("createPublicKey shim supports only Ed25519 spki/der");
}

export function createPrivateKey(input) {
  const key = Buffer.from(input.key ?? input);
  if (input.format === "der" && input.type === "pkcs8" && startsWith(key, PKCS8_PREFIX) && key.length === 48) {
    return new PrivateKeyObject(Buffer.from(key.subarray(16)));
  }
  throw new Error("createPrivateKey shim supports only Ed25519 pkcs8/der");
}

export function generateKeyPairSync(alg) {
  if (alg !== "ed25519") throw new Error(`generateKeyPairSync: unsupported algorithm ${alg}`);
  const seed = randomBytes(32);
  return {
    publicKey: new PublicKeyObject(edPublicFromSeed(seed)),
    privateKey: new PrivateKeyObject(seed),
  };
}

export function sign(alg, data, key) {
  if (alg !== null && alg !== undefined) throw new Error("sign shim supports only alg=null (Ed25519)");
  if (!(key instanceof PrivateKeyObject)) throw new Error("sign: expected an Ed25519 private KeyObject");
  return edSignDetached(Buffer.from(data), key.seed);
}

export function verify(alg, data, key, signature) {
  if (alg !== null && alg !== undefined) throw new Error("verify shim supports only alg=null (Ed25519)");
  if (!(key instanceof PublicKeyObject)) throw new Error("verify: expected an Ed25519 public KeyObject");
  return edVerifyDetached(Buffer.from(data), Buffer.from(signature), key.raw);
}

/* --------------------------------------------------------------- globals */

// The Node sources reference `Buffer` (and occasionally `process.env`) as
// globals. Loading this module makes both available in the browser.
if (typeof globalThis.Buffer === "undefined") globalThis.Buffer = Buffer;
if (typeof globalThis.process === "undefined") globalThis.process = { env: {} };
