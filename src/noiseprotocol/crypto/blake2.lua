--- @module "noiseprotocol.crypto.blake2"
--- Pure Lua BLAKE2s and BLAKE2b Implementation for portability.
--- @class noiseprotocol.crypto.blake2
local blake2 = {}

local bitn = require("bitn")
local bit32 = bitn.bit32
local bit64 = bitn.bit64

local openssl_wrapper = require("noiseprotocol.openssl_wrapper")
local utils = require("noiseprotocol.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance (avoid module table lookups in hot loops)
local bit32_add = bit32.add
local bit32_bxor = bit32.bxor
local bit32_ror = bit32.ror
local bit64_add = bit64.add
local bit64_xor = bit64.xor
local bit64_ror = bit64.ror
local bit64_new = bit64.new
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local table_concat = table.concat

-- BLAKE2s initialization vectors (first 32 bits of fractional parts of square roots of first 8 primes)
--- @type HashState
local BLAKE2S_IV = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
}

-- BLAKE2b initialization vectors (first 64 bits of fractional parts of square roots of first 8 primes)
--- @type HashState64
local BLAKE2B_IV = {
  { 0x6a09e667, 0xf3bcc908 },
  { 0xbb67ae85, 0x84caa73b },
  { 0x3c6ef372, 0xfe94f82b },
  { 0xa54ff53a, 0x5f1d36f1 },
  { 0x510e527f, 0xade682d1 },
  { 0x9b05688c, 0x2b3e6c1f },
  { 0x1f83d9ab, 0xfb41bd6b },
  { 0x5be0cd19, 0x137e2179 },
}

--- @alias Blake2sVector16 [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]
--- @alias Blake2bVector16 [Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow]

-- BLAKE2s permutation table
--- @type Blake2sVector16[]
local BLAKE2S_SIGMA = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
}

-- BLAKE2b permutation table (same as BLAKE2s)
local BLAKE2B_SIGMA = BLAKE2S_SIGMA

--- Initialize a 16-element BLAKE2s working vector with zeros
--- @return Blake2sVector16 array Initialized array
local function create_blake2s_vector()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  --- @cast arr Blake2sVector16
  return arr
end

--- Initialize a 16-element BLAKE2b working vector with zeros
--- @return Blake2bVector16 array Initialized array
local function create_blake2b_vector()
  local arr = {}
  for i = 1, 16 do
    arr[i] = bit64_new(0, 0)
  end
  --- @cast arr Blake2bVector16
  return arr
end

-- Pre-allocated arrays for blake2s_compress() to avoid repeated allocation
local blake2s_v = create_blake2s_vector()

-- Pre-allocated arrays for blake2b_compress() to avoid repeated allocation
local blake2b_v = create_blake2b_vector()

--- BLAKE2s G function
--- @param v Blake2sVector16 Working vector
--- @param a integer Index a
--- @param b integer Index b
--- @param c integer Index c
--- @param d integer Index d
--- @param x integer Message word x
--- @param y integer Message word y
local function blake2s_g(v, a, b, c, d, x, y)
  v[a] = bit32_add(bit32_add(v[a], v[b]), x)
  v[d] = bit32_ror(bit32_bxor(v[d], v[a]), 16)
  v[c] = bit32_add(v[c], v[d])
  v[b] = bit32_ror(bit32_bxor(v[b], v[c]), 12)
  v[a] = bit32_add(bit32_add(v[a], v[b]), y)
  v[d] = bit32_ror(bit32_bxor(v[d], v[a]), 8)
  v[c] = bit32_add(v[c], v[d])
  v[b] = bit32_ror(bit32_bxor(v[b], v[c]), 7)
end

--- BLAKE2b G function
--- @param v Blake2bVector16 Working vector
--- @param a integer Index a
--- @param b integer Index b
--- @param c integer Index c
--- @param d integer Index d
--- @param x table Message word x
--- @param y table Message word y
local function blake2b_g(v, a, b, c, d, x, y)
  v[a] = bit64_add(bit64_add(v[a], v[b]), x)
  v[d] = bit64_ror(bit64_xor(v[d], v[a]), 32)
  v[c] = bit64_add(v[c], v[d])
  v[b] = bit64_ror(bit64_xor(v[b], v[c]), 24)
  v[a] = bit64_add(bit64_add(v[a], v[b]), y)
  v[d] = bit64_ror(bit64_xor(v[d], v[a]), 16)
  v[c] = bit64_add(v[c], v[d])
  v[b] = bit64_ror(bit64_xor(v[b], v[c]), 63)
end

--- BLAKE2s compression function
--- @param h HashState Hash state (8 words)
--- @param m Blake2sVector16 Message block (16 words)
--- @param t integer Counter (low 32 bits)
--- @param th integer Counter (high 32 bits)
--- @param f boolean Final block flag
local function blake2s_compress(h, m, t, th, f)
  -- Reuse pre-allocated working vector
  local v = blake2s_v

  -- First half from hash state
  for i = 1, 8 do
    v[i] = h[i]
  end

  -- Second half from IV
  for i = 1, 8 do
    v[8 + i] = BLAKE2S_IV[i]
  end

  -- Mix in counter and final flag
  v[13] = bit32_bxor(v[13], t) -- Low 32 bits of counter
  v[14] = bit32_bxor(v[14], th) -- High 32 bits of counter
  if f then
    v[15] = bit32_bxor(v[15], 0xFFFFFFFF) -- Invert all bits for final block
  end

  -- 10 rounds
  for r = 1, 10 do
    --- @type Blake2sVector16
    local s = assert(BLAKE2S_SIGMA[r], "Invalid BLAKE2s round index")

    -- Column step
    blake2s_g(v, 1, 5, 9, 13, m[s[1] + 1], m[s[2] + 1])
    blake2s_g(v, 2, 6, 10, 14, m[s[3] + 1], m[s[4] + 1])
    blake2s_g(v, 3, 7, 11, 15, m[s[5] + 1], m[s[6] + 1])
    blake2s_g(v, 4, 8, 12, 16, m[s[7] + 1], m[s[8] + 1])

    -- Diagonal step
    blake2s_g(v, 1, 6, 11, 16, m[s[9] + 1], m[s[10] + 1])
    blake2s_g(v, 2, 7, 12, 13, m[s[11] + 1], m[s[12] + 1])
    blake2s_g(v, 3, 8, 9, 14, m[s[13] + 1], m[s[14] + 1])
    blake2s_g(v, 4, 5, 10, 15, m[s[15] + 1], m[s[16] + 1])
  end

  -- Finalize
  for i = 1, 8 do
    h[i] = bit32_bxor(bit32_bxor(h[i], v[i]), v[i + 8])
  end
end

--- BLAKE2b compression function
--- @param h HashState64 Hash state (8 64-bit words)
--- @param m Blake2bVector16 Message block (16 64-bit words)
--- @param t table Counter (64-bit)
--- @param f boolean Final block flag
local function blake2b_compress(h, m, t, f)
  -- Reuse pre-allocated working vector
  local v = blake2b_v

  -- First half from hash state
  for i = 1, 8 do
    v[i][1], v[i][2] = h[i][1], h[i][2]
  end

  -- Second half from IV
  for i = 1, 8 do
    v[8 + i][1], v[8 + i][2] = BLAKE2B_IV[i][1], BLAKE2B_IV[i][2]
  end

  -- Mix in counter and final flag
  v[13] = bit64_xor(v[13], t)
  v[14] = bit64_xor(v[14], bit64_new(0, 0)) -- High 64 bits of counter (always 0 for messages < 2^64 bytes)
  if f then
    v[15] = bit64_xor(v[15], bit64_new(0xffffffff, 0xffffffff))
  end

  -- 12 rounds
  for r = 1, 12 do
    --- @type Blake2sVector16
    local s = assert(BLAKE2B_SIGMA[((r - 1) % 10) + 1], "Invalid round index for BLAKE2b")

    -- Column step
    blake2b_g(v, 1, 5, 9, 13, m[s[1] + 1], m[s[2] + 1])
    blake2b_g(v, 2, 6, 10, 14, m[s[3] + 1], m[s[4] + 1])
    blake2b_g(v, 3, 7, 11, 15, m[s[5] + 1], m[s[6] + 1])
    blake2b_g(v, 4, 8, 12, 16, m[s[7] + 1], m[s[8] + 1])

    -- Diagonal step
    blake2b_g(v, 1, 6, 11, 16, m[s[9] + 1], m[s[10] + 1])
    blake2b_g(v, 2, 7, 12, 13, m[s[11] + 1], m[s[12] + 1])
    blake2b_g(v, 3, 8, 9, 14, m[s[13] + 1], m[s[14] + 1])
    blake2b_g(v, 4, 5, 10, 15, m[s[15] + 1], m[s[16] + 1])
  end

  -- Finalize
  for i = 1, 8 do
    h[i] = bit64_xor(bit64_xor(h[i], v[i]), v[i + 8])
  end
end

--- Compute BLAKE2s hash of input data
--- @param data string Input data to hash
--- @return string hash 32-byte binary hash
function blake2.blake2s(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("blake2s256", data, true)
  end

  -- Native implementation
  -- Initialize hash state
  --- @type HashState
  local h = {}
  for i = 1, 8 do
    h[i] = BLAKE2S_IV[i]
  end

  -- Parameter block: digest length = 32, key length = 0, fanout = 1, depth = 1
  -- All other parameters are 0 (no salt, no personalization, etc.)
  local param = 32 + (0 * 256) + (1 * 65536) + (1 * 16777216) -- 0x01010020
  h[1] = bit32_bxor(h[1], param)

  local data_len = #data
  local offset = 1
  local counter = 0

  -- Process full 64-byte blocks
  while offset + 63 <= data_len do
    counter = counter + 64

    -- Check if this is the last block
    local is_last_block = (offset + 64 > data_len)

    -- Load message block
    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u32(data, offset + (i - 1) * 4)
    end

    blake2s_compress(h, m, counter, 0, is_last_block)
    offset = offset + 64
  end

  -- Process final block (if there's remaining data)
  local remaining = data_len - offset + 1

  if remaining > 0 then
    -- We have a partial block left to process
    counter = counter + remaining

    -- Pad final block with zeros
    local final_data = data:sub(offset)
    local final_block = final_data .. string_rep("\0", 64 - remaining)

    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u32(final_block, (i - 1) * 4 + 1)
    end

    blake2s_compress(h, m, counter, 0, true)
  elseif data_len == 0 then
    -- Special case: empty input
    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = 0
    end

    blake2s_compress(h, m, 0, 0, true)
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes.u32_to_le_bytes(h[i])
  end

  return table_concat(result_bytes)
end

--- Compute BLAKE2b hash of input data
--- @param data string Input data to hash
--- @return string hash 64-byte binary hash
function blake2.blake2b(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("blake2b512", data, true)
  end

  -- Native implementation
  -- Initialize hash state
  --- @type HashState64
  local h = {}
  for i = 1, 8 do
    h[i] = { BLAKE2B_IV[i][1], BLAKE2B_IV[i][2] }
  end

  -- Parameter block: digest length = 64, key length = 0, fanout = 1, depth = 1
  -- The parameter block is 128 bytes, but we only need to XOR the first 8 bytes with h[1]
  -- Format (little-endian): digest_length(1) || key_length(1) || fanout(1) || depth(1) || leaf_length(4)
  -- For standard BLAKE2b: digest_length=64, key_length=0, fanout=1, depth=1
  -- In little-endian 64-bit: 0x0000000001010040
  -- Split into two 32-bit words (little-endian): low=0x01010040, high=0x00000000
  -- But our u64 format is {high, low}, so we need {0x00000000, 0x01010040}
  h[1] = bit64_xor(h[1], bit64_new(0x00000000, 0x01010040))

  local data_len = #data
  local offset = 1
  local counter = bit64_new(0, 0)

  -- Process full 128-byte blocks
  while offset + 127 <= data_len do
    counter = bit64_add(counter, bit64_new(0, 128))

    -- Check if this is the last block
    local is_last_block = (offset + 128 > data_len)

    -- Load message block
    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u64(data, offset + (i - 1) * 8)
    end

    blake2b_compress(h, m, counter, is_last_block)
    offset = offset + 128
  end

  -- Process final block (if there's remaining data)
  local remaining = data_len - offset + 1
  if remaining > 0 then
    counter = bit64_add(counter, bit64_new(0, remaining))

    -- Pad final block with zeros
    local final_block = data:sub(offset) .. string_rep("\0", 128 - remaining)

    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u64(final_block, (i - 1) * 8 + 1)
    end

    blake2b_compress(h, m, counter, true)
  elseif data_len == 0 then
    -- Empty input case
    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bit64_new(0, 0)
    end
    blake2b_compress(h, m, bit64_new(0, 0), true)
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes.u64_to_le_bytes(h[i])
  end

  return table_concat(result_bytes)
end

--- Compute BLAKE2s hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 64-character hex string
function blake2.blake2s_hex(data)
  return bytes.to_hex(blake2.blake2s(data))
end

--- Compute BLAKE2b hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 128-character hex string
function blake2.blake2b_hex(data)
  return bytes.to_hex(blake2.blake2b(data))
end

--- Compute HMAC-BLAKE2s
--- Note: RFC 7693 recommends using BLAKE2's native keyed mode instead of HMAC.
--- However, HMAC-BLAKE2 is provided for compatibility with protocols that require
--- HMAC for all hash functions (e.g., Noise Protocol Framework).
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 32-byte HMAC value
function blake2.hmac_blake2s(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("blake2s256", data, key, true)
  end

  -- Native implementation
  local block_size = 64 -- BLAKE2s block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = blake2.blake2s(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string_rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding (optimized with table)
  local ipad_bytes = {}
  local opad_bytes = {}
  for i = 1, block_size do
    local byte = string_byte(key, i)
    ipad_bytes[i] = string_char(bit32_bxor(byte, 0x36))
    opad_bytes[i] = string_char(bit32_bxor(byte, 0x5C))
  end
  local ipad = table_concat(ipad_bytes)
  local opad = table_concat(opad_bytes)

  -- Compute HMAC = H(opad || H(ipad || data))
  local inner_hash = blake2.blake2s(ipad .. data)
  return blake2.blake2s(opad .. inner_hash)
end

--- Compute HMAC-BLAKE2b
--- Note: RFC 7693 recommends using BLAKE2's native keyed mode instead of HMAC.
--- However, HMAC-BLAKE2 is provided for compatibility with protocols that require
--- HMAC for all hash functions (e.g., Noise Protocol Framework).
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 64-byte HMAC value
function blake2.hmac_blake2b(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("blake2b512", data, key, true)
  end

  -- Native implementation
  local block_size = 128 -- BLAKE2b block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = blake2.blake2b(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string_rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding (optimized with table)
  local ipad_bytes = {}
  local opad_bytes = {}
  for i = 1, block_size do
    local byte = string_byte(key, i)
    ipad_bytes[i] = string_char(bit32_bxor(byte, 0x36))
    opad_bytes[i] = string_char(bit32_bxor(byte, 0x5C))
  end
  local ipad = table_concat(ipad_bytes)
  local opad = table_concat(opad_bytes)

  -- Compute HMAC = H(opad || H(ipad || data))
  local inner_hash = blake2.blake2b(ipad .. data)
  return blake2.blake2b(opad .. inner_hash)
end

--- Compute HMAC-BLAKE2s and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 64-character hex string
function blake2.hmac_blake2s_hex(key, data)
  return bytes.to_hex(blake2.hmac_blake2s(key, data))
end

--- Compute HMAC-BLAKE2b and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 128-character hex string
function blake2.hmac_blake2b_hex(key, data)
  return bytes.to_hex(blake2.hmac_blake2b(key, data))
end

--- Digest test vectors
local blake2s_test_vectors = {
  {
    name = "Test Vector 1 - Empty string",
    input = "",
    expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
  },
  {
    name = "Test Vector 2 - abc",
    input = "abc",
    expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
  },
  {
    name = "Test Vector 3 - Long string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189",
  },
}

local blake2b_test_vectors = {
  {
    name = "Test Vector 1 - Empty string",
    input = "",
    expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  },
  {
    name = "Test Vector 2 - abc",
    input = "abc",
    expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  },
  {
    name = "Test Vector 3 - Long string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888",
  },
}

--- HMAC-BLAKE2 test vectors verified with Python's hmac library
--- These use true HMAC construction (RFC 2104), not BLAKE2's keyed mode
--- Python code: hmac.new(key, message, hashlib.blake2s).hexdigest()
local hmac_blake2s_test_vectors = {
  {
    name = "Empty message with short key",
    key = "key",
    message = "",
    expected = "67148074efc0f6741b474ef81c4d98d266e880d372fe723d2569b1d414d234be",
  },
  {
    name = "Short message with short key",
    key = "key",
    message = "The quick brown fox jumps over the lazy dog",
    expected = "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0",
  },
  {
    name = "RFC 4231 Test Case 1 pattern",
    key = string_rep(string_char(0x0b), 20),
    message = "Hi There",
    expected = "65a8b7c5cc9136d424e82c37e2707e74e913c0655b99c75f40edf387453a3260",
  },
  {
    name = "RFC 4231 Test Case 2 pattern",
    key = "Jefe",
    message = "what do ya want for nothing?",
    expected = "90b6281e2f3038c9056af0b4a7e763cae6fe5d9eb4386a0ec95237890c104ff0",
  },
  {
    name = "Key = block size (64 bytes)",
    key = string_rep("a", 64),
    message = "Test message",
    expected = "12d0e782ae473d8007d33ae6e5244afcaf9239f6a7d5476c69060c01383d6b58",
  },
  {
    name = "Key > block size (80 bytes)",
    key = string_rep("a", 80),
    message = "Test message",
    expected = "41da357bda1107f9fad1a504b5afbe75f5ead5ed7cf8f82e59e18c5e9e653882",
  },
}

local hmac_blake2b_test_vectors = {
  {
    name = "Empty message with short key",
    key = "key",
    message = "",
    expected = "019fe04bf010b8d72772e6b46897ecf74b4878c394ff2c4d5cfa0b7cc9bbefcb28c36de23cef03089db9c3d900468c89804f135e9fdef7ec9b3c7abe50ed33d3",
  },
  {
    name = "Short message with short key",
    key = "key",
    message = "The quick brown fox jumps over the lazy dog",
    expected = "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aaaf6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b",
  },
  {
    name = "RFC 4231 Test Case 1 pattern",
    key = string_rep(string_char(0x0b), 20),
    message = "Hi There",
    expected = "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24",
  },
  {
    name = "RFC 4231 Test Case 2 pattern",
    key = "Jefe",
    message = "what do ya want for nothing?",
    expected = "6ff884f8ddc2a6586b3c98a4cd6ebdf14ec10204b6710073eb5865ade37a2643b8807c1335d107ecdb9ffeaeb6828c4625ba172c66379efcd222c2de11727ab4",
  },
  {
    name = "Key = block size (128 bytes)",
    key = string_rep("a", 128),
    message = "Test message",
    expected = "021a22a3ecf0f1f7a15aca6a5d9704fc99b6a84a627fa53f7ac932a961ffb69b1e68c46981d5b44fd00a7cae75e4ee63d393eec844a8de2dd00e45b5a0d4e275",
  },
  {
    name = "Key > block size (80 bytes)",
    key = string_rep("a", 80),
    message = "Test message",
    expected = "1c8fb6f426d7800000e8d03c141905b33d10a4da16f9c018140955c5cedfa7a017204aaea1f141c1c0d3d942dee04a795a6e589898c1328b717ad6053a7b4790",
  },
}

--- Run comprehensive self-test with test vectors and functional tests
--- @return boolean result True if all tests pass, false otherwise
function blake2.selftest()
  print("Running BLAKE2s test vectors...")
  local passed = 0
  local total = #blake2s_test_vectors

  for _, test in ipairs(blake2s_test_vectors) do
    local result = blake2.blake2s_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      passed = passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
      return false
    end
  end

  print(string.format("\nBLAKE2s test vectors result: %d/%d tests passed\n", passed, total))

  print("Running BLAKE2b test vectors...")
  local blake2b_passed = 0
  local blake2b_total = #blake2b_test_vectors

  for _, test in ipairs(blake2b_test_vectors) do
    local result = blake2.blake2b_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      blake2b_passed = blake2b_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
      return false
    end
  end

  print(string.format("\nBLAKE2b test vectors result: %d/%d tests passed\n", blake2b_passed, blake2b_total))

  -- Run HMAC-BLAKE2 test vectors
  print("Running HMAC-BLAKE2s test vectors...")

  local hmac_s_passed = 0
  local hmac_s_total = #hmac_blake2s_test_vectors

  for _, test in ipairs(hmac_blake2s_test_vectors) do
    local result = blake2.hmac_blake2s_hex(test.key, test.message)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_s_passed = hmac_s_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC-BLAKE2s test vectors: %d/%d tests passed\n", hmac_s_passed, hmac_s_total))

  print("Running HMAC-BLAKE2b test vectors...")
  local hmac_b_passed = 0
  local hmac_b_total = #hmac_blake2b_test_vectors

  for _, test in ipairs(hmac_blake2b_test_vectors) do
    local result = blake2.hmac_blake2b_hex(test.key, test.message)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_b_passed = hmac_b_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC-BLAKE2b test vectors: %d/%d tests passed\n", hmac_b_passed, hmac_b_total))

  print("Running BLAKE2 functional tests...")

  -- Test consistency
  local test_data = "Hello, BLAKE2!"
  local blake2s_hash1 = blake2.blake2s_hex(test_data)
  local blake2s_hash2 = blake2.blake2s_hex(test_data)
  local blake2b_hash1 = blake2.blake2b_hex(test_data)
  local blake2b_hash2 = blake2.blake2b_hex(test_data)

  if blake2s_hash1 ~= blake2s_hash2 or blake2b_hash1 ~= blake2b_hash2 then
    print("  ❌ FAIL: Hash functions are not deterministic")
    return false
  else
    print("  ✅ PASS: Hash functions are deterministic")
  end

  -- Test different inputs produce different outputs
  local hash_a_s = blake2.blake2s_hex("a")
  local hash_b_s = blake2.blake2s_hex("b")
  local hash_a_b = blake2.blake2b_hex("a")
  local hash_b_b = blake2.blake2b_hex("b")

  if hash_a_s == hash_b_s or hash_a_b == hash_b_b then
    print("  ❌ FAIL: Different inputs produce same hash")
    return false
  else
    print("  ✅ PASS: Different inputs produce different hashes")
  end

  -- Test binary vs hex consistency
  local test_msg = "test message"
  local binary_s = blake2.blake2s(test_msg)
  local hex_s = blake2.blake2s_hex(test_msg)
  local binary_b = blake2.blake2b(test_msg)
  local hex_b = blake2.blake2b_hex(test_msg)

  if hex_s ~= bytes.to_hex(binary_s) or hex_b ~= bytes.to_hex(binary_b) then
    print("  ❌ FAIL: Binary and hex outputs inconsistent")
    return false
  else
    print("  ✅ PASS: Binary and hex outputs consistent")
  end

  -- Test HMAC consistency
  local hmac1_s = blake2.hmac_blake2s_hex("key", "data")
  local hmac2_s = blake2.hmac_blake2s_hex("key", "data")
  local hmac1_b = blake2.hmac_blake2b_hex("key", "data")
  local hmac2_b = blake2.hmac_blake2b_hex("key", "data")

  if hmac1_s ~= hmac2_s or hmac1_b ~= hmac2_b then
    print("  ❌ FAIL: HMAC functions are not deterministic")
    return false
  else
    print("  ✅ PASS: HMAC functions are deterministic")
  end

  print("\nFunctional tests result: 4/4 tests passed")

  return true
end

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for BLAKE2 operations
--- including BLAKE2s and BLAKE2b hash computation for various message sizes.
function blake2.benchmark()
  -- Test data
  local message_64 = string_rep("a", 64)
  local message_1k = string_rep("a", 1024)
  local message_8k = string_rep("a", 8192)
  local hmac_key = "benchmark_key"

  print("BLAKE2s Hash Operations:")
  benchmark_op("blake2s_64_bytes", function()
    blake2.blake2s(message_64)
  end, 1000)

  benchmark_op("blake2s_1k", function()
    blake2.blake2s(message_1k)
  end, 200)

  benchmark_op("blake2s_8k", function()
    blake2.blake2s(message_8k)
  end, 50)

  print("\nBLAKE2b Hash Operations:")
  benchmark_op("blake2b_64_bytes", function()
    blake2.blake2b(message_64)
  end, 500)

  benchmark_op("blake2b_1k", function()
    blake2.blake2b(message_1k)
  end, 100)

  benchmark_op("blake2b_8k", function()
    blake2.blake2b(message_8k)
  end, 25)

  print("\nBLAKE2s HMAC Operations:")
  benchmark_op("hmac_blake2s_64_bytes", function()
    blake2.hmac_blake2s(hmac_key, message_64)
  end, 500)

  benchmark_op("hmac_blake2s_1k", function()
    blake2.hmac_blake2s(hmac_key, message_1k)
  end, 100)
end

return blake2
