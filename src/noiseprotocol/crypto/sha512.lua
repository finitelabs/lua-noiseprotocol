--- @module "noiseprotocol.crypto.sha512"
--- Pure Lua SHA-512 Implementation for portability.
--- @class noiseprotocol.crypto.sha512
local sha512 = {}

local bitn = require("bitn")
local bit32 = bitn.bit32
local bit64 = bitn.bit64

local openssl_wrapper = require("noiseprotocol.openssl_wrapper")
local utils = require("noiseprotocol.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance (avoid module table lookups in hot loops)
local bit64_add = bit64.add
local bit64_xor = bit64.xor
local bit64_band = bit64.band
local bit64_bnot = bit64.bnot
local bit64_ror = bit64.ror
local bit64_shr = bit64.shr
local bit64_new = bit64.new
local bit32_bxor = bit32.bxor
local string_char = string.char
local string_rep = string.rep
local string_byte = string.byte
local table_concat = table.concat
local floor = math.floor

-- SHA-512 uses 64-bit words, but Lua numbers are limited to 2^53-1
-- We'll work with 32-bit high/low pairs for 64-bit arithmetic

-- SHA-512 round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
--- @type Int64HighLow[]
local K = {
  { 0x428a2f98, 0xd728ae22 },
  { 0x71374491, 0x23ef65cd },
  { 0xb5c0fbcf, 0xec4d3b2f },
  { 0xe9b5dba5, 0x8189dbbc },
  { 0x3956c25b, 0xf348b538 },
  { 0x59f111f1, 0xb605d019 },
  { 0x923f82a4, 0xaf194f9b },
  { 0xab1c5ed5, 0xda6d8118 },
  { 0xd807aa98, 0xa3030242 },
  { 0x12835b01, 0x45706fbe },
  { 0x243185be, 0x4ee4b28c },
  { 0x550c7dc3, 0xd5ffb4e2 },
  { 0x72be5d74, 0xf27b896f },
  { 0x80deb1fe, 0x3b1696b1 },
  { 0x9bdc06a7, 0x25c71235 },
  { 0xc19bf174, 0xcf692694 },
  { 0xe49b69c1, 0x9ef14ad2 },
  { 0xefbe4786, 0x384f25e3 },
  { 0x0fc19dc6, 0x8b8cd5b5 },
  { 0x240ca1cc, 0x77ac9c65 },
  { 0x2de92c6f, 0x592b0275 },
  { 0x4a7484aa, 0x6ea6e483 },
  { 0x5cb0a9dc, 0xbd41fbd4 },
  { 0x76f988da, 0x831153b5 },
  { 0x983e5152, 0xee66dfab },
  { 0xa831c66d, 0x2db43210 },
  { 0xb00327c8, 0x98fb213f },
  { 0xbf597fc7, 0xbeef0ee4 },
  { 0xc6e00bf3, 0x3da88fc2 },
  { 0xd5a79147, 0x930aa725 },
  { 0x06ca6351, 0xe003826f },
  { 0x14292967, 0x0a0e6e70 },
  { 0x27b70a85, 0x46d22ffc },
  { 0x2e1b2138, 0x5c26c926 },
  { 0x4d2c6dfc, 0x5ac42aed },
  { 0x53380d13, 0x9d95b3df },
  { 0x650a7354, 0x8baf63de },
  { 0x766a0abb, 0x3c77b2a8 },
  { 0x81c2c92e, 0x47edaee6 },
  { 0x92722c85, 0x1482353b },
  { 0xa2bfe8a1, 0x4cf10364 },
  { 0xa81a664b, 0xbc423001 },
  { 0xc24b8b70, 0xd0f89791 },
  { 0xc76c51a3, 0x0654be30 },
  { 0xd192e819, 0xd6ef5218 },
  { 0xd6990624, 0x5565a910 },
  { 0xf40e3585, 0x5771202a },
  { 0x106aa070, 0x32bbd1b8 },
  { 0x19a4c116, 0xb8d2d0c8 },
  { 0x1e376c08, 0x5141ab53 },
  { 0x2748774c, 0xdf8eeb99 },
  { 0x34b0bcb5, 0xe19b48a8 },
  { 0x391c0cb3, 0xc5c95a63 },
  { 0x4ed8aa4a, 0xe3418acb },
  { 0x5b9cca4f, 0x7763e373 },
  { 0x682e6ff3, 0xd6b2b8a3 },
  { 0x748f82ee, 0x5defb2fc },
  { 0x78a5636f, 0x43172f60 },
  { 0x84c87814, 0xa1f0ab72 },
  { 0x8cc70208, 0x1a6439ec },
  { 0x90befffa, 0x23631e28 },
  { 0xa4506ceb, 0xde82bde9 },
  { 0xbef9a3f7, 0xb2c67915 },
  { 0xc67178f2, 0xe372532b },
  { 0xca273ece, 0xea26619c },
  { 0xd186b8c7, 0x21c0c207 },
  { 0xeada7dd6, 0xcde0eb1e },
  { 0xf57d4f7f, 0xee6ed178 },
  { 0x06f067aa, 0x72176fba },
  { 0x0a637dc5, 0xa2c898a6 },
  { 0x113f9804, 0xbef90dae },
  { 0x1b710b35, 0x131c471b },
  { 0x28db77f5, 0x23047d84 },
  { 0x32caab7b, 0x40c72493 },
  { 0x3c9ebe0a, 0x15c9bebc },
  { 0x431d67c4, 0x9c100d4c },
  { 0x4cc5d4be, 0xcb3e42b6 },
  { 0x597f299c, 0xfc657e2a },
  { 0x5fcb6fab, 0x3ad6faec },
  { 0x6c44198c, 0x4a475817 },
}

--- @alias HashState64 [Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow]

-- Initial SHA-512 hash values (first 64 bits of fractional parts of square roots of first 8 primes)
--- @type HashState64
local H0 = {
  { 0x6a09e667, 0xf3bcc908 },
  { 0xbb67ae85, 0x84caa73b },
  { 0x3c6ef372, 0xfe94f82b },
  { 0xa54ff53a, 0x5f1d36f1 },
  { 0x510e527f, 0xade682d1 },
  { 0x9b05688c, 0x2b3e6c1f },
  { 0x1f83d9ab, 0xfb41bd6b },
  { 0x5be0cd19, 0x137e2179 },
}

--- Initialize an 80-element message schedule array with zeros (64-bit values)
--- @return Int64HighLow[] array Initialized array
local function create_message_schedule_64()
  local arr = {}
  for i = 1, 80 do
    arr[i] = bit64_new(0, 0)
  end
  return arr
end

-- Pre-allocated message schedule array for sha512_chunk()
local chunk_W = create_message_schedule_64()

--- SHA-512 Sigma0 function
--- @param x Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function Sigma0(x)
  return bit64_xor(bit64_xor(bit64_ror(x, 28), bit64_ror(x, 34)), bit64_ror(x, 39))
end

--- SHA-512 Sigma1 function
--- @param x Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function Sigma1(x)
  return bit64_xor(bit64_xor(bit64_ror(x, 14), bit64_ror(x, 18)), bit64_ror(x, 41))
end

--- SHA-512 sigma0 function
--- @param x Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function sigma0(x)
  return bit64_xor(bit64_xor(bit64_ror(x, 1), bit64_ror(x, 8)), bit64_shr(x, 7))
end

--- SHA-512 sigma1 function
--- @param x Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function sigma1(x)
  return bit64_xor(bit64_xor(bit64_ror(x, 19), bit64_ror(x, 61)), bit64_shr(x, 6))
end

--- SHA-512 Ch function
--- @param x Int64HighLow {high, low} input
--- @param y Int64HighLow {high, low} input
--- @param z Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function Ch(x, y, z)
  return bit64_xor(bit64_band(x, y), bit64_band(bit64_bnot(x), z))
end

--- SHA-512 Maj function
--- @param x Int64HighLow {high, low} input
--- @param y Int64HighLow {high, low} input
--- @param z Int64HighLow {high, low} input
--- @return Int64HighLow {high, low} result
local function Maj(x, y, z)
  return bit64_xor(bit64_xor(bit64_band(x, y), bit64_band(x, z)), bit64_band(y, z))
end

--- SHA-512 core compression function
--- @param chunk string 128-byte chunk
--- @param H HashState64 Hash state (8 64-bit values)
local function sha512_chunk(chunk, H)
  -- Reuse pre-allocated message schedule W
  local W = chunk_W

  -- First 16 words are the message chunk
  for i = 1, 16 do
    local val = bytes.be_bytes_to_u64(chunk, (i - 1) * 8 + 1)
    W[i][1], W[i][2] = val[1], val[2]
  end

  -- Extend the first 16 words into the remaining 64 words
  for i = 17, 80 do
    local w15 = W[i - 15]
    local w2 = W[i - 2]
    local s0 = sigma0(w15)
    local s1 = sigma1(w2)
    local result = bit64_add(bit64_add(bit64_add(W[i - 16], s0), W[i - 7]), s1)
    W[i][1], W[i][2] = result[1], result[2]
  end

  -- Initialize working variables
  local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

  -- Main loop (optimized)
  for i = 1, 80 do
    local prime = K[i]
    local S1 = Sigma1(e)
    local ch = Ch(e, f, g)
    local temp1 = bit64_add(bit64_add(bit64_add(bit64_add(h, S1), ch), prime), W[i])
    local S0 = Sigma0(a)
    local maj = Maj(a, b, c)
    local temp2 = bit64_add(S0, maj)

    h = g
    g = f
    f = e
    e = bit64_add(d, temp1)
    d = c
    c = b
    b = a
    a = bit64_add(temp1, temp2)
  end

  -- Add compressed chunk to current hash value
  H[1] = bit64_add(H[1], a)
  H[2] = bit64_add(H[2], b)
  H[3] = bit64_add(H[3], c)
  H[4] = bit64_add(H[4], d)
  H[5] = bit64_add(H[5], e)
  H[6] = bit64_add(H[6], f)
  H[7] = bit64_add(H[7], g)
  H[8] = bit64_add(H[8], h)
end

--- Compute SHA-512 hash of input data
--- @param data string Input data to hash
--- @return string hash 64-byte binary hash
function sha512.sha512(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("sha512", data, true)
  end

  -- Native implementation
  -- Initialize hash values
  --- @type HashState64
  local H = {}
  for i = 1, 8 do
    H[i] = { H0[i][1], H0[i][2] }
  end

  -- Pre-processing: adding padding bits
  local msg_len = #data
  local msg_len_bits = msg_len * 8

  -- Append '1' bit (plus zero padding to make it a byte)
  data = data .. string_char(0x80)

  -- Append zeros to make message length ≡ 896 (mod 1024) bits = 112 (mod 128) bytes
  local current_len = msg_len + 1
  local target_len = 112 -- We want to reach 112 bytes before adding the 16-byte length
  local padding_len = (target_len - current_len) % 128
  data = data .. string_rep("\0", padding_len)

  -- Append original length as 128-bit big-endian integer
  -- For simplicity, we only support messages < 2^64 bits
  data = data .. string_rep("\0", 8) -- High 64 bits (always 0)
  -- Low 64 bits of length
  local len_high = floor(msg_len_bits / 0x100000000)
  local len_low = msg_len_bits % 0x100000000
  data = data .. bytes.u64_to_be_bytes({ len_high, len_low })

  -- Process message in 128-byte chunks
  for i = 1, #data, 128 do
    local chunk = data:sub(i, i + 127)
    if #chunk == 128 then
      sha512_chunk(chunk, H)
    end
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes.u64_to_be_bytes(H[i])
  end

  return table_concat(result_bytes)
end

--- Compute SHA-512 hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 128-character hex string
function sha512.sha512_hex(data)
  return bytes.to_hex(sha512.sha512(data))
end

--- Compute HMAC-SHA512
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 64-byte HMAC value
function sha512.hmac_sha512(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("sha512", data, key, true)
  end

  -- Native implementation
  local block_size = 128 -- SHA-512 block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = sha512.sha512(key)
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
  local inner_hash = sha512.sha512(ipad .. data)
  return sha512.sha512(opad .. inner_hash)
end

--- Compute HMAC-SHA512 and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 128-character hex string
function sha512.hmac_sha512_hex(key, data)
  return bytes.to_hex(sha512.hmac_sha512(key, data))
end

--- Test vectors from FIPS 180-4 and RFC 4634
local test_vectors = {
  {
    name = "RFC 4634 Test 1 - Empty string",
    input = "",
    expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  },
  {
    name = "RFC 4634 Test 2 - 'abc'",
    input = "abc",
    expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  },
  {
    name = "RFC 4634 Test 3 - 448 bit string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
  },
  {
    name = "RFC 4634 Test 4 - 896 bit string",
    input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    expected = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  },
}
if os.getenv("INCLUDE_SLOW_TESTS") == "1" then
  table.insert(test_vectors, {
    name = "RFC 4634 Test 5 - One million 'a' characters",
    input = string_rep("a", 1000000),
    expected = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
  })
end

--- HMAC test vectors from RFC 4231
local hmac_test_vectors = {
  {
    name = "RFC 4231 Test Case 1",
    key = string_rep(string_char(0x0b), 20),
    data = "Hi There",
    expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  },
  {
    name = "RFC 4231 Test Case 2",
    key = "Jefe",
    data = "what do ya want for nothing?",
    expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
  },
  {
    name = "RFC 4231 Test Case 3",
    key = string_rep(string_char(0xaa), 20),
    data = string_rep(string_char(0xdd), 50),
    expected = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
  },
  {
    name = "RFC 4231 Test Case 4",
    key = bytes.from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
    data = string_rep(string_char(0xcd), 50),
    expected = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
  },
}

--- Run comprehensive self-test with test vectors and functional tests
--- @return boolean result True if all tests pass, false otherwise
function sha512.selftest()
  print("Running SHA-512 test vectors...")
  local all_passed = true
  local passed = 0
  local total = #test_vectors

  for _, test in ipairs(test_vectors) do
    local result = sha512.sha512_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      passed = passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
  all_passed = all_passed and (passed == total)

  print("Running SHA-512 HMAC test vectors...")
  local hmac_passed = 0
  local hmac_total = #hmac_test_vectors

  for _, test in ipairs(hmac_test_vectors) do
    local result = sha512.hmac_sha512_hex(test.key, test.data)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_passed = hmac_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC test vectors result: %d/%d tests passed\n", hmac_passed, hmac_total))
  all_passed = all_passed and (hmac_passed == hmac_total)

  print("Running SHA-512 functional tests...")

  local func_passed = 0
  local func_total = 0

  -- Test consistency
  func_total = func_total + 1
  local test_data = "Hello, World!"
  local hash1 = sha512.sha512_hex(test_data)
  local hash2 = sha512.sha512_hex(test_data)
  if hash1 ~= hash2 then
    print("  ❌ FAIL: Hash function is not deterministic")
  else
    print("  ✅ PASS: Hash function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test different inputs produce different outputs
  func_total = func_total + 1
  local hash_a = sha512.sha512_hex("a")
  local hash_b = sha512.sha512_hex("b")
  if hash_a == hash_b then
    print("  ❌ FAIL: Different inputs produce same hash")
  else
    print("  ✅ PASS: Different inputs produce different hashes")
    func_passed = func_passed + 1
  end

  -- Test binary vs hex consistency
  func_total = func_total + 1
  local test_msg = "test message"
  local binary_hash = sha512.sha512(test_msg)
  local hex_hash = sha512.sha512_hex(test_msg)
  if hex_hash ~= bytes.to_hex(binary_hash) then
    print("  ❌ FAIL: Binary and hex outputs inconsistent")
  else
    print("  ✅ PASS: Binary and hex outputs consistent")
    func_passed = func_passed + 1
  end

  -- Test HMAC consistency
  func_total = func_total + 1
  local hmac1 = sha512.hmac_sha512_hex("key", "data")
  local hmac2 = sha512.hmac_sha512_hex("key", "data")
  if hmac1 ~= hmac2 then
    print("  ❌ FAIL: HMAC function is not deterministic")
  else
    print("  ✅ PASS: HMAC function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test HMAC key sensitivity
  func_total = func_total + 1
  local hmac_key1 = sha512.hmac_sha512_hex("key1", "data")
  local hmac_key2 = sha512.hmac_sha512_hex("key2", "data")
  if hmac_key1 == hmac_key2 then
    print("  ❌ FAIL: Different HMAC keys produce same result")
  else
    print("  ✅ PASS: Different HMAC keys produce different results")
    func_passed = func_passed + 1
  end

  print(string.format("\nFunctional tests result: %d/%d tests passed", func_passed, func_total))

  return all_passed and (func_passed == func_total)
end

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for SHA-512 operations
--- including hash computation and HMAC for various message sizes.
function sha512.benchmark()
  -- Test data
  local message_64 = string_rep("a", 64)
  local message_1k = string_rep("a", 1024)
  local message_8k = string_rep("a", 8192)
  local hmac_key = "benchmark_key"

  print("Hash Operations:")
  benchmark_op("hash_64_bytes", function()
    sha512.sha512(message_64)
  end, 500)

  benchmark_op("hash_1k", function()
    sha512.sha512(message_1k)
  end, 100)

  benchmark_op("hash_8k", function()
    sha512.sha512(message_8k)
  end, 25)

  print("\nHMAC Operations:")
  benchmark_op("hmac_64_bytes", function()
    sha512.hmac_sha512(hmac_key, message_64)
  end, 250)

  benchmark_op("hmac_1k", function()
    sha512.hmac_sha512(hmac_key, message_1k)
  end, 50)

  benchmark_op("hmac_8k", function()
    sha512.hmac_sha512(hmac_key, message_8k)
  end, 15)
end

return sha512
