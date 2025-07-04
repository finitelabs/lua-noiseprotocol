--- @module "crypto.sha256"
--- Pure Lua SHA-256 Implementation for portability.

local sha256 = {}

-- SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
--- @type integer[64]
local K = {
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
}

--- @alias HashState [integer, integer, integer, integer, integer, integer, integer, integer]

-- Initial SHA-256 hash values (first 32 bits of fractional parts of square roots of first 8 primes)
--- @type HashState
local H0 = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
}

-- Load utils library for consistent operations
local utils = require("utils")
local band32 = utils.band32
local bxor32 = utils.bxor32
local bnot32 = utils.bnot32
local rshift32 = utils.rshift32
local ror32 = utils.ror32
local add32 = utils.add32

--- SHA-256 core compression function
--- @param chunk string 64-byte chunk
--- @param H HashState Hash state (8 integers)
local function sha256_chunk(chunk, H)
  -- Prepare message schedule W
  local W = {}

  -- First 16 words are the message chunk
  for i = 1, 16 do
    W[i] = utils.be_bytes_to_u32(chunk, (i - 1) * 4 + 1)
  end

  -- Extend the first 16 words into the remaining 48 words
  for i = 17, 64 do
    local s0 = bxor32(ror32(W[i - 15], 7), bxor32(ror32(W[i - 15], 18), rshift32(W[i - 15], 3)))
    local s1 = bxor32(ror32(W[i - 2], 17), bxor32(ror32(W[i - 2], 19), rshift32(W[i - 2], 10)))
    W[i] = add32(add32(add32(W[i - 16], s0), W[i - 7]), s1)
  end

  -- Initialize working variables
  local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

  -- Main loop
  for i = 1, 64 do
    local prime = assert(K[i], "Missing SHA-256 constant K[" .. i .. "]")
    local S1 = bxor32(ror32(e, 6), bxor32(ror32(e, 11), ror32(e, 25)))
    local ch = bxor32(band32(e, f), band32(bnot32(e), g))
    local temp1 = add32(add32(add32(add32(h, S1), ch), prime), W[i])
    local S0 = bxor32(ror32(a, 2), bxor32(ror32(a, 13), ror32(a, 22)))
    local maj = bxor32(band32(a, b), bxor32(band32(a, c), band32(b, c)))
    local temp2 = add32(S0, maj)

    h = g
    g = f
    f = e
    e = add32(d, temp1)
    d = c
    c = b
    b = a
    a = add32(temp1, temp2)
  end

  -- Add compressed chunk to current hash value
  H[1] = add32(H[1], a)
  H[2] = add32(H[2], b)
  H[3] = add32(H[3], c)
  H[4] = add32(H[4], d)
  H[5] = add32(H[5], e)
  H[6] = add32(H[6], f)
  H[7] = add32(H[7], g)
  H[8] = add32(H[8], h)
end

-- ============================================================================
-- SHA-256 PUBLIC INTERFACE
-- ============================================================================

--- Compute SHA-256 hash of input data
--- @param data string Input data to hash
--- @return string hash 32-byte binary hash
function sha256.sha256(data)
  -- Initialize hash values
  --- @type HashState
  local H = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] }

  -- Pre-processing: adding padding bits
  local msg_len = #data
  local msg_len_bits = msg_len * 8

  -- Append '1' bit (plus zero padding to make it a byte)
  data = data .. string.char(0x80)

  -- Append zeros to make message length ≡ 448 (mod 512) bits = 56 (mod 64) bytes
  -- Current length is msg_len + 1 (for the 0x80 byte)
  local current_len = msg_len + 1
  local target_len = 56 -- We want to reach 56 bytes before adding the 8-byte length
  local padding_len = (target_len - current_len) % 64
  data = data .. string.rep("\0", padding_len)

  -- Append original length as 64-bit big-endian integer
  -- For simplicity, we only support messages < 2^32 bits
  data = data .. string.rep("\0", 4) .. utils.u32_to_be_bytes(msg_len_bits)

  -- Process message in 64-byte chunks
  for i = 1, #data, 64 do
    local chunk = data:sub(i, i + 63)
    if #chunk == 64 then
      sha256_chunk(chunk, H)
    end
  end

  -- Produce final hash value as binary string
  local result = ""
  for i = 1, 8 do
    result = result .. utils.u32_to_be_bytes(H[i])
  end

  return result
end

--- Compute SHA-256 hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 64-character hex string
function sha256.sha256_hex(data)
  local hash = sha256.sha256(data)
  return utils.to_hex(hash)
end

--- Compute HMAC-SHA256
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 32-byte HMAC value
function sha256.hmac_sha256(key, data)
  local block_size = 64 -- SHA-256 block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = sha256.sha256(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string.rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding
  local ipad = ""
  local opad = ""
  for i = 1, block_size do
    local byte = string.byte(key, i)
    ipad = ipad .. string.char(bxor32(byte, 0x36))
    opad = opad .. string.char(bxor32(byte, 0x5C))
  end

  -- Compute HMAC = H(opad || H(ipad || data))
  local inner_hash = sha256.sha256(ipad .. data)
  return sha256.sha256(opad .. inner_hash)
end

--- Compute HMAC-SHA256 and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 64-character hex string
function sha256.hmac_sha256_hex(key, data)
  local hmac = sha256.hmac_sha256(key, data)
  return utils.to_hex(hmac)
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- Test vectors for self-test
local test_vectors = {
  {
    name = "Empty string",
    input = "",
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  {
    name = "Single character 'a'",
    input = "a",
    expected = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  },
  {
    name = "Short string 'abc'",
    input = "abc",
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  },
  {
    name = "Numeric string '123456'",
    input = "123456",
    expected = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
  },
  {
    name = "Medium length string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  },
  {
    name = "The quick brown fox",
    input = "The quick brown fox jumps over the lazy dog",
    expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  },
  {
    name = "The quick brown fox (cog)",
    input = "The quick brown fox jumps over the lazy cog",
    expected = "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
  },
}
if os.getenv("INCLUDE_SLOW_TESTS") == "1" then
  table.insert(test_vectors, {
    name = "Million 'a' characters",
    input = string.rep("a", 1000000),
    expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  })
end

--- HMAC test vectors
local hmac_test_vectors = {
  {
    name = "HMAC Test Case 1",
    key = string.rep(string.char(0x0b), 20),
    data = "Hi There",
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  },
  {
    name = "HMAC Test Case 2",
    key = "Jefe",
    data = "what do ya want for nothing?",
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  },
  {
    name = "HMAC Test Case 3",
    key = string.rep(string.char(0xaa), 20),
    data = string.rep(string.char(0xdd), 50),
    expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  },
}

--- Run comprehensive self-test with test vectors and functional tests
--- @return boolean result True if all tests pass, false otherwise
function sha256.selftest()
  print("Running SHA-256 test vectors...")
  local all_passed = true
  local passed = 0
  local total = #test_vectors

  for _, test in ipairs(test_vectors) do
    local result = sha256.sha256_hex(test.input)
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

  print("Running SHA-256 HMAC test vectors...")
  local hmac_passed = 0
  local hmac_total = #hmac_test_vectors

  for _, test in ipairs(hmac_test_vectors) do
    local result = sha256.hmac_sha256_hex(test.key, test.data)
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

  print("Running SHA-256 functional tests...")

  local func_passed = 0
  local func_total = 0

  -- Test consistency
  func_total = func_total + 1
  local test_data = "Hello, World!"
  local hash1 = sha256.sha256_hex(test_data)
  local hash2 = sha256.sha256_hex(test_data)
  if hash1 ~= hash2 then
    print("  ❌ FAIL: Hash function is not deterministic")
  else
    print("  ✅ PASS: Hash function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test different inputs produce different outputs
  func_total = func_total + 1
  local hash_a = sha256.sha256_hex("a")
  local hash_b = sha256.sha256_hex("b")
  if hash_a == hash_b then
    print("  ❌ FAIL: Different inputs produce same hash")
  else
    print("  ✅ PASS: Different inputs produce different hashes")
    func_passed = func_passed + 1
  end

  -- Test binary vs hex consistency
  func_total = func_total + 1
  local test_msg = "test message"
  local binary_hash = sha256.sha256(test_msg)
  local hex_hash = sha256.sha256_hex(test_msg)
  if hex_hash ~= utils.to_hex(binary_hash) then
    print("  ❌ FAIL: Binary and hex outputs inconsistent")
  else
    print("  ✅ PASS: Binary and hex outputs consistent")
    func_passed = func_passed + 1
  end

  -- Test HMAC consistency
  func_total = func_total + 1
  local hmac1 = sha256.hmac_sha256_hex("key", "data")
  local hmac2 = sha256.hmac_sha256_hex("key", "data")
  if hmac1 ~= hmac2 then
    print("  ❌ FAIL: HMAC function is not deterministic")
  else
    print("  ✅ PASS: HMAC function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test HMAC key sensitivity
  func_total = func_total + 1
  local hmac_key1 = sha256.hmac_sha256_hex("key1", "data")
  local hmac_key2 = sha256.hmac_sha256_hex("key2", "data")
  if hmac_key1 == hmac_key2 then
    print("  ❌ FAIL: Different HMAC keys produce same result")
  else
    print("  ✅ PASS: Different HMAC keys produce different results")
    func_passed = func_passed + 1
  end

  print(string.format("\nFunctional tests result: %d/%d tests passed", func_passed, func_total))

  return all_passed and (func_passed == func_total)
end

return sha256
