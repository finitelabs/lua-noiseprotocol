--- @module "noiseprotocol.crypto.chacha20"
--- ChaCha20 Stream Cipher Implementation for portability.
--- @class noiseprotocol.crypto.chacha20
local chacha20 = {}

local bit32 = require("bitn").bit32

local openssl_wrapper = require("noiseprotocol.openssl_wrapper")
local utils = require("noiseprotocol.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local bit32_raw_add = bit32.raw_add
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_rol = bit32.raw_rol
local floor = math.floor
local min = math.min
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local table_concat = table.concat

-- Type definitions for better type checking

--- 16-element array of 32-bit words
--- @class Word32Array
--- @field [1] integer
--- @field [2] integer
--- @field [3] integer
--- @field [4] integer
--- @field [5] integer
--- @field [6] integer
--- @field [7] integer
--- @field [8] integer
--- @field [9] integer
--- @field [10] integer
--- @field [11] integer
--- @field [12] integer
--- @field [13] integer
--- @field [14] integer
--- @field [15] integer
--- @field [16] integer

--- Initialize a 16-element word array with zeros
--- @return Word32Array array Initialized array
local function create_word_array()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  --- @cast arr Word32Array
  return arr
end

-- Pre-allocated arrays for chacha20_block() to avoid repeated allocation
local block_state = create_word_array()
local block_working = create_word_array()

--- Convert 32-bit word to 4 bytes (little-endian)
--- @param word integer 32-bit word
--- @return integer, integer, integer, integer bytes Four bytes in little-endian order
local function word_to_bytes(word)
  local byte1 = word % 256
  word = floor(word * 0.00390625) -- / 256
  local byte2 = word % 256
  word = floor(word * 0.00390625)
  local byte3 = word % 256
  word = floor(word * 0.00390625)
  local byte4 = word % 256

  return byte1, byte2, byte3, byte4
end

--- Convert 4 bytes to 32-bit word (little-endian)
--- @param byte1 integer First byte (least significant)
--- @param byte2 integer Second byte
--- @param byte3 integer Third byte
--- @param byte4 integer Fourth byte (most significant)
--- @return integer word 32-bit word
local function bytes_to_word(byte1, byte2, byte3, byte4)
  return byte1 + byte2 * 256 + byte3 * 65536 + byte4 * 16777216
end

--- ChaCha20 quarter round operation
--- @param state Word32Array 16-word state array (modified in place)
--- @param a integer Index of first word
--- @param b integer Index of second word
--- @param c integer Index of third word
--- @param d integer Index of fourth word
local function quarter_round(state, a, b, c, d)
  state[a] = bit32_raw_add(state[a], state[b])
  state[d] = bit32_raw_rol(bit32_raw_bxor(state[d], state[a]), 16)

  state[c] = bit32_raw_add(state[c], state[d])
  state[b] = bit32_raw_rol(bit32_raw_bxor(state[b], state[c]), 12)

  state[a] = bit32_raw_add(state[a], state[b])
  state[d] = bit32_raw_rol(bit32_raw_bxor(state[d], state[a]), 8)

  state[c] = bit32_raw_add(state[c], state[d])
  state[b] = bit32_raw_rol(bit32_raw_bxor(state[b], state[c]), 7)
end

--- Generate one 64-byte block of ChaCha20 keystream
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param counter integer 32-bit counter value
--- @return string keystream 64-byte keystream block
local function chacha20_block(key, nonce, counter)
  -- Reuse pre-allocated arrays
  local state = block_state
  local working_state = block_working

  -- Initialize state inline (avoiding function call overhead)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(counter >= 0 and counter < 0x100000000, "Counter must be a valid 32-bit integer")

  -- ChaCha20 constants "expand 32-byte k"
  state[1] = 0x61707865 -- "expa"
  state[2] = 0x3320646e -- "nd 3"
  state[3] = 0x79622d32 -- "2-by"
  state[4] = 0x6b206574 -- "te k"

  -- 256-bit key (8 words)
  for i = 1, 8 do
    local base = (i - 1) * 4
    state[4 + i] = bytes_to_word(
      string_byte(key, base + 1),
      string_byte(key, base + 2),
      string_byte(key, base + 3),
      string_byte(key, base + 4)
    )
  end

  -- 32-bit counter
  state[13] = counter

  -- 96-bit nonce (3 words)
  for i = 1, 3 do
    local base = (i - 1) * 4
    state[13 + i] = bytes_to_word(
      string_byte(nonce, base + 1),
      string_byte(nonce, base + 2),
      string_byte(nonce, base + 3),
      string_byte(nonce, base + 4)
    )
  end

  -- Create working copy of state
  for i = 1, 16 do
    working_state[i] = state[i]
  end

  -- Perform 20 rounds (10 double rounds)
  for _ = 1, 10 do
    -- Column rounds
    quarter_round(working_state, 1, 5, 9, 13)
    quarter_round(working_state, 2, 6, 10, 14)
    quarter_round(working_state, 3, 7, 11, 15)
    quarter_round(working_state, 4, 8, 12, 16)

    -- Diagonal rounds
    quarter_round(working_state, 1, 6, 11, 16)
    quarter_round(working_state, 2, 7, 12, 13)
    quarter_round(working_state, 3, 8, 9, 14)
    quarter_round(working_state, 4, 5, 10, 15)
  end

  -- Add original state to working state
  for i = 1, 16 do
    working_state[i] = bit32_raw_add(working_state[i], state[i])
  end

  -- Convert state to byte string (little-endian) - optimized with local references
  local result_bytes = {}
  for i = 1, 16 do
    local b1, b2, b3, b4 = word_to_bytes(working_state[i])
    result_bytes[i] = string_char(b1, b2, b3, b4)
  end

  return table_concat(result_bytes)
end

--- ChaCha20 encryption/decryption (same operation)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param plaintext string Data to encrypt/decrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string ciphertext Encrypted/decrypted data
function chacha20.crypt(key, nonce, plaintext, counter)
  counter = counter or 1

  local result_bytes = {}
  local result_idx = 1
  local offset = 1
  local data_len = #plaintext

  while offset <= data_len do
    -- Generate keystream block
    local keystream = chacha20_block(key, nonce, counter)

    -- XOR with plaintext (optimized with local references)
    local block_size = min(64, data_len - offset + 1)
    for i = 1, block_size do
      local plaintext_byte = string_byte(plaintext, offset + i - 1)
      local keystream_byte = string_byte(keystream, i)
      result_bytes[result_idx] = string_char(bit32_raw_bxor(plaintext_byte, keystream_byte))
      result_idx = result_idx + 1
    end

    offset = offset + 64
    counter = counter + 1
  end

  return table_concat(result_bytes)
end

--- Convenience function for encryption (same as crypt)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param plaintext string Data to encrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string ciphertext Encrypted data
function chacha20.encrypt(key, nonce, plaintext, counter)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl and #plaintext > 0 then
    -- Prepend 32-bit counter to 96-bit nonce for complete 128-bit nonce
    nonce = bytes.u32_to_le_bytes(counter or 1) .. nonce
    return openssl.cipher.encrypt("chacha20", plaintext, key, nonce)
  end
  return chacha20.crypt(key, nonce, plaintext, counter)
end

--- Convenience function for decryption (same as crypt)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param ciphertext string Data to decrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string plaintext Decrypted data
function chacha20.decrypt(key, nonce, ciphertext, counter)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl and #ciphertext > 0 then
    -- Prepend 32-bit counter to 96-bit nonce for complete 128-bit nonce
    nonce = bytes.u32_to_le_bytes(counter or 1) .. nonce
    return openssl.cipher.decrypt("chacha20", ciphertext, key, nonce)
  end
  return chacha20.crypt(key, nonce, ciphertext, counter)
end

--- Test vectors from RFC 8439
local test_vectors = {
  {
    name = "RFC 8439 Test Vector 1 - ChaCha20 Block Function",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    nonce = bytes.from_hex("000000090000004a00000000"),
    counter = 1,
    plaintext = "", -- Empty for block function test
    expected_keystream = bytes.from_hex(
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    ),
  },
  {
    name = "RFC 8439 Test Vector 2 - ChaCha20 Encryption",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    nonce = bytes.from_hex("000000000000004a00000000"),
    counter = 1,
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    expected_ciphertext = bytes.from_hex(
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
    ),
  },
  {
    name = "RFC 8439 Test Vector 3 - Key and IV setup",
    key = bytes.from_hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
    nonce = bytes.from_hex("000000000000000000000002"),
    counter = 42,
    plaintext = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.",
    expected_ciphertext = bytes.from_hex(
      "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
    ),
  },
  {
    name = "Zero key test",
    key = string_rep("\0", 32),
    nonce = string_rep("\0", 12),
    counter = 0,
    plaintext = string_rep("\0", 64),
    expected_ciphertext = bytes.from_hex(
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    ),
  },
}

--- Run comprehensive self-test with all standard test vectors
---
--- This function validates the implementation against known test vectors
--- from RFC 8439. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function chacha20.selftest()
  local function test_vectors_suite()
    print("Running ChaCha20 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))
      if test.expected_keystream then
        assert(
          test.expected_ciphertext == nil,
          "Test vector cannot have both expected_keystream and expected_ciphertext"
        )
        -- Test keystream generation
        local keystream = chacha20_block(test.key, test.nonce, test.counter)

        if keystream == test.expected_keystream then
          print("  ✅ PASS: " .. test.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. test.name)
          print("  Expected keystream length:", #test.expected_keystream)
          print("  Got keystream length:     ", #keystream)

          -- Show first few bytes for debugging
          local expected_hex = ""
          local result_hex = ""
          local show_bytes = min(16, #test.expected_keystream)

          for j = 1, show_bytes do
            expected_hex = expected_hex .. string.format("%02x", string_byte(assert(test.expected_keystream), j))
            result_hex = result_hex .. string.format("%02x", string_byte(keystream, j))
          end

          print("  Expected (first " .. show_bytes .. " bytes): " .. expected_hex)
          print("  Got (first " .. show_bytes .. " bytes):      " .. result_hex)
        end
      elseif test.expected_ciphertext then
        assert(
          test.expected_keystream == nil,
          "Test vector cannot have both expected_keystream and expected_ciphertext"
        )
        -- Test encryption
        local result = chacha20.crypt(test.key, test.nonce, test.plaintext, test.counter)

        if result == test.expected_ciphertext then
          print("  ✅ PASS: " .. test.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. test.name)
          print("  Expected ciphertext length:", #test.expected_ciphertext)
          print("  Got ciphertext length:     ", #result)

          -- Show first few bytes for debugging
          local expected_hex = ""
          local result_hex = ""
          local show_bytes = min(16, #test.expected_ciphertext)

          for j = 1, show_bytes do
            expected_hex = expected_hex .. string.format("%02x", string_byte(assert(test.expected_ciphertext), j))
            result_hex = result_hex .. string.format("%02x", string_byte(result, j))
          end

          print("  Expected (first " .. show_bytes .. " bytes): " .. expected_hex)
          print("  Got (first " .. show_bytes .. " bytes):      " .. result_hex)
        end
      else
        error("Test vector must have either expected_keystream or expected_ciphertext")
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running ChaCha20 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Basic encryption/decryption
    total = total + 1
    local key = string_rep(string_char(0x42), 32)
    local nonce = string_rep("\0", 12)
    local counter = 1
    local plaintext = "Hello, ChaCha20! This is a test message for encryption."

    local ciphertext = chacha20.encrypt(key, nonce, plaintext, counter)
    local decrypted = chacha20.decrypt(key, nonce, ciphertext, counter)

    if plaintext == decrypted then
      print("  ✅ PASS: Basic encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption")
    end

    -- Test 2: Encryption is deterministic
    total = total + 1
    local ciphertext2 = chacha20.encrypt(key, nonce, plaintext, counter)

    if ciphertext == ciphertext2 then
      print("  ✅ PASS: Encryption is deterministic")
      passed = passed + 1
    else
      print("  ❌ FAIL: Encryption is not deterministic")
    end

    -- Test 3: Different nonces produce different output
    total = total + 1
    local nonce2 = string_char(0x01) .. string_rep("\0", 11)
    local ciphertext3 = chacha20.encrypt(key, nonce2, plaintext, counter)

    if ciphertext ~= ciphertext3 then
      print("  ✅ PASS: Different nonces produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different nonces produce same ciphertext")
    end

    -- Test 4: Different counters produce different output
    total = total + 1
    local ciphertext4 = chacha20.encrypt(key, nonce, plaintext, 2)

    if ciphertext ~= ciphertext4 then
      print("  ✅ PASS: Different counters produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different counters produce same ciphertext")
    end

    -- Test 5: Empty plaintext
    total = total + 1
    local empty_ct = chacha20.encrypt(key, nonce, "", counter)
    local empty_pt = chacha20.decrypt(key, nonce, empty_ct, counter)

    if empty_pt == "" then
      print("  ✅ PASS: Empty plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty plaintext encryption/decryption")
    end

    -- Test 6: Large plaintext (multi-block)
    total = total + 1
    local large_plaintext = string_rep("A", 256) -- 4 blocks
    local large_ct = chacha20.encrypt(key, nonce, large_plaintext, counter)
    local large_pt = chacha20.decrypt(key, nonce, large_ct, counter)

    if large_pt == large_plaintext then
      print("  ✅ PASS: Multi-block encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Multi-block encryption/decryption")
    end

    -- Test 7: Partial block
    total = total + 1
    local partial_plaintext = string_rep("B", 100) -- Not a multiple of 64
    local partial_ct = chacha20.encrypt(key, nonce, partial_plaintext, counter)
    local partial_pt = chacha20.decrypt(key, nonce, partial_ct, counter)

    if partial_pt == partial_plaintext then
      print("  ✅ PASS: Partial block encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Partial block encryption/decryption")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for ChaCha20 operations
--- including block generation and stream encryption/decryption.
function chacha20.benchmark()
  -- Test data
  local key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  local nonce = bytes.from_hex("000000090000004a00000000")
  local plaintext_64 = string_rep("a", 64)
  local plaintext_1k = string_rep("a", 1024)
  local plaintext_8k = string_rep("a", 8192)

  print("Encryption Operations:")
  benchmark_op("encrypt_64_bytes", function()
    chacha20.encrypt(key, nonce, plaintext_64, 1)
  end, 1000)

  benchmark_op("encrypt_1k", function()
    chacha20.encrypt(key, nonce, plaintext_1k, 1)
  end, 200)

  benchmark_op("encrypt_8k", function()
    chacha20.encrypt(key, nonce, plaintext_8k, 1)
  end, 50)
end

return chacha20
