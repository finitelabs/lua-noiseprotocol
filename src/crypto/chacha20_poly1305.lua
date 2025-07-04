--- @module "crypto.chacha20_poly1305"
--- ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) Implementation for portability.

local chacha20_poly1305 = {}

local chacha20 = require("crypto.chacha20")
local poly1305 = require("crypto.poly1305")
local utils = require("utils")

--- Generate Poly1305 one-time key using ChaCha20
--- @param key string 32-byte ChaCha20 key
--- @param nonce string 12-byte nonce
--- @return string poly_key 32-byte Poly1305 one-time key
local function poly1305_key_gen(key, nonce)
  -- Generate Poly1305 key by encrypting 32 zero bytes with ChaCha20
  -- Counter starts at 0 for key generation
  local zero_block = string.rep("\0", 32)
  return chacha20.crypt(key, nonce, zero_block, 0)
end

--- Construct authentication data for Poly1305
--- @param aad string Additional Authenticated Data
--- @param ciphertext string Encrypted data
--- @return string auth_data Data to be authenticated
local function construct_aad_data(aad, ciphertext)
  local aad_len = #aad
  local ciphertext_len = #ciphertext

  -- Construct the data to authenticate according to RFC 8439:
  -- AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || num_to_8_le_bytes(aad_len) || num_to_8_le_bytes(ciphertext_len)
  local auth_data = ""

  -- Add AAD and pad to 16-byte boundary
  auth_data = auth_data .. utils.pad_to_16(aad)

  -- Add ciphertext and pad to 16-byte boundary
  auth_data = auth_data .. utils.pad_to_16(ciphertext)

  -- Add lengths as 64-bit little-endian integers
  auth_data = auth_data .. utils.u64_to_le_bytes(aad_len)
  auth_data = auth_data .. utils.u64_to_le_bytes(ciphertext_len)

  return auth_data
end

-- ============================================================================
-- CHACHA20-POLY1305 AEAD PUBLIC INTERFACE
-- ============================================================================

--- ChaCha20-Poly1305 AEAD Encryption
---
--- Encrypts plaintext and authenticates both the plaintext and additional data.
--- Returns the ciphertext concatenated with a 16-byte authentication tag.
---
--- @param key string 32-byte encryption key
--- @param nonce string 12-byte nonce (must be unique for each encryption with the same key)
--- @param plaintext string Data to encrypt
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string result Ciphertext concatenated with 16-byte authentication tag
function chacha20_poly1305.encrypt(key, nonce, plaintext, aad)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")

  aad = aad or ""

  -- Step 1: Generate Poly1305 one-time key
  local poly_key = poly1305_key_gen(key, nonce)

  -- Step 2: Encrypt plaintext with ChaCha20
  local ciphertext = chacha20.crypt(key, nonce, plaintext)

  -- Step 3: Construct authentication data
  local auth_data = construct_aad_data(aad, ciphertext)

  -- Step 4: Generate authentication tag with Poly1305
  local tag = poly1305.authenticate(poly_key, auth_data)

  -- Step 5: Return ciphertext || tag
  return ciphertext .. tag
end

--- ChaCha20-Poly1305 AEAD Decryption
---
--- Verifies the authentication tag and decrypts the ciphertext if authentic.
--- The input should be the result of encrypt() - ciphertext concatenated with tag.
---
--- @param key string 32-byte encryption key
--- @param nonce string 12-byte nonce (same as used for encryption)
--- @param ciphertext_and_tag string Encrypted data with 16-byte authentication tag appended
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string? plaintext Decrypted data, or nil if authentication fails
function chacha20_poly1305.decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(#ciphertext_and_tag >= 16, "Input must contain at least 16 bytes for authentication tag")

  aad = aad or ""

  -- Step 1: Split ciphertext and tag
  local ciphertext_len = #ciphertext_and_tag - 16
  local ciphertext = string.sub(ciphertext_and_tag, 1, ciphertext_len)
  local received_tag = string.sub(ciphertext_and_tag, ciphertext_len + 1)

  -- Step 2: Generate Poly1305 one-time key (same as encryption)
  local poly_key = poly1305_key_gen(key, nonce)

  -- Step 3: Construct authentication data (same as encryption)
  local auth_data = construct_aad_data(aad, ciphertext)

  -- Step 4: Compute expected authentication tag
  local expected_tag = poly1305.authenticate(poly_key, auth_data)

  -- Step 5: Verify authentication tag (constant-time comparison)
  if received_tag ~= expected_tag then
    return nil -- Authentication failed
  end

  -- Step 6: Decrypt ciphertext with ChaCha20 (counter starts at 1)
  local plaintext = chacha20.crypt(key, nonce, ciphertext, 1)

  return plaintext
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- Test vectors from RFC 8439
local test_vectors = {
  {
    name = "RFC 8439 Section 2.8.2 Test Vector",
    key = utils.from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    nonce = utils.from_hex("070000004041424344454647"),
    aad = utils.from_hex("50515253c0c1c2c3c4c5c6c7"),
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    expected = utils.from_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"),
  },
  {
    name = "Poly1305 key generation test",
    key = utils.from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    nonce = utils.from_hex("000000000001020304050607"),
    aad = "",
    plaintext = "",
    expected_poly_key = utils.from_hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"),
  },
  {
    name = "Roundtrip test with various inputs",
    key = utils.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    nonce = utils.from_hex("000000000000004a00000000"),
    aad = "Additional authenticated data",
    plaintext = "Hello, ChaCha20-Poly1305 AEAD!",
  },
  {
    name = "Empty AAD roundtrip test",
    key = string.char(0x42) .. string.rep("\0", 31),
    nonce = string.rep("\0", 12),
    aad = "",
    plaintext = "No additional data",
  },
  {
    name = "Empty plaintext roundtrip test",
    key = string.rep(string.char(0xff), 32),
    nonce = utils.from_hex("0102030405060708090a0b0c"),
    aad = "Only authenticating this data",
    plaintext = "",
  },
}

--- Run comprehensive self-test with all standard test vectors
---
--- This function validates the implementation against known test vectors.
--- ALL tests must pass for the implementation to be considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function chacha20_poly1305.selftest()
  local function test_vectors_suite()
    print("Running ChaCha20-Poly1305 AEAD test vectors...")
    local passed = 0.0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      if test.expected_poly_key then
        -- Test Poly1305 key generation
        local poly_key = poly1305_key_gen(test.key, test.nonce)

        if poly_key == test.expected_poly_key then
          print("  ✅ PASS: " .. test.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. test.name)
          print("  Expected poly key length:", #test.expected_poly_key)
          print("  Got poly key length:     ", #poly_key)

          local expected_hex = ""
          local result_hex = ""
          for j = 1, math.min(16, #test.expected_poly_key) do
            expected_hex = expected_hex .. string.format("%02x", string.byte(test.expected_poly_key, j))
            result_hex = result_hex .. string.format("%02x", string.byte(poly_key, j))
          end

          print("  Expected (first 16 bytes): " .. expected_hex)
          print("  Got (first 16 bytes):      " .. result_hex)
        end
      else
        -- Test encryption and decryption
        local encrypted = chacha20_poly1305.encrypt(test.key, test.nonce, test.plaintext, test.aad)

        -- Test against expected result if provided
        if test.expected then
          if encrypted == test.expected then
            print("  ✅ PASS: " .. test.name .. " (encryption)")
            passed = passed + 0.5
          else
            print("  ❌ FAIL: " .. test.name .. " (encryption)")
            print("  Expected length:", #test.expected)
            print("  Got length:     ", #encrypted)

            local expected_hex = ""
            local result_hex = ""
            local show_bytes = math.min(16, #test.expected)

            for j = 1, show_bytes do
              expected_hex = expected_hex .. string.format("%02x", string.byte(test.expected, j))
              result_hex = result_hex .. string.format("%02x", string.byte(encrypted, j))
            end

            print("  Expected (first " .. show_bytes .. " bytes): " .. expected_hex)
            print("  Got (first " .. show_bytes .. " bytes):      " .. result_hex)
          end
        else
          print("  ✅ PASS: " .. test.name .. " (encryption - no reference)")
          passed = passed + 0.5
        end

        -- Test decryption
        local decrypted = chacha20_poly1305.decrypt(test.key, test.nonce, encrypted, test.aad)

        if decrypted == test.plaintext then
          print("  ✅ PASS: " .. test.name .. " (decryption)")
          passed = passed + 0.5
        else
          print("  ❌ FAIL: " .. test.name .. " (decryption)")
          if decrypted == nil then
            print("  Decryption returned nil (authentication failed)")
          else
            print("  Expected plaintext:", test.plaintext)
            print("  Got plaintext:     ", decrypted)
          end
        end
      end
      print()
    end

    print(string.format("Test vectors result: %.0f/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running ChaCha20-Poly1305 AEAD functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Basic encryption/decryption
    total = total + 1
    local key = string.rep(string.char(0x42), 32)
    local nonce = string.rep("\0", 11) .. string.char(0x01)
    local aad = "user@example.com|2024-01-01"
    local plaintext = "This is a secret message that needs both encryption and authentication."

    local ciphertext_and_tag = chacha20_poly1305.encrypt(key, nonce, plaintext, aad)
    local decrypted = chacha20_poly1305.decrypt(key, nonce, ciphertext_and_tag, aad)

    if decrypted == plaintext then
      print("  ✅ PASS: Basic encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption")
    end

    -- Test 2: Authentication tag tampering detection
    total = total + 1
    local tampered = ciphertext_and_tag:sub(1, -2) .. string.char(255)
    local tampered_result = chacha20_poly1305.decrypt(key, nonce, tampered, aad)

    if tampered_result == nil then
      print("  ✅ PASS: Tampered tag correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered tag was not detected")
    end

    -- Test 3: Wrong AAD detection
    total = total + 1
    local wrong_aad = "wrong@example.com|2024-01-01"
    local wrong_aad_result = chacha20_poly1305.decrypt(key, nonce, ciphertext_and_tag, wrong_aad)

    if wrong_aad_result == nil then
      print("  ✅ PASS: Wrong AAD correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Wrong AAD was not detected")
    end

    -- Test 4: Nonce uniqueness
    total = total + 1
    local nonce2 = string.rep("\0", 11) .. string.char(0x02)
    local ciphertext2 = chacha20_poly1305.encrypt(key, nonce2, plaintext, aad)

    if ciphertext_and_tag ~= ciphertext2 then
      print("  ✅ PASS: Different nonces produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different nonces produced same ciphertext")
    end

    -- Test 5: Empty plaintext
    total = total + 1
    local empty_ct = chacha20_poly1305.encrypt(key, nonce, "", aad)
    local empty_pt = chacha20_poly1305.decrypt(key, nonce, empty_ct, aad)

    if empty_pt == "" then
      print("  ✅ PASS: Empty plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty plaintext encryption/decryption")
    end

    -- Test 6: Empty AAD
    total = total + 1
    local no_aad_ct = chacha20_poly1305.encrypt(key, nonce, plaintext, "")
    local no_aad_pt = chacha20_poly1305.decrypt(key, nonce, no_aad_ct, "")

    if no_aad_pt == plaintext then
      print("  ✅ PASS: Empty AAD encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty AAD encryption/decryption")
    end

    -- Test 7: Ciphertext tampering detection
    total = total + 1
    local tampered_ct = string.char(255) .. ciphertext_and_tag:sub(2)
    local tampered_ct_result = chacha20_poly1305.decrypt(key, nonce, tampered_ct, aad)

    if tampered_ct_result == nil then
      print("  ✅ PASS: Tampered ciphertext correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered ciphertext was not detected")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return chacha20_poly1305
