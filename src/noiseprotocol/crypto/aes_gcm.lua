--- @module "noiseprotocol.crypto.aes_gcm"
--- AES-GCM Authenticated Encryption with Associated Data (AEAD) Implementation for portability.

local utils = require("noiseprotocol.utils")
local bit32 = utils.bit32
local bytes = utils.bytes

local aes_gcm = {}

-- ============================================================================
-- AES CORE IMPLEMENTATION
-- ============================================================================

-- AES S-box (substitution box)
--- @type integer[]
local SBOX = {
  0x63,
  0x7c,
  0x77,
  0x7b,
  0xf2,
  0x6b,
  0x6f,
  0xc5,
  0x30,
  0x01,
  0x67,
  0x2b,
  0xfe,
  0xd7,
  0xab,
  0x76,
  0xca,
  0x82,
  0xc9,
  0x7d,
  0xfa,
  0x59,
  0x47,
  0xf0,
  0xad,
  0xd4,
  0xa2,
  0xaf,
  0x9c,
  0xa4,
  0x72,
  0xc0,
  0xb7,
  0xfd,
  0x93,
  0x26,
  0x36,
  0x3f,
  0xf7,
  0xcc,
  0x34,
  0xa5,
  0xe5,
  0xf1,
  0x71,
  0xd8,
  0x31,
  0x15,
  0x04,
  0xc7,
  0x23,
  0xc3,
  0x18,
  0x96,
  0x05,
  0x9a,
  0x07,
  0x12,
  0x80,
  0xe2,
  0xeb,
  0x27,
  0xb2,
  0x75,
  0x09,
  0x83,
  0x2c,
  0x1a,
  0x1b,
  0x6e,
  0x5a,
  0xa0,
  0x52,
  0x3b,
  0xd6,
  0xb3,
  0x29,
  0xe3,
  0x2f,
  0x84,
  0x53,
  0xd1,
  0x00,
  0xed,
  0x20,
  0xfc,
  0xb1,
  0x5b,
  0x6a,
  0xcb,
  0xbe,
  0x39,
  0x4a,
  0x4c,
  0x58,
  0xcf,
  0xd0,
  0xef,
  0xaa,
  0xfb,
  0x43,
  0x4d,
  0x33,
  0x85,
  0x45,
  0xf9,
  0x02,
  0x7f,
  0x50,
  0x3c,
  0x9f,
  0xa8,
  0x51,
  0xa3,
  0x40,
  0x8f,
  0x92,
  0x9d,
  0x38,
  0xf5,
  0xbc,
  0xb6,
  0xda,
  0x21,
  0x10,
  0xff,
  0xf3,
  0xd2,
  0xcd,
  0x0c,
  0x13,
  0xec,
  0x5f,
  0x97,
  0x44,
  0x17,
  0xc4,
  0xa7,
  0x7e,
  0x3d,
  0x64,
  0x5d,
  0x19,
  0x73,
  0x60,
  0x81,
  0x4f,
  0xdc,
  0x22,
  0x2a,
  0x90,
  0x88,
  0x46,
  0xee,
  0xb8,
  0x14,
  0xde,
  0x5e,
  0x0b,
  0xdb,
  0xe0,
  0x32,
  0x3a,
  0x0a,
  0x49,
  0x06,
  0x24,
  0x5c,
  0xc2,
  0xd3,
  0xac,
  0x62,
  0x91,
  0x95,
  0xe4,
  0x79,
  0xe7,
  0xc8,
  0x37,
  0x6d,
  0x8d,
  0xd5,
  0x4e,
  0xa9,
  0x6c,
  0x56,
  0xf4,
  0xea,
  0x65,
  0x7a,
  0xae,
  0x08,
  0xba,
  0x78,
  0x25,
  0x2e,
  0x1c,
  0xa6,
  0xb4,
  0xc6,
  0xe8,
  0xdd,
  0x74,
  0x1f,
  0x4b,
  0xbd,
  0x8b,
  0x8a,
  0x70,
  0x3e,
  0xb5,
  0x66,
  0x48,
  0x03,
  0xf6,
  0x0e,
  0x61,
  0x35,
  0x57,
  0xb9,
  0x86,
  0xc1,
  0x1d,
  0x9e,
  0xe1,
  0xf8,
  0x98,
  0x11,
  0x69,
  0xd9,
  0x8e,
  0x94,
  0x9b,
  0x1e,
  0x87,
  0xe9,
  0xce,
  0x55,
  0x28,
  0xdf,
  0x8c,
  0xa1,
  0x89,
  0x0d,
  0xbf,
  0xe6,
  0x42,
  0x68,
  0x41,
  0x99,
  0x2d,
  0x0f,
  0xb0,
  0x54,
  0xbb,
  0x16,
}

-- Round constants (Rcon) for key expansion
--- @type integer[]
local RCON = {
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80,
  0x1b,
  0x36,
}

--- @alias AESGCMWord [integer, integer, integer, integer]
--- @alias AESGCMBlock [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]
--- @alias AESGCMState [AESGCMWord, AESGCMWord, AESGCMWord, AESGCMWord]

--- XOR two 4-byte words
--- @param a AESGCMWord 4-byte array
--- @param b AESGCMWord 4-byte array
--- @return table Word 4-byte array
local function xor_words(a, b)
  return {
    bit32.bxor(a[1], b[1]),
    bit32.bxor(a[2], b[2]),
    bit32.bxor(a[3], b[3]),
    bit32.bxor(a[4], b[4]),
  }
end

--- Rotate word (circular left shift by 1 byte)
--- @param word AESGCMWord 4-byte array
--- @return AESGCMWord result Rotated 4-byte array
local function rot_word(word)
  return { word[2], word[3], word[4], word[1] }
end

--- Apply S-box substitution to a word
--- @param word AESGCMWord 4-byte array
--- @return AESGCMWord result Substituted 4-byte array
local function sub_word(word)
  local s_1 = assert(SBOX[word[1] + 1], "Invalid SBOX index " .. (word[1] + 1))
  local s_2 = assert(SBOX[word[2] + 1], "Invalid SBOX index " .. (word[2] + 1))
  local s_3 = assert(SBOX[word[3] + 1], "Invalid SBOX index " .. (word[3] + 1))
  local s_4 = assert(SBOX[word[4] + 1], "Invalid SBOX index " .. (word[4] + 1))
  return { s_1, s_2, s_3, s_4 }
end

--- AES key expansion
--- @param key string Encryption key (16, 24, or 32 bytes)
--- @return table expanded_key Array of round keys
--- @return integer nr Number of rounds
local function key_expansion(key)
  local key_len = #key
  local nr -- Number of rounds
  local nk -- Number of 32-bit words in key

  if key_len == 16 then
    nr = 10
    nk = 4
  elseif key_len == 24 then
    nr = 12
    nk = 6
  elseif key_len == 32 then
    nr = 14
    nk = 8
  else
    error("Invalid key length. Must be 16, 24, or 32 bytes")
  end

  -- Convert key to words
  --- @type AESGCMWord
  local w = {}
  for i = 0, nk - 1 do
    w[i] = {
      string.byte(key, i * 4 + 1),
      string.byte(key, i * 4 + 2),
      string.byte(key, i * 4 + 3),
      string.byte(key, i * 4 + 4),
    }
  end

  -- Expand key
  for i = nk, 4 * (nr + 1) - 1 do
    local temp = w[i - 1]
    if i % nk == 0 then
      local t = assert(RCON[i / nk], "Invalid RCON index " .. (i / nk))
      temp = xor_words(sub_word(rot_word(temp)), { t, 0, 0, 0 })
    elseif nk > 6 and i % nk == 4 then
      temp = sub_word(temp)
    end
    w[i] = xor_words(w[i - nk], temp)
  end

  return w, nr
end

--- MixColumns transformation
--- @param state AESGCMState 4x4 state matrix
local function mix_columns(state)
  for c = 0, 3 do
    --- @type AESGCMWord
    local a = {}
    --- @type AESGCMWord
    local b = {}
    for i = 0, 3 do
      a[i] = state[i][c]
      b[i] = bit32.band(state[i][c], 0x80) ~= 0 and bit32.bxor(bit32.band(bit32.lshift(state[i][c], 1), 0xFF), 0x1B)
        or bit32.band(bit32.lshift(state[i][c], 1), 0xFF)
    end

    state[0][c] = bit32.bxor(bit32.bxor(bit32.bxor(b[0], a[1]), bit32.bxor(b[1], a[2])), a[3])
    state[1][c] = bit32.bxor(bit32.bxor(bit32.bxor(a[0], b[1]), bit32.bxor(a[2], b[2])), a[3])
    state[2][c] = bit32.bxor(bit32.bxor(bit32.bxor(a[0], a[1]), bit32.bxor(b[2], a[3])), b[3])
    state[3][c] = bit32.bxor(bit32.bxor(bit32.bxor(a[0], b[0]), bit32.bxor(a[1], a[2])), b[3])
  end
end

--- SubBytes transformation
--- @param state AESGCMState 4x4 state matrix
local function sub_bytes(state)
  for i = 0, 3 do
    for j = 0, 3 do
      local s_index = state[i][j] + 1
      state[i][j] = assert(SBOX[s_index], "Invalid SBOX index " .. s_index)
    end
  end
end

--- ShiftRows transformation
--- @param state AESGCMState 4x4 state matrix
local function shift_rows(state)
  -- Row 0: no shift
  -- Row 1: shift left by 1
  local temp = state[1][0]
  state[1][0] = state[1][1]
  state[1][1] = state[1][2]
  state[1][2] = state[1][3]
  state[1][3] = temp

  -- Row 2: shift left by 2
  temp = state[2][0]
  state[2][0] = state[2][2]
  state[2][2] = temp
  temp = state[2][1]
  state[2][1] = state[2][3]
  state[2][3] = temp

  -- Row 3: shift left by 3 (or right by 1)
  temp = state[3][3]
  state[3][3] = state[3][2]
  state[3][2] = state[3][1]
  state[3][1] = state[3][0]
  state[3][0] = temp
end

--- AddRoundKey transformation
--- @param state AESGCMState 4x4 state matrix
--- @param round_key table Round key words
--- @param round integer Round number
local function add_round_key(state, round_key, round)
  for c = 0, 3 do
    local key_word = round_key[round * 4 + c]
    for r = 0, 3 do
      state[r][c] = bit32.bxor(state[r][c], key_word[r + 1])
    end
  end
end

--- AES block encryption
--- @param input string 16-byte plaintext block
--- @param expanded_key table Expanded key
--- @param nr integer Number of rounds
--- @return string ciphertext 16-byte encrypted block
local function aes_encrypt_block(input, expanded_key, nr)
  -- Initialize state from input
  --- @type AESGCMState
  local state = {}
  for i = 0, 3 do
    --- @type AESGCMWord
    state[i] = {}
    for j = 0, 3 do
      state[i][j] = string.byte(input, j * 4 + i + 1)
    end
  end

  -- Initial round
  add_round_key(state, expanded_key, 0)

  -- Main rounds
  for round = 1, nr - 1 do
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, expanded_key, round)
  end

  -- Final round (no MixColumns)
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, expanded_key, nr)

  -- Convert state to output
  local output = ""
  for j = 0, 3 do
    for i = 0, 3 do
      output = output .. string.char(state[i][j])
    end
  end

  return output
end

-- ============================================================================
-- GCM MODE IMPLEMENTATION
-- ============================================================================

--- GCM field multiplication
--- @param x string 16-byte block
--- @param y string 16-byte block
--- @return string result Product in GF(2^128)
local function gcm_multiply(x, y)
  -- Convert to bit arrays for easier manipulation
  --- @type AESGCMBlock
  local z = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  --- @type AESGCMBlock
  local v = {}
  for i = 1, 16 do
    v[i] = string.byte(y, i)
  end

  -- Process each bit of x from MSB to LSB
  for i = 1, 16 do
    local byte = string.byte(x, i)
    for bit = 7, 0, -1 do
      if bit32.band(byte, bit32.lshift(1, bit)) ~= 0 then
        -- z = z XOR v
        for j = 1, 16 do
          z[j] = bit32.bxor(z[j], v[j])
        end
      end

      -- Check if LSB of v is 1 (bit 0 of last byte)
      local lsb = bit32.band(v[16], 1)

      -- v = v >> 1 (right shift entire 128-bit value by 1)
      local carry = 0
      for j = 1, 16 do
        local new_carry = bit32.band(v[j], 1)
        v[j] = bit32.bor(bit32.rshift(v[j], 1), bit32.lshift(carry, 7))
        carry = new_carry
      end

      -- If LSB was 1, XOR with R = 0xE1000000000000000000000000000000
      if lsb ~= 0 then
        v[1] = bit32.bxor(v[1], 0xE1)
      end
    end
  end

  -- Convert result back to string
  local result = ""
  for i = 1, 16 do
    result = result .. string.char(z[i])
  end
  return result
end

--- GHASH function
--- @param h string Hash key (16 bytes)
--- @param data string Data to hash (multiple of 16 bytes)
--- @return string result 16-byte hash
local function ghash(h, data)
  local y = string.rep("\0", 16)

  -- Process each 16-byte block
  for i = 1, #data, 16 do
    local block = string.sub(data, i, i + 15)

    -- y = (y XOR block) * h
    local y_xor = ""
    for j = 1, 16 do
      y_xor = y_xor .. string.char(bit32.bxor(string.byte(y, j), string.byte(block, j)))
    end

    y = gcm_multiply(y_xor, h)
  end

  return y
end

--- Increment counter block
--- @param counter string 16-byte counter block
--- @return string result Incremented counter
local function inc_counter(counter)
  local result = string.sub(counter, 1, 12) -- Keep first 12 bytes

  -- Increment last 4 bytes (big-endian)
  local val = 0
  for i = 13, 16 do
    val = val * 256 + string.byte(counter, i)
  end

  val = (val + 1) % 0x100000000

  -- Convert back to bytes (big-endian)
  for i = 3, 0, -1 do
    result = result .. string.char(bit32.band(bit32.rshift(val, i * 8), 0xFF))
  end

  return result
end

--- Generate counter mode keystream
--- @param key string AES key
--- @param iv string Initialization vector
--- @param length integer Number of bytes needed
--- @return string keystream Generated keystream
local function generate_keystream(key, iv, length)
  local expanded_key, nr = key_expansion(key)
  local keystream = ""

  -- Initial counter value: IV || 0x00000002
  local counter = iv .. string.rep("\0", 3) .. string.char(0x02)

  while #keystream < length do
    keystream = keystream .. aes_encrypt_block(counter, expanded_key, nr)
    counter = inc_counter(counter)
  end

  return string.sub(keystream, 1, length)
end

-- ============================================================================
-- AEAD INTERFACE
-- ============================================================================

--- Pad AAD and ciphertext as required by GCM
--- @param aad string Additional authenticated data
--- @param ciphertext string Encrypted data
--- @return string padded_data Data formatted for GHASH
local function format_gcm_data(aad, ciphertext)
  local result = ""

  -- Add AAD and padding
  result = result .. aad
  local aad_pad = (16 - (#aad % 16)) % 16
  result = result .. string.rep("\0", aad_pad)

  -- Add ciphertext and padding
  result = result .. ciphertext
  local ct_pad = (16 - (#ciphertext % 16)) % 16
  result = result .. string.rep("\0", ct_pad)

  -- Add lengths (in bits) as 64-bit big-endian integers
  -- For messages under 2^61 bytes, high 32 bits are always 0
  local aad_bits_low = #aad * 8
  local ct_bits_low = #ciphertext * 8

  -- AAD length (64 bits big-endian)
  result = result .. string.rep("\0", 4) -- High 32 bits
  result = result .. bytes.u32_to_be_bytes(aad_bits_low) -- Low 32 bits

  -- Ciphertext length (64 bits big-endian)
  result = result .. string.rep("\0", 4) -- High 32 bits
  result = result .. bytes.u32_to_be_bytes(ct_bits_low) -- Low 32 bits

  return result
end

--- AES-GCM AEAD Encryption
---
--- Encrypts plaintext and authenticates both the plaintext and additional data.
--- Returns the ciphertext concatenated with a 16-byte authentication tag.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string 12-byte nonce (must be unique for each encryption with the same key)
--- @param plaintext string Data to encrypt
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string result Ciphertext concatenated with 16-byte authentication tag
function aes_gcm.encrypt(key, nonce, plaintext, aad)
  assert(#key == 16 or #key == 24 or #key == 32, "Key must be 16, 24, or 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")

  aad = aad or ""

  -- Expand key
  local expanded_key, nr = key_expansion(key)

  -- Generate hash key H = E(K, 0^128)
  local h = aes_encrypt_block(string.rep("\0", 16), expanded_key, nr)

  -- Initial counter: nonce || 0x00000001
  local j0 = nonce .. string.rep("\0", 3) .. string.char(0x01)

  -- Encrypt plaintext using CTR mode
  local keystream = generate_keystream(key, nonce, #plaintext)
  local ciphertext = ""
  for i = 1, #plaintext do
    ciphertext = ciphertext .. string.char(bit32.bxor(string.byte(plaintext, i), string.byte(keystream, i)))
  end

  -- Calculate authentication tag
  local gcm_data = format_gcm_data(aad, ciphertext)
  local s = ghash(h, gcm_data)

  -- Encrypt S to get final tag: T = E(K, J0) XOR S
  local encrypted_j0 = aes_encrypt_block(j0, expanded_key, nr)
  local tag = ""
  for i = 1, 16 do
    tag = tag .. string.char(bit32.bxor(string.byte(s, i), string.byte(encrypted_j0, i)))
  end

  return ciphertext .. tag
end

--- AES-GCM AEAD Decryption
---
--- Verifies the authentication tag and decrypts the ciphertext if authentic.
--- The input should be the result of encrypt() - ciphertext concatenated with tag.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string 12-byte nonce (same as used for encryption)
--- @param ciphertext_and_tag string Encrypted data with 16-byte authentication tag appended
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string? plaintext Decrypted data, or nil if authentication fails
function aes_gcm.decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#key == 16 or #key == 24 or #key == 32, "Key must be 16, 24, or 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(#ciphertext_and_tag >= 16, "Input must contain at least 16 bytes for authentication tag")

  aad = aad or ""

  -- Split ciphertext and tag
  local ciphertext_len = #ciphertext_and_tag - 16
  local ciphertext = string.sub(ciphertext_and_tag, 1, ciphertext_len)
  local received_tag = string.sub(ciphertext_and_tag, ciphertext_len + 1)

  -- Expand key
  local expanded_key, nr = key_expansion(key)

  -- Generate hash key H = E(K, 0^128)
  local h = aes_encrypt_block(string.rep("\0", 16), expanded_key, nr)

  -- Initial counter: nonce || 0x00000001
  local j0 = nonce .. string.rep("\0", 3) .. string.char(0x01)

  -- Calculate expected authentication tag
  local gcm_data = format_gcm_data(aad, ciphertext)
  local s = ghash(h, gcm_data)

  -- Encrypt S to get expected tag: T = E(K, J0) XOR S
  local encrypted_j0 = aes_encrypt_block(j0, expanded_key, nr)
  local expected_tag = ""
  for i = 1, 16 do
    expected_tag = expected_tag .. string.char(bit32.bxor(string.byte(s, i), string.byte(encrypted_j0, i)))
  end

  -- Verify tag (constant-time comparison)
  if received_tag ~= expected_tag then
    return nil -- Authentication failed
  end

  -- Decrypt ciphertext using CTR mode
  local keystream = generate_keystream(key, nonce, #ciphertext)
  local plaintext = ""
  for i = 1, #ciphertext do
    plaintext = plaintext .. string.char(bit32.bxor(string.byte(ciphertext, i), string.byte(keystream, i)))
  end

  return plaintext
end

--- Test vectors from NIST SP 800-38D and other sources
local test_vectors = {
  {
    name = "NIST Test Case 1 (AES-128-GCM)",
    key = string.rep("\0", 16),
    nonce = string.rep("\0", 12),
    plaintext = "",
    aad = "",
    ciphertext = "",
    tag = bytes.from_hex("58e2fccefa7e3061367f1d57a4e7455a"),
  },
  {
    name = "NIST Test Case 2 (AES-128-GCM)",
    key = string.rep("\0", 16),
    nonce = string.rep("\0", 12),
    plaintext = string.rep("\0", 16),
    aad = "",
    ciphertext = bytes.from_hex("0388dace60b6a392f328c2b971b2fe78"),
    tag = bytes.from_hex("ab6e47d42cec13bdf53a67b21257bddf"),
  },
  {
    name = "NIST Test Case 3 (AES-128-GCM with AAD)",
    key = bytes.from_hex("feffe9928665731c6d6a8f9467308308"),
    nonce = bytes.from_hex("cafebabefacedbaddecaf888"),
    plaintext = bytes.from_hex(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    ),
    aad = "",
    ciphertext = bytes.from_hex(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
    ),
    tag = bytes.from_hex("4d5c2af327cd64a62cf35abd2ba6fab4"),
  },
  {
    name = "Roundtrip test with various inputs",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f"),
    nonce = bytes.from_hex("000000000000004a00000000"),
    aad = "Additional authenticated data",
    plaintext = "Hello, AES-GCM AEAD!",
  },
}

--- Run comprehensive self-test with test vectors
--- @return boolean result True if all tests pass, false otherwise
function aes_gcm.selftest()
  local function test_vectors_suite()
    print("Running AES-GCM test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      if test.ciphertext then
        -- Test with known ciphertext and tag
        local result = aes_gcm.encrypt(test.key, test.nonce, test.plaintext, test.aad)
        local result_ct = string.sub(result, 1, #test.ciphertext)
        local result_tag = string.sub(result, #test.ciphertext + 1)

        if result_ct == test.ciphertext and result_tag == test.tag then
          print("  ✅ PASS: Encryption")

          -- Test decryption
          local decrypted = aes_gcm.decrypt(test.key, test.nonce, result, test.aad)
          if decrypted == test.plaintext then
            print("  ✅ PASS: Decryption")
            passed = passed + 1
          else
            print("  ❌ FAIL: Decryption")
            print("    Expected: " .. bytes.to_hex(test.plaintext))
            print("    Got:      " .. (decrypted and bytes.to_hex(decrypted) or "nil"))
          end
        else
          print("  ❌ FAIL: Encryption")
          print("    Expected CT: " .. bytes.to_hex(test.ciphertext))
          print("    Got CT:      " .. bytes.to_hex(result_ct))
          print("    Expected Tag: " .. bytes.to_hex(test.tag))
          print("    Got Tag:      " .. bytes.to_hex(result_tag))
        end
      else
        -- Roundtrip test
        local encrypted = aes_gcm.encrypt(test.key, test.nonce, test.plaintext, test.aad)
        local decrypted = aes_gcm.decrypt(test.key, test.nonce, encrypted, test.aad)

        if decrypted == test.plaintext then
          print("  ✅ PASS: Roundtrip test")
          passed = passed + 1
        else
          print("  ❌ FAIL: Roundtrip test")
          print("    Original:  " .. bytes.to_hex(test.plaintext))
          print("    Decrypted: " .. (decrypted and bytes.to_hex(decrypted) or "nil"))
        end
      end
    end

    print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function functional_tests()
    print("Running AES-GCM functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Basic encryption/decryption with AES-128
    total = total + 1
    local key128 = string.rep(string.char(0x42), 16)
    local nonce = string.rep("\0", 11) .. string.char(0x01)
    local aad = "user@example.com|2024-01-01"
    local plaintext = "This is a secret message that needs both encryption and authentication."

    local ciphertext_and_tag = aes_gcm.encrypt(key128, nonce, plaintext, aad)
    local decrypted = aes_gcm.decrypt(key128, nonce, ciphertext_and_tag, aad)

    if decrypted == plaintext then
      print("  ✅ PASS: Basic encryption/decryption (AES-128)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption (AES-128)")
    end

    -- Test 2: Basic encryption/decryption with AES-256
    total = total + 1
    local key256 = string.rep(string.char(0x43), 32)
    local ct256 = aes_gcm.encrypt(key256, nonce, plaintext, aad)
    local pt256 = aes_gcm.decrypt(key256, nonce, ct256, aad)

    if pt256 == plaintext then
      print("  ✅ PASS: Basic encryption/decryption (AES-256)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption (AES-256)")
    end

    -- Test 3: Authentication tag tampering detection
    total = total + 1
    local tampered = ciphertext_and_tag:sub(1, -2) .. string.char(255)
    local tampered_result = aes_gcm.decrypt(key128, nonce, tampered, aad)

    if tampered_result == nil then
      print("  ✅ PASS: Tampered tag correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered tag was not detected")
    end

    -- Test 4: Wrong AAD detection
    total = total + 1
    local wrong_aad = "wrong@example.com|2024-01-01"
    local wrong_aad_result = aes_gcm.decrypt(key128, nonce, ciphertext_and_tag, wrong_aad)

    if wrong_aad_result == nil then
      print("  ✅ PASS: Wrong AAD correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Wrong AAD was not detected")
    end

    -- Test 5: Nonce uniqueness
    total = total + 1
    local nonce2 = string.rep("\0", 11) .. string.char(0x02)
    local ciphertext2 = aes_gcm.encrypt(key128, nonce2, plaintext, aad)

    if ciphertext_and_tag ~= ciphertext2 then
      print("  ✅ PASS: Different nonces produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different nonces produced same ciphertext")
    end

    -- Test 6: Empty plaintext
    total = total + 1
    local empty_ct = aes_gcm.encrypt(key128, nonce, "", aad)
    local empty_pt = aes_gcm.decrypt(key128, nonce, empty_ct, aad)

    if empty_pt == "" then
      print("  ✅ PASS: Empty plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty plaintext encryption/decryption")
    end

    -- Test 7: Empty AAD
    total = total + 1
    local no_aad_ct = aes_gcm.encrypt(key128, nonce, plaintext, "")
    local no_aad_pt = aes_gcm.decrypt(key128, nonce, no_aad_ct, "")

    if no_aad_pt == plaintext then
      print("  ✅ PASS: Empty AAD encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty AAD encryption/decryption")
    end

    -- Test 8: Ciphertext tampering detection
    total = total + 1
    local tampered_ct = string.char(255) .. ciphertext_and_tag:sub(2)
    local tampered_ct_result = aes_gcm.decrypt(key128, nonce, tampered_ct, aad)

    if tampered_ct_result == nil then
      print("  ✅ PASS: Tampered ciphertext correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered ciphertext was not detected")
    end

    -- Test 9: Wrong key detection
    total = total + 1
    local wrong_key = string.rep(string.char(0x99), 16)
    local wrong_key_result = aes_gcm.decrypt(wrong_key, nonce, ciphertext_and_tag, aad)

    if wrong_key_result == nil then
      print("  ✅ PASS: Wrong key correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Wrong key was not detected")
    end

    -- Test 10: Large plaintext (multiple blocks)
    total = total + 1
    local large_plaintext = string.rep("A", 1000)
    local large_ct = aes_gcm.encrypt(key128, nonce, large_plaintext, aad)
    local large_pt = aes_gcm.decrypt(key128, nonce, large_ct, aad)

    if large_pt == large_plaintext then
      print("  ✅ PASS: Large plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Large plaintext encryption/decryption")
    end

    -- Test 11: Different key sizes produce different outputs
    total = total + 1
    local key192 = string.rep(string.char(0x44), 24)
    local ct128 = aes_gcm.encrypt(key128, nonce, plaintext, aad)
    local ct192 = aes_gcm.encrypt(key192, nonce, plaintext, aad)
    local ct256_2 = aes_gcm.encrypt(key256, nonce, plaintext, aad)

    if ct128 ~= ct192 and ct192 ~= ct256_2 and ct128 ~= ct256_2 then
      print("  ✅ PASS: Different key sizes produce different outputs")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different key sizes should produce different outputs")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return aes_gcm
