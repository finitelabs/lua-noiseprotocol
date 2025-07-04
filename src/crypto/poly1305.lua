--- @module "crypto.poly1305"
--- Poly1305 Message Authentication Code (MAC) Implementation for portability.

local poly1305 = {}

local utils = require("utils")

-- Type definitions for better type checking

--- 17-element limb array for 130-bit + overflow
--- @alias Limb17Array [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- 33-element array for multiplication products
--- @alias Limb33Array [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- 16-element key array
--- @alias KeyArray [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- Helper function to process modular reduction for higher-order terms
---
--- Reduces coefficients of 2^k where k >= 130 using the identity:
--- 2^130 ≡ 5 (mod 2^130 - 5)
---
--- @param prod Limb33Array Product array to reduce
--- @param start_pos integer Starting position to reduce from
--- @param end_pos integer Ending position to reduce to
local function reduce_high_order_terms(prod, start_pos, end_pos)
  for i = start_pos, end_pos, -1 do
    if prod[i] > 0 then
      local bit_pos = 8 * (i - 1)
      local excess_bits = bit_pos - 130
      local reduction_multiplier = 5

      -- Calculate target byte position for the reduction
      local target_byte = 1 + math.floor(excess_bits / 8)
      local bit_offset = excess_bits % 8

      if bit_offset > 0 then
        reduction_multiplier = math.floor(reduction_multiplier * math.pow(2, bit_offset))
      end

      -- Add reduced value to target position
      if target_byte <= 17 then
        prod[target_byte] = prod[target_byte] + prod[i] * reduction_multiplier
      end
      prod[i] = 0
    end
  end
end

--- Helper function to propagate carries in limb array
---
--- Normalizes a limb array by propagating carries from lower to higher positions.
--- Each limb is reduced modulo 256 (8-bit) with carries propagated forward.
---
--- @param h Limb17Array|Limb33Array Limb array to normalize (modified in place)
--- @return integer carry Final carry value
local function propagate_carries(h)
  local carry = 0
  for i = 1, 17 do
    assert(h[i] ~= nil, "Limb array must have at least 17 non-nil elements")
    carry = carry + h[i]
    h[i] = carry % 256
    carry = math.floor(carry / 256)
  end
  return carry
end

--- Helper function to handle final carry overflow
---
--- When carry propagation results in overflow beyond position 17,
--- this function applies the modular reduction: 2^136 ≡ 320 (mod 2^130 - 5)
---
--- @param h Limb17Array Limb array (modified in place)
--- @param carry integer Initial carry to process
local function handle_final_carry(h, carry)
  while carry > 0 do
    -- 2^136 = 2^6 * 2^130 ≡ 64 * 5 = 320 (mod 2^130 - 5)
    h[1] = h[1] + carry * 320

    carry = propagate_carries(h)
  end
end

--- Helper function to reduce limb 17 to valid range
---
--- Position 17 can only hold 2 bits (values 0-3) since we're working modulo 2^130.
--- Values >= 4 represent overflow that must be reduced.
---
--- @param h Limb17Array Limb array (modified in place)
local function reduce_position_17(h)
  while h[17] >= 4 do
    local high_bits = math.floor(h[17] / 4)
    h[17] = h[17] % 4

    -- high_bits represents coefficient of 2^130, so multiply by 5
    h[1] = h[1] + high_bits * 5

    local carry = propagate_carries(h)
    handle_final_carry(h, carry)
  end
end

--- Initialize a 17-element limb array with zeros
--- @return Limb17Array array Initialized array
local function create_limb17_array()
  local arr = {}
  for i = 1, 17 do
    arr[i] = 0
  end
  --- @cast arr Limb17Array
  return arr
end

--- Initialize a 33-element product array with zeros
--- @return Limb33Array array Initialized array
local function create_product_array()
  local arr = {}
  for i = 1, 33 do
    arr[i] = 0
  end
  --- @cast arr Limb33Array
  return arr
end

--- Initialize a 16-element key array
--- @param source integer[] Source array to copy from
--- @param offset integer Starting offset in source array
--- @return KeyArray array Initialized key array
local function create_key_array(source, offset)
  local arr = {}
  for i = 1, 16 do
    arr[i] = source[offset + i - 1]
  end
  --- @cast arr KeyArray
  return arr
end

--- Compute Poly1305 MAC for given key and message
---
--- This function implements the complete Poly1305 algorithm:
--- 1. Key setup with RFC 7539 clamping
--- 2. Message processing in 16-byte blocks with padding
--- 3. Modular arithmetic over the field 2^130 - 5
--- 4. Final reduction and output formatting
---
--- @param key string 32-byte key (r || s)
--- @param msg string Message to authenticate (any length)
--- @return string mac 16-byte authentication tag
--- @error Throws assertion error if key is not exactly 32 bytes
function poly1305.authenticate(key, msg)
  assert(#key == 32, "Key must be exactly 32 bytes")

  -- Convert key to byte array for easier manipulation
  --- @type integer[]
  local key_bytes = {}
  for i = 1, #key do
    key_bytes[i] = string.byte(key, i)
  end

  -- Extract and clamp r (first 16 bytes) per RFC 7539
  local r = create_key_array(key_bytes, 1)

  -- Apply RFC 7539 clamping to ensure r has specific bit patterns
  -- This prevents certain classes of attacks and ensures key validity
  r[4] = utils.band32(r[4], 15) -- Clear top 4 bits of 4th byte
  r[5] = utils.band32(r[5], 252) -- Clear bottom 2 bits of 5th byte
  r[8] = utils.band32(r[8], 15) -- Clear top 4 bits of 8th byte
  r[9] = utils.band32(r[9], 252) -- Clear bottom 2 bits of 9th byte
  r[12] = utils.band32(r[12], 15) -- Clear top 4 bits of 12th byte
  r[13] = utils.band32(r[13], 252) -- Clear bottom 2 bits of 13th byte
  r[16] = utils.band32(r[16], 15) -- Clear top 4 bits of 16th byte

  -- Extract s (second 16 bytes) - used for final addition
  local s = create_key_array(key_bytes, 17)

  -- Initialize accumulator h as 17-byte array (130-bit + 6 extra bits)
  local h = create_limb17_array()

  local msglen = #msg
  local offset = 1

  -- Process message in 16-byte blocks
  while msglen >= 16 do
    -- Load current 16-byte block
    local c = create_limb17_array()
    for i = 1, 16 do
      c[i] = string.byte(msg, offset + i - 1)
    end
    c[17] = 1 -- Add high bit (represents 2^128 for full blocks)

    -- Add message block to accumulator: h = h + c
    local carry = 0
    for i = 1, 17 do
      carry = carry + h[i] + c[i]
      h[i] = carry % 256
      carry = math.floor(carry / 256)
    end

    -- Multiply by r: h = (h * r) mod (2^130 - 5)

    -- Step 1: Compute full precision product h * r
    local prod = create_product_array()

    for i = 1, 17 do
      for j = 1, 16 do
        prod[i + j - 1] = prod[i + j - 1] + h[i] * r[j]
      end
    end

    -- Step 2: Reduce high-order terms (positions 18-33)
    reduce_high_order_terms(prod, 33, 18)

    -- Step 3: Propagate carries and normalize
    carry = propagate_carries(prod)
    for i = 1, 17 do
      h[i] = prod[i]
    end

    -- Step 4: Handle overflow carry
    handle_final_carry(h, carry)

    -- Step 5: Reduce position 17 to valid range
    reduce_position_17(h)

    offset = offset + 16
    msglen = msglen - 16
  end

  -- Process final partial block (if any)
  if msglen > 0 then
    local c = create_limb17_array()

    -- Load partial block
    for i = 1, msglen do
      c[i] = string.byte(msg, offset + i - 1)
    end
    c[msglen + 1] = 1 -- Add padding bit at end of message

    -- Same operations as full blocks
    local carry = 0
    for i = 1, 17 do
      carry = carry + h[i] + c[i]
      h[i] = carry % 256
      carry = math.floor(carry / 256)
    end

    -- Multiply by r
    local prod = create_product_array()

    for i = 1, 17 do
      for j = 1, 16 do
        prod[i + j - 1] = prod[i + j - 1] + h[i] * r[j]
      end
    end

    reduce_high_order_terms(prod, 33, 18)

    carry = propagate_carries(prod)
    for i = 1, 17 do
      h[i] = prod[i]
    end

    handle_final_carry(h, carry)
    reduce_position_17(h)
  end

  -- Final reduction: conditionally subtract (2^130 - 5) if h >= 2^130 - 5
  -- This ensures the result is in canonical form

  local g = create_limb17_array()
  for i = 1, 17 do
    g[i] = h[i]
  end

  -- Test reduction by computing h + 5
  g[1] = g[1] + 5
  local carry = math.floor(g[1] / 256)
  g[1] = g[1] % 256

  for i = 2, 17 do
    if carry == 0 then
      break
    end
    carry = carry + g[i]
    g[i] = carry % 256
    carry = math.floor(carry / 256)
  end

  -- Use mask-based selection for constant-time operation
  -- If g[17] >= 4, then h + 5 overflowed the 130-bit boundary,
  -- meaning h >= 2^130 - 5, so we use the reduced value g
  local use_g = (g[17] >= 4) and 1 or 0
  for i = 1, 17 do
    h[i] = (h[i] * (1 - use_g)) + (g[i] * use_g)
  end

  -- Add s and create final 16-byte result
  local result = ""
  carry = 0
  for i = 1, 16 do
    local sum = h[i] + s[i] + carry
    result = result .. string.char(sum % 256)
    carry = math.floor(sum / 256)
  end

  return result
end

--- Test vectors from RFC 8439, RFC 7539, and other reference implementations
local test_vectors = {
  {
    name = "RFC 8439 Test Vector #1 (all zeros)",
    key = string.rep("\0", 32),
    message = string.rep("\0", 64),
    expected = string.rep("\0", 16),
  },
  {
    name = "RFC 8439 Test Vector #2 (r=0, long message)",
    key = string.rep("\0", 16) .. utils.from_hex("36e5f6b5c5e06070f0efca96227a863e"),
    message = 'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to',
    expected = utils.from_hex("36e5f6b5c5e06070f0efca96227a863e"),
  },
  {
    name = "RFC 8439 Test Vector #3 (r!=0, s=0)",
    key = utils.from_hex("36e5f6b5c5e06070f0efca96227a863e") .. string.rep("\0", 16),
    message = 'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to',
    expected = utils.from_hex("f3477e7cd95417af89a6b8794c310cf0"),
  },
  {
    name = "Wrap test vector (tests modular reduction edge case)",
    key = utils.from_hex("0200000000000000000000000000000000000000000000000000000000000000"),
    message = string.rep(string.char(255), 16),
    expected = utils.from_hex("03000000000000000000000000000000"),
  },
  {
    name = "RFC 7539 test vector",
    key = utils.from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
    message = "Cryptographic Forum Research Group",
    expected = utils.from_hex("a8061dc1305136c6c22b8baf0c0127a9"),
  },
  {
    name = "NaCl test vector (tests complex multi-block processing)",
    key = utils.from_hex("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"),
    message = utils.from_hex("8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"),
    expected = utils.from_hex("f3ffc7703f9400e52a7dfb4b3d3305d9"),
  },
}

--- Run comprehensive self-test with all standard test vectors
---
--- This function validates the implementation against known test vectors
--- from RFCs and reference implementations. ALL tests must pass for the
--- implementation to be considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function poly1305.selftest()
  local function test_vectors_suite()
    print("Running Poly1305 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      local result = poly1305.authenticate(test.key, test.message)

      -- Convert results to hex for comparison display
      local result_hex = ""
      local expected_hex = ""

      for j = 1, #result do
        result_hex = result_hex .. string.format("%02x", string.byte(result, j))
      end

      for j = 1, #test.expected do
        expected_hex = expected_hex .. string.format("%02x", string.byte(test.expected, j))
      end

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)
        print("  Expected: " .. expected_hex)
        print("  Got:      " .. result_hex)
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running Poly1305 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Different keys produce different tags
    total = total + 1
    local key1 = string.rep(string.char(0x42), 32)
    local key2 = string.rep(string.char(0x43), 32)
    local message = "Test message for MAC verification"

    local tag1 = poly1305.authenticate(key1, message)
    local tag2 = poly1305.authenticate(key2, message)

    if tag1 ~= tag2 then
      print("  ✅ PASS: Different keys produce different tags")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different keys produce same tag")
    end

    -- Test 2: Different messages produce different tags
    total = total + 1
    local msg1 = "Message 1"
    local msg2 = "Message 2"

    local tag_msg1 = poly1305.authenticate(key1, msg1)
    local tag_msg2 = poly1305.authenticate(key1, msg2)

    if tag_msg1 ~= tag_msg2 then
      print("  ✅ PASS: Different messages produce different tags")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different messages produce same tag")
    end

    -- Test 3: Empty message handling
    total = total + 1
    local empty_tag = poly1305.authenticate(key1, "")

    if #empty_tag == 16 then
      print("  ✅ PASS: Empty message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty message tag length is not 16 bytes")
    end

    -- Test 4: Large message handling (multi-block)
    total = total + 1
    local large_msg = string.rep("A", 256) -- 16 full blocks
    local large_tag = poly1305.authenticate(key1, large_msg)

    if #large_tag == 16 then
      print("  ✅ PASS: Large message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Large message tag length is not 16 bytes")
    end

    -- Test 5: Partial block handling
    total = total + 1
    local partial_msg = string.rep("B", 33) -- 2 blocks + 1 byte
    local partial_tag = poly1305.authenticate(key1, partial_msg)

    if #partial_tag == 16 then
      print("  ✅ PASS: Partial block message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Partial block tag length is not 16 bytes")
    end

    -- Test 6: Deterministic MAC
    total = total + 1
    local tag_a = poly1305.authenticate(key1, message)
    local tag_b = poly1305.authenticate(key1, message)

    if tag_a == tag_b then
      print("  ✅ PASS: MAC is deterministic (same input = same output)")
      passed = passed + 1
    else
      print("  ❌ FAIL: MAC is not deterministic")
    end

    -- Test 7: Single byte change detection
    total = total + 1
    local original = "This is a test message"
    local modified = "This is a Test message" -- Changed 't' to 'T'

    local tag_orig = poly1305.authenticate(key1, original)
    local tag_mod = poly1305.authenticate(key1, modified)

    if tag_orig ~= tag_mod then
      print("  ✅ PASS: Single byte change produces different tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Single byte change not detected")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return poly1305
