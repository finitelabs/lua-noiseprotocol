--- @module "noiseprotocol.crypto.x448"
--- X448 Curve448 Elliptic Curve Diffie-Hellman Implementation
---
--- This module implements X448 key exchange as specified in RFC 7748.
--- It uses 8-bit limbs for portability and compatibility with systems
--- that have limited integer precision (e.g., Lua's 53-bit integers).
---
--- The implementation follows the Montgomery ladder algorithm and includes:
--- - Field arithmetic modulo p = 2^448 - 2^224 - 1
--- - Scalar multiplication on Curve448
--- - Key generation and Diffie-Hellman operations
local x448 = {}

local utils = require("noiseprotocol.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op
local band = utils.bit32.band
local bor = utils.bit32.bor
local bxor = utils.bit32.bxor
local rshift = utils.bit32.rshift
local floor = math.floor
local char = string.char
local byte = string.byte

-- Constants for X448 implementation
-- Field prime p = 2^448 - 2^224 - 1 (Goldilocks prime)
-- We use 56 limbs of 8 bits each (56 * 8 = 448 bits)
local LIMB_MASK = 0xFF -- 2^8 - 1 (mask for 8-bit limbs)
local NUM_LIMBS = 56 -- Number of 8-bit limbs for 448 bits
local A24 = 39081 -- Montgomery curve constant (A-2)/4 where A = 156326

--- Create a new field element initialized to zero
--- @return table fe Field element (56 limbs)
local function fe_zero()
  local r = {}
  for i = 1, NUM_LIMBS do
    r[i] = 0
  end
  return r
end

--- Create a new field element initialized to one
--- @return table fe Field element (56 limbs)
local function fe_one()
  local r = fe_zero()
  r[1] = 1
  return r
end

--- Copy a field element
--- @param a table Source field element
--- @return table fe New field element
local function fe_copy(a)
  local r = {}
  for i = 1, NUM_LIMBS do
    r[i] = a[i] or 0
  end
  return r
end

--- Reduce coefficients and propagate carries
--- @param a table Field element to reduce (modified in place)
local function fe_reduce(a)
  -- First, normalize all limbs and collect carries
  local carry = 0
  for i = 1, NUM_LIMBS do
    carry = carry + (a[i] or 0)
    a[i] = band(carry, LIMB_MASK)
    carry = floor(carry / 256)
  end

  -- Handle overflow: 2^448 ≡ 2^224 + 1 (mod p)
  while carry > 0 do
    a[1] = a[1] + carry
    a[29] = a[29] + carry -- Position 224 is limb 28+1 = 29

    -- Propagate carries again
    local new_carry = 0
    for i = 1, NUM_LIMBS do
      new_carry = new_carry + a[i]
      a[i] = band(new_carry, LIMB_MASK)
      new_carry = floor(new_carry / 256)
    end
    carry = new_carry
  end
end

--- Add two field elements
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_add(a, b)
  local r = {}
  for i = 1, NUM_LIMBS do
    r[i] = (a[i] or 0) + (b[i] or 0)
  end
  fe_reduce(r)
  return r
end

--- Subtract two field elements
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_sub(a, b)
  local r = {}
  local borrow = 0

  for i = 1, NUM_LIMBS do
    local diff = (a[i] or 0) - (b[i] or 0) - borrow
    if diff < 0 then
      r[i] = diff + 256
      borrow = 1
    else
      r[i] = diff
      borrow = 0
    end
  end

  -- If we have a borrow, add p to make positive
  if borrow > 0 then
    -- Add p = 2^448 - 2^224 - 1 with proper carry propagation
    local carry = 0
    for i = 1, 28 do
      local sum = r[i] + 0xFF + carry
      r[i] = band(sum, LIMB_MASK)
      carry = floor(sum / 256)
    end

    local sum = r[29] + 0xFE + carry
    r[29] = band(sum, LIMB_MASK)
    carry = floor(sum / 256)

    for i = 30, NUM_LIMBS do
      sum = r[i] + 0xFF + carry
      r[i] = band(sum, LIMB_MASK)
      carry = floor(sum / 256)
    end
  end

  fe_reduce(r)
  return r
end

--- Multiply two field elements
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_mul(a, b)
  -- Pre-allocate result array with zeros
  local r = {}
  for i = 1, 2 * NUM_LIMBS do
    r[i] = 0
  end

  -- Schoolbook multiplication without intermediate carry propagation
  -- This is safe because each limb product is at most 255*255 = 65025
  -- and we can accumulate up to ~56 of these before overflow
  for i = 1, NUM_LIMBS do
    local ai = a[i]
    if ai and ai > 0 then -- Skip zero multiplications
      for j = 1, NUM_LIMBS do
        local bj = b[j]
        if bj and bj > 0 then
          r[i + j - 1] = r[i + j - 1] + ai * bj
        end
      end
    end
  end

  -- Single carry propagation pass
  local carry = 0
  for i = 1, 2 * NUM_LIMBS do
    local sum = r[i] + carry
    r[i] = band(sum, LIMB_MASK)
    carry = floor(sum / 256)
  end

  -- Fast reduction using the special form of p = 2^448 - 2^224 - 1
  -- For each limb i >= 56, we have:
  -- 2^(8i) ≡ 2^(8(i-56)) + 2^(8(i-56)+224) (mod p)
  for i = NUM_LIMBS + 1, 2 * NUM_LIMBS do
    local c = r[i]
    if c > 0 then
      r[i] = 0
      local pos1 = i - NUM_LIMBS
      local pos2 = pos1 + 28 -- 224/8 = 28

      r[pos1] = r[pos1] + c
      if pos2 <= NUM_LIMBS then
        r[pos2] = r[pos2] + c
      else
        -- Handle wraparound
        local wrap_pos = pos2 - NUM_LIMBS
        r[wrap_pos] = r[wrap_pos] + c
        r[wrap_pos + 28] = r[wrap_pos + 28] + c
      end
    end
  end

  -- Handle remaining carry from reduction
  if carry > 0 then
    r[1] = r[1] + carry
    r[29] = r[29] + carry
  end

  -- Final carry propagation and normalization
  carry = 0
  for i = 1, NUM_LIMBS do
    local sum = r[i] + carry
    r[i] = band(sum, LIMB_MASK)
    carry = floor(sum / 256)
  end

  -- Handle final carry
  while carry > 0 do
    r[1] = r[1] + carry
    r[29] = r[29] + carry

    carry = 0
    for i = 1, NUM_LIMBS do
      local sum = r[i] + carry
      r[i] = band(sum, LIMB_MASK)
      carry = floor(sum / 256)
    end
  end

  -- Ensure we only have NUM_LIMBS limbs
  local result = {}
  for i = 1, NUM_LIMBS do
    result[i] = r[i]
  end

  return result
end

--- Square a field element
--- @param a table Operand
--- @return table r Result
local function fe_sq(a)
  return fe_mul(a, a)
end

--- Field inversion using Fermat's little theorem
--- @param a table Field element to invert
--- @return table r Result (a^-1)
local function fe_inv(a)
  -- Special case: if input is 1, return 1
  local is_one = true
  for i = 2, NUM_LIMBS do
    if (a[i] or 0) ~= 0 then
      is_one = false
      break
    end
  end
  if is_one and (a[1] or 0) == 1 then
    return fe_one()
  end

  -- Implement exact binary exponentiation matching Python's pow() algorithm
  -- Process the exponent bit by bit from MSB to LSB
  -- Exponent = p-2 = 2^448 - 2^224 - 3

  local result = fe_one()
  local base = fe_copy(a)

  -- The exponent in binary is: 448 bits starting with 1
  -- Pattern: 223 ones, 1 zero, 222 ones, 1 zero, 1 one

  -- Process MSB (bit 447) = 1
  result = fe_mul(result, base)

  -- Pre-compute small powers for sliding window
  local powers = {}
  powers[1] = fe_copy(base)
  powers[2] = fe_sq(base)
  powers[3] = fe_mul(powers[2], base)

  -- Process bits 446 down to 225 (222 ones) using 2-bit sliding window
  for _ = 1, 111 do
    result = fe_sq(result)
    result = fe_sq(result)
    result = fe_mul(result, powers[3]) -- Multiply by a^3
  end

  -- Process bit 224 = 0
  result = fe_sq(result)

  -- Process bits 223 down to 2 (222 ones) using 2-bit sliding window
  for _ = 1, 111 do
    result = fe_sq(result)
    result = fe_sq(result)
    result = fe_mul(result, powers[3]) -- Multiply by a^3
  end

  -- Process bit 1 = 0
  result = fe_sq(result)

  -- Process bit 0 (LSB) = 1
  result = fe_sq(result)
  result = fe_mul(result, base)

  return result
end

--- Conditional swap of two field elements (returns new arrays)
--- @param swap number 0 or 1
--- @param a table First element
--- @param b table Second element
--- @return table new_a, table new_b
local function cswap(swap, a, b)
  if swap == 1 then
    local new_a = {}
    local new_b = {}
    for i = 1, NUM_LIMBS do
      new_a[i] = b[i]
      new_b[i] = a[i]
    end
    return new_a, new_b
  else
    local new_a = {}
    local new_b = {}
    for i = 1, NUM_LIMBS do
      new_a[i] = a[i]
      new_b[i] = b[i]
    end
    return new_a, new_b
  end
end

--- Convert bytes to field element (little-endian)
--- @param bytes string 56-byte string
--- @return table fe Field element
local function fe_frombytes(b)
  local r = fe_zero()
  -- With 8-bit limbs, it's a direct 1-to-1 mapping
  for i = 1, NUM_LIMBS do
    r[i] = byte(b, i) or 0
  end
  return r
end

--- Convert field element to bytes (little-endian)
--- @param a table Field element
--- @return string bytes 56-byte string
local function fe_tobytes(a)
  -- First ensure the field element is fully reduced
  local t = fe_copy(a)
  fe_reduce(t)

  -- Convert to bytes - with 8-bit limbs it's direct
  local b = {}
  for i = 1, NUM_LIMBS do
    b[i] = char(band(t[i] or 0, 0xFF))
  end

  return table.concat(b)
end

--- X448 scalar multiplication
--- @param scalar string 56-byte scalar
--- @param base string 56-byte base point
--- @return string result 56-byte result
local function x448_scalarmult(scalar, base)
  -- Decode base point
  local u = fe_frombytes(base)

  -- Scalar clamping as per RFC 7748 for X448
  local k = {}
  for i = 1, 56 do
    k[i] = byte(scalar, i) or 0
  end
  k[1] = band(k[1], 252) -- Clear low 2 bits
  k[56] = bor(k[56], 128) -- Set high bit

  -- Initialize Montgomery ladder
  local x_1 = fe_copy(u)
  local x_2 = fe_one()
  local z_2 = fe_zero()
  local x_3 = fe_copy(u)
  local z_3 = fe_one()
  local swap = 0

  -- Montgomery ladder
  for t = 447, 0, -1 do
    local byte_idx = rshift(t, 3) + 1 -- t // 8 + 1
    local bit_idx = band(t, 7) -- t % 8
    local kt = band(rshift(k[byte_idx], bit_idx), 1)

    -- Conditional swap
    swap = bxor(swap, kt)
    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    swap = kt

    -- Montgomery ladder step
    local a = fe_add(x_2, z_2)
    local aa = fe_sq(a)
    local b = fe_sub(x_2, z_2)
    local bb = fe_sq(b)
    local e = fe_sub(aa, bb)
    local c = fe_add(x_3, z_3)
    local d = fe_sub(x_3, z_3)
    local da = fe_mul(d, a)
    local cb = fe_mul(c, b)

    x_3 = fe_sq(fe_add(da, cb))
    z_3 = fe_mul(x_1, fe_sq(fe_sub(da, cb)))
    x_2 = fe_mul(aa, bb)

    -- z_2 = e * (aa + a24 * e)
    local a24_limbs = fe_zero()
    a24_limbs[1] = band(A24, 0xFF)
    a24_limbs[2] = band(rshift(A24, 8), 0xFF)

    local a24_e = fe_mul(a24_limbs, e)
    z_2 = fe_mul(e, fe_add(aa, a24_e))
  end

  -- Final swap
  local _
  x_2, _ = cswap(swap, x_2, x_3)
  z_2, _ = cswap(swap, z_2, z_3)

  -- Compute x_2 / z_2
  local z_inv = fe_inv(z_2)
  local x = fe_mul(x_2, z_inv)

  -- Convert to bytes
  return fe_tobytes(x)
end

--- Generate a random Curve448 private key
--- @return string private_key 56-byte private key
function x448.generate_private_key()
  -- Generate 56 random bytes
  local key = ""

  -- Mix multiple sources of randomness
  local seed = os.time() + (os.clock() * 1000000)
  math.randomseed(seed)

  for _ = 1, 56 do
    key = key .. char(math.random(0, 255))
  end

  return key
end

--- Derive public key from private key
--- @param private_key string 56-byte private key
--- @return string public_key 56-byte public key
function x448.derive_public_key(private_key)
  assert(#private_key == 56, "Private key must be exactly 56 bytes")

  -- Base point for X448 (u = 5)
  local base = char(5) .. string.rep(char(0), 55)

  return x448_scalarmult(private_key, base)
end

--- Perform X448 Diffie-Hellman
--- @param private_key string 56-byte private key
--- @param public_key string 56-byte public key
--- @return string shared_secret 56-byte shared secret
function x448.diffie_hellman(private_key, public_key)
  assert(#private_key == 56, "Private key must be exactly 56 bytes")
  assert(#public_key == 56, "Public key must be exactly 56 bytes")

  return x448_scalarmult(private_key, public_key)
end

--- Generate a Curve448 key pair
--- @return string private_key 56-byte private key
--- @return string public_key 56-byte public key
function x448.generate_keypair()
  local private_key = x448.generate_private_key()
  local public_key = x448.derive_public_key(private_key)
  return private_key, public_key
end

--- Test vectors from RFC 7748
local test_vectors = {
  {
    name = "RFC 7748 Test Vector 1",
    scalar = bytes.from_hex(
      "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
        .. "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
    ),
    u_coord = bytes.from_hex(
      "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
        .. "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
    ),
    expected = bytes.from_hex(
      "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
        .. "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    ),
  },
  {
    name = "RFC 7748 Test Vector 2",
    scalar = bytes.from_hex(
      "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
        .. "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"
    ),
    u_coord = bytes.from_hex(
      "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b"
        .. "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"
    ),
    expected = bytes.from_hex(
      "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
        .. "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    ),
  },
}

--- Run comprehensive self-test with RFC test vectors and functional tests
---
--- This function validates the X448 implementation against known test vectors
--- from RFC 7748. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function x448.selftest()
  local function test_vectors_suite()
    print("Running X448 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      -- Debug: Check input format
      print("  Scalar length: " .. #test.scalar)
      print("  U-coord length: " .. #test.u_coord)

      local result = x448.diffie_hellman(test.scalar, test.u_coord)

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)
        print("    Expected: " .. bytes.to_hex(test.expected))
        print("    Got:      " .. bytes.to_hex(result))
      end
    end

    print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function functional_tests()
    print("Running X448 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Key generation
    total = total + 1
    local ok, err = pcall(function()
      local private_key, public_key = x448.generate_keypair()
      assert(#private_key == 56, "Private key should be 56 bytes")
      assert(#public_key == 56, "Public key should be 56 bytes")
    end)
    if ok then
      print("  ✅ PASS: Key generation")
      passed = passed + 1
    else
      print("  ❌ FAIL: Key generation - " .. tostring(err))
    end

    -- Test 2: Public key derivation consistency
    total = total + 1
    ok = pcall(function()
      local private_key = x448.generate_private_key()
      local public_key1 = x448.derive_public_key(private_key)
      local public_key2 = x448.derive_public_key(private_key)
      assert(public_key1 == public_key2, "Public key derivation should be deterministic")
    end)
    if ok then
      print("  ✅ PASS: Public key derivation consistency")
      passed = passed + 1
    else
      print("  ❌ FAIL: Public key derivation consistency")
    end

    -- Test 3: Diffie-Hellman symmetry
    total = total + 1
    ok = pcall(function()
      local alice_private, alice_public = x448.generate_keypair()
      local bob_private, bob_public = x448.generate_keypair()

      local alice_shared = x448.diffie_hellman(alice_private, bob_public)
      local bob_shared = x448.diffie_hellman(bob_private, alice_public)

      assert(alice_shared == bob_shared, "DH key exchange should be symmetric")
    end)
    if ok then
      print("  ✅ PASS: Diffie-Hellman symmetry")
      passed = passed + 1
    else
      print("  ❌ FAIL: Diffie-Hellman symmetry")
    end

    -- Test 4: Different shared secrets
    total = total + 1
    ok = pcall(function()
      local alice_private, _alice_public = x448.generate_keypair()
      local _bob_private, bob_public = x448.generate_keypair()
      local _charlie_private, charlie_public = x448.generate_keypair()

      local alice_bob = x448.diffie_hellman(alice_private, bob_public)
      local alice_charlie = x448.diffie_hellman(alice_private, charlie_public)

      assert(alice_bob ~= alice_charlie, "Different key pairs should produce different shared secrets")
    end)
    if ok then
      print("  ✅ PASS: Different shared secrets")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different shared secrets")
    end

    -- Test 5: Edge case handling
    total = total + 1
    ok = pcall(function()
      -- Test with all-zero public key
      local private_key = x448.generate_private_key()
      local zero_public = string.rep(char(0), 56)
      local shared = x448.diffie_hellman(private_key, zero_public)
      assert(#shared == 56, "Should handle zero public key")
    end)
    if ok then
      print("  ✅ PASS: Edge case handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Edge case handling")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  -- Run both test suites
  local vectors_pass = test_vectors_suite()
  local functional_pass = functional_tests()

  return vectors_pass and functional_pass
end

-- Store private key counter for better randomness
x448._key_counter = 0

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for X448 operations
--- including key generation, public key derivation, and Diffie-Hellman operations.
function x448.benchmark()
  -- Test data from RFC 7748
  local test_scalar = bytes.from_hex(
    "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
      .. "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
  )
  local test_point = bytes.from_hex(
    "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
      .. "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
  )

  print("Key Operations:")
  benchmark_op("generate_keypair", function()
    x448.generate_keypair()
  end, 5)

  benchmark_op("derive_public_key", function()
    x448.derive_public_key(test_scalar)
  end, 10)

  benchmark_op("diffie_hellman", function()
    x448.diffie_hellman(test_scalar, test_point)
  end, 10)
end

return x448
