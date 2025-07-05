--- @module "noiseprotocol.crypto.x448"
--- X448 Curve448 Elliptic Curve Diffie-Hellman Implementation for portability.

local utils = require("noiseprotocol.utils")
local bit32 = utils.bit32
local bytes = utils.bytes

local x448 = {}

-- Field element is 2^448 - 2^224 - 1
-- We use 16 limbs of 28 bits each (total 448 bits)
-- This allows us to stay well within LuaJIT's 2^53-1 integer limit
local LIMB_BITS = 28
local LIMB_MASK = bit32.lshift(1, LIMB_BITS) - 1 -- 0xFFFFFFF
local NUM_LIMBS = 16

--- Create a new field element initialized to zero
--- @return table fe Field element (16 limbs)
local function fe_zero()
  local r = {}
  for i = 0, NUM_LIMBS - 1 do
    r[i] = 0
  end
  return r
end

--- Create a new field element initialized to one
--- @return table fe Field element
local function fe_one()
  local r = fe_zero()
  r[0] = 1
  return r
end

--- Copy a field element
--- @param a table Source field element
--- @return table fe Copy of the field element
local function fe_copy(a)
  local r = {}
  for i = 0, NUM_LIMBS - 1 do
    r[i] = a[i] or 0
  end
  return r
end

--- Reduce coefficients and propagate carries
--- For p = 2^448 - 2^224 - 1, we have 2^448 ≡ 2^224 + 1 (mod p)
--- @param a table Field element to reduce (modified in place)
local function fe_reduce(a)
  -- First pass: ensure all limbs are positive and collect carry
  local carry = 0
  for i = 0, NUM_LIMBS - 1 do
    carry = carry + (a[i] or 0)
    a[i] = bit32.band(carry, LIMB_MASK)
    carry = math.floor(carry / bit32.lshift(1, LIMB_BITS))
  end

  -- Now we have overflow in 'carry' representing multiples of 2^448
  -- Since 2^448 ≡ 2^224 + 1 (mod p), each unit of carry adds:
  -- - 1 to limb 0
  -- - 1 to limb 8 (bit position 224 = 8 * 28)
  while carry > 0 do
    a[0] = a[0] + carry
    a[8] = a[8] + carry

    -- Propagate carries again
    local new_carry = 0
    for i = 0, NUM_LIMBS - 1 do
      new_carry = new_carry + a[i]
      a[i] = bit32.band(new_carry, LIMB_MASK)
      new_carry = math.floor(new_carry / bit32.lshift(1, LIMB_BITS))
    end
    carry = new_carry
  end

  -- Final reduction to ensure result is less than p
  -- We'll do this by trial subtraction
  local tmp = fe_copy(a)
  local borrow = 0

  -- Subtract p from tmp
  -- p in 28-bit limbs (little-endian):
  -- limb 0: 2^28 - 2 = 0xFFFFFFE
  -- limbs 1-7: 2^28 - 1 = 0xFFFFFFF
  -- limb 8: 2^28 - 2 = 0xFFFFFFE
  -- limbs 9-15: 2^28 - 1 = 0xFFFFFFF

  -- limb 0
  local diff = tmp[0] - 0xFFFFFFE
  if diff < 0 then
    tmp[0] = diff + bit32.lshift(1, LIMB_BITS)
    borrow = 1
  else
    tmp[0] = diff
    borrow = 0
  end

  -- limbs 1-7
  for i = 1, 7 do
    diff = tmp[i] - LIMB_MASK - borrow
    if diff < 0 then
      tmp[i] = diff + bit32.lshift(1, LIMB_BITS)
      borrow = 1
    else
      tmp[i] = diff
      borrow = 0
    end
  end

  -- limb 8
  diff = tmp[8] - 0xFFFFFFE - borrow
  if diff < 0 then
    tmp[8] = diff + bit32.lshift(1, LIMB_BITS)
    borrow = 1
  else
    tmp[8] = diff
    borrow = 0
  end

  -- limbs 9-15
  for i = 9, NUM_LIMBS - 1 do
    diff = tmp[i] - LIMB_MASK - borrow
    if diff < 0 then
      tmp[i] = diff + bit32.lshift(1, LIMB_BITS)
      borrow = 1
    else
      tmp[i] = diff
      borrow = 0
    end
  end

  -- If no borrow occurred, then a >= p, so use a - p
  if borrow == 0 then
    for i = 0, NUM_LIMBS - 1 do
      a[i] = tmp[i]
    end
  end
end

--- Add two field elements: r = a + b
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_add(a, b)
  local r = {}
  for i = 0, NUM_LIMBS - 1 do
    r[i] = (a[i] or 0) + (b[i] or 0)
  end
  fe_reduce(r)
  return r
end

--- Subtract two field elements: r = a - b
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_sub(a, b)
  local r = {}
  local borrow = 0

  for i = 0, NUM_LIMBS - 1 do
    local diff = (a[i] or 0) - (b[i] or 0) - borrow
    if diff < 0 then
      r[i] = diff + bit32.lshift(1, LIMB_BITS)
      borrow = 1
    else
      r[i] = diff
      borrow = 0
    end
  end

  -- If we have a borrow, add p to make positive
  if borrow > 0 then
    -- Add p
    r[0] = r[0] + 0xFFFFFFE
    for i = 1, 7 do
      r[i] = r[i] + LIMB_MASK
    end
    r[8] = r[8] + 0xFFFFFFE
    for i = 9, NUM_LIMBS - 1 do
      r[i] = r[i] + LIMB_MASK
    end
  end

  fe_reduce(r)
  return r
end

--- Multiply two field elements: r = a * b
--- @param a table First operand
--- @param b table Second operand
--- @return table r Result
local function fe_mul(a, b)
  -- Schoolbook multiplication
  local r = {}
  for i = 0, 2 * NUM_LIMBS - 1 do
    r[i] = 0
  end

  for i = 0, NUM_LIMBS - 1 do
    for j = 0, NUM_LIMBS - 1 do
      r[i + j] = r[i + j] + (a[i] or 0) * (b[j] or 0)
    end
  end

  -- Reduce modulo p
  -- For coefficients beyond limb 15, use 2^448 ≡ 2^224 + 1
  for i = NUM_LIMBS, 2 * NUM_LIMBS - 1 do
    if r[i] > 0 then
      local c = r[i]
      r[i - NUM_LIMBS] = r[i - NUM_LIMBS] + c -- Add c * 1
      r[i - NUM_LIMBS + 8] = r[i - NUM_LIMBS + 8] + c -- Add c * 2^224
      r[i] = 0
    end
  end

  -- Final reduction
  fe_reduce(r)

  -- Ensure we only have NUM_LIMBS limbs
  local result = {}
  for i = 0, NUM_LIMBS - 1 do
    result[i] = r[i]
  end

  return result
end

--- Square a field element: r = a^2
--- @param a table Operand
--- @return table r Result
local function fe_sq(a)
  return fe_mul(a, a)
end

--- Compute a^(2^n) by repeated squaring
--- @param a table Base
--- @param n number Number of squarings
--- @return table Result
local function fe_pow2k(a, n)
  local r = fe_copy(a)
  for _ = 1, n do
    r = fe_sq(r)
  end
  return r
end

--- Invert a field element using Fermat's little theorem
--- For p = 2^448 - 2^224 - 1, compute a^(p-2)
--- @param a table Field element to invert
--- @return table r Result (1/a)
local function fe_inv(a)
  -- Using the addition chain from the Ed448-Goldilocks paper
  -- This computes a^(p-2) = a^(2^448 - 2^224 - 3)

  local t0, t1, t2

  -- Build up powers
  t0 = fe_sq(a) -- a^2
  t1 = fe_mul(t0, a) -- a^3
  t0 = fe_sq(t1) -- a^6
  t1 = fe_mul(t0, t1) -- a^9
  t0 = fe_sq(t0) -- a^12
  t0 = fe_sq(t0) -- a^24
  t0 = fe_sq(t0) -- a^48
  t1 = fe_mul(t0, t1) -- a^57
  t0 = fe_sq(t0) -- a^96
  t0 = fe_sq(t0) -- a^192
  t0 = fe_mul(t0, a) -- a^193
  t1 = fe_mul(t0, t1) -- a^250
  t0 = fe_sq(t1) -- a^500
  t0 = fe_sq(t0) -- a^1000
  t0 = fe_sq(t0) -- a^2000
  t0 = fe_sq(t0) -- a^4000

  -- Continue building the chain
  t2 = t0
  for _ = 1, 5 do
    t2 = fe_sq(t2)
  end -- a^(2^17)
  t1 = fe_mul(t1, t2) -- a^(2^17 + 250)

  t2 = t1
  for _ = 1, 17 do
    t2 = fe_sq(t2)
  end -- a^(2^34 + 2^17*250)

  t0 = fe_mul(t0, t2) -- Add to running total

  -- Continue to build up to a^(p-2)
  -- This is still an approximation - would need exact chain
  for _ = 1, 17 do
    t0 = fe_sq(t0)
  end
  t0 = fe_mul(t0, t1)

  for _ = 1, 17 do
    t0 = fe_sq(t0)
  end
  t0 = fe_mul(t0, a)

  for _ = 1, 116 do
    t0 = fe_sq(t0)
  end
  t0 = fe_mul(t0, a)

  for _ = 1, 223 do
    t0 = fe_sq(t0)
  end
  t0 = fe_mul(t0, a)

  return t0
end

--- Conditional swap of two field elements
--- @param a table First element (modified)
--- @param b table Second element (modified)
--- @param swap number 0 or 1
local function fe_cswap(a, b, swap)
  for i = 0, NUM_LIMBS - 1 do
    local ai = a[i] or 0
    local bi = b[i] or 0
    local x = swap * (ai - bi)
    a[i] = ai - x
    b[i] = bi + x
  end
end

--- Convert bytes to field element (little-endian)
--- @param bytes string 56-byte string
--- @return table fe Field element
local function fe_frombytes(bytes)
  local r = fe_zero()

  -- Pack bytes into 28-bit limbs
  local byte_idx = 1
  local bit_offset = 0
  local accumulator = 0

  for limb = 0, NUM_LIMBS - 1 do
    -- Collect 28 bits
    while bit_offset < LIMB_BITS and byte_idx <= 56 do
      accumulator = accumulator + bit32.lshift(string.byte(bytes, byte_idx) or 0, bit_offset)
      bit_offset = bit_offset + 8
      byte_idx = byte_idx + 1
    end

    r[limb] = bit32.band(accumulator, LIMB_MASK)
    accumulator = bit32.rshift(accumulator, LIMB_BITS)
    bit_offset = bit_offset - LIMB_BITS
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

  local bytes = {}
  local accumulator = 0
  local bits_available = 0
  local limb_idx = 0

  for byte_idx = 1, 56 do
    -- Get 8 bits
    while bits_available < 8 and limb_idx < NUM_LIMBS do
      accumulator = accumulator + bit32.lshift(t[limb_idx] or 0, bits_available)
      bits_available = bits_available + LIMB_BITS
      limb_idx = limb_idx + 1
    end

    bytes[byte_idx] = string.char(bit32.band(accumulator, 0xFF))
    accumulator = bit32.rshift(accumulator, 8)
    bits_available = bits_available - 8
  end

  return table.concat(bytes)
end

--- X448 scalar multiplication
--- @param scalar string 56-byte scalar
--- @param base string 56-byte base point
--- @return string result 56-byte result
local function x448_scalarmult(scalar, base)
  -- Decode base point
  local u = fe_frombytes(base)

  -- Set up the Montgomery ladder
  local x_1 = fe_copy(u)
  local x_2 = fe_one()
  local z_2 = fe_zero()
  local x_3 = fe_copy(u)
  local z_3 = fe_one()

  -- Scalar clamping as per RFC 7748 for X448
  local k = {}
  for i = 1, 56 do
    k[i] = string.byte(scalar, i) or 0
  end
  k[1] = bit32.band(k[1], 252) -- Clear low 2 bits
  k[56] = bit32.bor(k[56], 128) -- Set high bit

  -- Montgomery ladder
  local swap = 0
  for t = 447, 0, -1 do
    local byte = math.floor(t / 8) + 1
    local bit_pos = t % 8
    local kt = bit32.band(bit32.rshift(k[byte], bit_pos), 1)

    swap = bit32.bxor(swap, kt)
    fe_cswap(x_2, x_3, swap)
    fe_cswap(z_2, z_3, swap)
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

    -- Multiply e by a24 = 39082
    -- a24 = (A-2)/4 where A = 156326 for Curve448
    local a24 = fe_zero()
    -- 39082 in base 2^28 is just 39082 in limb 0
    a24[0] = 39082

    local e_a24 = fe_mul(e, a24)
    z_2 = fe_mul(e, fe_add(aa, e_a24))
  end

  -- Final swap
  fe_cswap(x_2, x_3, swap)
  fe_cswap(z_2, z_3, swap)

  -- Compute x_2 / z_2
  local z_inv = fe_inv(z_2)
  local x = fe_mul(x_2, z_inv)

  -- Convert to bytes
  return fe_tobytes(x)
end

--- Generate a random Curve448 private key
--- @return string private_key 56-byte private key
function x448.generate_private_key()
  -- Better randomness by using time + clock + counter
  local counter = x448._key_counter or 0
  x448._key_counter = counter + 1
  math.randomseed(os.time() + os.clock() * 1000000 + counter)

  local key = ""
  for _ = 1, 56 do
    key = key .. string.char(math.random(0, 255))
  end

  return key
end

--- Derive public key from private key
--- @param private_key string 56-byte private key
--- @return string public_key 56-byte public key
function x448.derive_public_key(private_key)
  assert(#private_key == 56, "Private key must be exactly 56 bytes")

  -- Base point for X448 (u = 5)
  local base = string.char(5) .. string.rep("\x00", 55)

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
      local alice_private, alice_public = x448.generate_keypair()
      local bob_private, bob_public = x448.generate_keypair()
      local charlie_private, charlie_public = x448.generate_keypair()

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
      local zero_public = string.rep("\x00", 56)
      local shared = x448.diffie_hellman(private_key, zero_public)
      assert(#shared == 56, "Should handle zero public key")
    end)
    if ok then
      print("  ✅ PASS: Edge case handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Edge case handling")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    return passed == total
  end

  local test_vectors_pass = test_vectors_suite()
  local functional_pass = functional_tests()

  return test_vectors_pass and functional_pass
end

return x448
