--- @module "noiseprotocol.crypto.x25519"
--- X25519 Curve25519 Elliptic Curve Diffie-Hellman Implementation for portability.

local x25519 = {}

local utils = require("noiseprotocol.utils")

-- ============================================================================
-- CURVE25519 FIELD ARITHMETIC
-- ============================================================================

--- Carry operation for 64-bit arithmetic
--- @param out integer[] Array to perform carry on
local function carry(out)
  for i = 0, 15 do
    out[i] = out[i] + 0x10000
    local c = out[i] / 0x10000 - (out[i] / 0x10000) % 1
    if i < 15 then
      out[i + 1] = out[i + 1] + c - 1
    else
      out[0] = out[0] + 38 * (c - 1)
    end
    out[i] = out[i] - c * 0x10000
  end
end

--- Conditional swap based on bit value
--- @param a integer[] First array
--- @param b integer[] Second array
--- @param bit integer Bit value (0 or 1)
local function swap(a, b, bit)
  for i = 0, 15 do
    a[i], b[i] = a[i] * ((bit - 1) % 2) + b[i] * bit, b[i] * ((bit - 1) % 2) + a[i] * bit
  end
end

--- Unpack byte array to limb array
--- @param out integer[] Output limb array
--- @param a integer[] Input byte array
local function unpack(out, a)
  for i = 0, 15 do
    out[i] = a[2 * i] + a[2 * i + 1] * 0x100
  end
  out[15] = out[15] % 0x8000
end

--- Pack limb array to byte array with modular reduction
--- @param out integer[] Output byte array
--- @param a integer[] Input limb array
local function pack(out, a)
  local t, m = {}, {}
  for i = 0, 15 do
    t[i] = a[i]
  end
  carry(t)
  carry(t)
  carry(t)
  local prime = { [0] = 0xffed, [15] = 0x7fff }
  for i = 1, 14 do
    prime[i] = 0xffff
  end
  for _ = 0, 1 do
    m[0] = t[0] - prime[0]
    for i = 1, 15 do
      m[i] = t[i] - prime[i] - ((m[i - 1] / 0x10000 - (m[i - 1] / 0x10000) % 1) % 2)
      m[i - 1] = (m[i - 1] + 0x10000) % 0x10000
    end
    local c = (m[15] / 0x10000 - (m[15] / 0x10000) % 1) % 2
    swap(t, m, 1 - c)
  end
  for i = 0, 15 do
    out[2 * i] = t[i] % 0x100
    out[2 * i + 1] = t[i] / 0x100 - (t[i] / 0x100) % 1
  end
end

--- Add two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function add(out, a, b)
  for i = 0, 15 do
    out[i] = a[i] + b[i]
  end
end

--- Subtract two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function sub(out, a, b)
  for i = 0, 15 do
    out[i] = a[i] - b[i]
  end
end

--- Multiply two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function mul(out, a, b)
  local prod = {}
  for i = 0, 31 do
    prod[i] = 0
  end
  for i = 0, 15 do
    for j = 0, 15 do
      prod[i + j] = prod[i + j] + a[i] * b[j]
    end
  end
  for i = 0, 14 do
    prod[i] = prod[i] + 38 * prod[i + 16]
  end
  for i = 0, 15 do
    out[i] = prod[i]
  end
  carry(out)
  carry(out)
end

--- Compute modular inverse using Fermat's little theorem
--- @param out integer[] Output array
--- @param a integer[] Input array
local function inv(out, a)
  local c = {}
  for i = 0, 15 do
    c[i] = a[i]
  end
  for i = 253, 0, -1 do
    mul(c, c, c)
    if i ~= 2 and i ~= 4 then
      mul(c, c, a)
    end
  end
  for i = 0, 15 do
    out[i] = c[i]
  end
end

--- X25519 scalar multiplication using Montgomery ladder
--- @param out integer[] Output point
--- @param scalar integer[] Input scalar
--- @param point integer[] Input point
local function scalarmult(out, scalar, point)
  local a, b, c, d, e, f, x, clam = {}, {}, {}, {}, {}, {}, {}, {}
  unpack(x, point)
  for i = 0, 15 do
    a[i], b[i], c[i], d[i] = 0, x[i], 0, 0
  end
  a[0], d[0] = 1, 1
  for i = 0, 30 do
    clam[i] = scalar[i]
  end
  clam[0] = clam[0] - (clam[0] % 8)
  clam[31] = scalar[31] % 64 + 64
  for i = 254, 0, -1 do
    local bit = (clam[math.floor(i / 8)] / math.pow(2, i % 8) - (clam[math.floor(i / 8)] / math.pow(2, i % 8)) % 1) % 2
    swap(a, b, bit)
    swap(c, d, bit)
    add(e, a, c)
    sub(a, a, c)
    add(c, b, d)
    sub(b, b, d)
    mul(d, e, e)
    mul(f, a, a)
    mul(a, c, a)
    mul(c, b, e)
    add(e, a, c)
    sub(a, a, c)
    mul(b, a, a)
    sub(c, d, f)
    mul(a, c, { [0] = 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })
    add(a, a, d)
    mul(c, c, a)
    mul(a, d, f)
    mul(d, b, x)
    mul(b, e, e)
    swap(a, b, bit)
    swap(c, d, bit)
  end
  inv(c, c)
  mul(a, a, c)
  pack(out, a)
end

--- Convert string to byte array
--- @param s string Input string
--- @return integer[] byte_array Byte array
local function string_to_bytes(s)
  local b = {}
  for i = 1, #s do
    b[i - 1] = string.byte(s, i)
  end
  return b
end

--- Convert byte array to string
--- @param b integer[] Byte array
--- @param len integer Length
--- @return string result Output string
local function bytes_to_string(b, len)
  local result = ""
  for i = 0, len - 1 do
    result = result .. string.char(b[i] or 0)
  end
  return result
end

-- ============================================================================
-- X25519 PUBLIC INTERFACE
-- ============================================================================

--- Generate a random Curve25519 private key
--- @return string private_key 32-byte private key
function x25519.generate_private_key()
  -- Better randomness by using time + clock + counter
  local counter = x25519._key_counter or 0
  x25519._key_counter = counter + 1
  math.randomseed(os.time() + os.clock() * 1000000 + counter)

  local key = ""
  for _ = 1, 32 do
    key = key .. string.char(math.random(0, 255))
  end
  return key
end

--- Derive public key from private key
--- @param private_key string 32-byte private key
--- @return string public_key 32-byte public key
function x25519.derive_public_key(private_key)
  assert(#private_key == 32, "Private key must be exactly 32 bytes")

  local sk = string_to_bytes(private_key)
  local pk = {}
  local base = { [0] = 9 }
  for i = 1, 31 do
    base[i] = 0
  end

  scalarmult(pk, sk, base)
  return bytes_to_string(pk, 32)
end

--- Perform X25519 Diffie-Hellman
--- @param private_key string 32-byte private key
--- @param public_key string 32-byte public key
--- @return string shared_secret 32-byte shared secret
function x25519.diffie_hellman(private_key, public_key)
  assert(#private_key == 32, "Private key must be exactly 32 bytes")
  assert(#public_key == 32, "Public key must be exactly 32 bytes")

  local sk = string_to_bytes(private_key)
  local pk = string_to_bytes(public_key)
  local shared = {}

  scalarmult(shared, sk, pk)
  return bytes_to_string(shared, 32)
end

--- Generate a Curve25519 key pair
--- @return string private_key 32-byte private key
--- @return string public_key 32-byte public key
function x25519.generate_keypair()
  local private_key = x25519.generate_private_key()
  local public_key = x25519.derive_public_key(private_key)
  return private_key, public_key
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- Test vectors from RFC 7748
local test_vectors = {
  {
    name = "RFC 7748 Test Vector 1",
    scalar = utils.bytes.from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    u_coord = utils.bytes.from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    expected = utils.bytes.from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
  },
  {
    name = "RFC 7748 Test Vector 2",
    scalar = utils.bytes.from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
    u_coord = utils.bytes.from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    expected = utils.bytes.from_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
  },
}

--- Run comprehensive self-test with RFC test vectors and functional tests
---
--- This function validates the X25519 implementation against known test vectors
--- from RFC 7748. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function x25519.selftest()
  local function test_vectors_suite()
    print("Running X25519 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      local result = x25519.diffie_hellman(test.scalar, test.u_coord)

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)

        -- Show hex output for debugging
        local result_hex = ""
        local expected_hex = ""
        for j = 1, #result do
          result_hex = result_hex .. string.format("%02x", string.byte(result, j))
        end
        for j = 1, #test.expected do
          expected_hex = expected_hex .. string.format("%02x", string.byte(test.expected, j))
        end
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
    print("Running X25519 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Key generation
    total = total + 1
    local success, err = pcall(function()
      local priv1, pub1 = x25519.generate_keypair()
      local priv2, pub2 = x25519.generate_keypair()

      assert(#priv1 == 32 and #pub1 == 32, "Keys should be 32 bytes")
      assert(priv1 ~= priv2, "Different key generations should produce different keys")
      assert(pub1 ~= pub2, "Different key generations should produce different public keys")
    end)

    if success then
      print("  ✅ PASS: Key generation")
      passed = passed + 1
    else
      print("  ❌ FAIL: Key generation - " .. err)
    end

    -- Test 2: Public key derivation consistency
    total = total + 1
    success, err = pcall(function()
      local priv = x25519.generate_private_key()
      local pub1 = x25519.derive_public_key(priv)
      local pub2 = x25519.derive_public_key(priv)

      assert(pub1 == pub2, "Public key derivation should be deterministic")
    end)

    if success then
      print("  ✅ PASS: Public key derivation consistency")
      passed = passed + 1
    else
      print("  ❌ FAIL: Public key derivation consistency - " .. err)
    end

    -- Test 3: Diffie-Hellman symmetry
    total = total + 1
    success, err = pcall(function()
      local alice_priv, alice_pub = x25519.generate_keypair()
      local bob_priv, bob_pub = x25519.generate_keypair()

      local alice_shared = x25519.diffie_hellman(alice_priv, bob_pub)
      local bob_shared = x25519.diffie_hellman(bob_priv, alice_pub)

      assert(alice_shared == bob_shared, "DH should be symmetric")
      assert(#alice_shared == 32, "Shared secret should be 32 bytes")
    end)

    if success then
      print("  ✅ PASS: Diffie-Hellman symmetry")
      passed = passed + 1
    else
      print("  ❌ FAIL: Diffie-Hellman symmetry - " .. err)
    end

    -- Test 4: Different keys produce different shared secrets
    total = total + 1
    success, err = pcall(function()
      local alice_priv, _alice_pub = x25519.generate_keypair()
      local _bob_priv, bob_pub = x25519.generate_keypair()
      local _charlie_priv, charlie_pub = x25519.generate_keypair()

      local alice_bob = x25519.diffie_hellman(alice_priv, bob_pub)
      local alice_charlie = x25519.diffie_hellman(alice_priv, charlie_pub)

      assert(alice_bob ~= alice_charlie, "Different keys should produce different shared secrets")
    end)

    if success then
      print("  ✅ PASS: Different shared secrets")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different shared secrets - " .. err)
    end

    -- Test 5: Edge case - all zero input (should not fail)
    total = total + 1
    success, err = pcall(function()
      local zero_key = string.rep("\0", 32)
      local priv, _pub = x25519.generate_keypair()

      -- This should not crash, though result may be predictable
      local result = x25519.diffie_hellman(priv, zero_key)
      assert(#result == 32, "Should still produce 32-byte result")
    end)

    if success then
      print("  ✅ PASS: Edge case handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Edge case handling - " .. err)
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return x25519
