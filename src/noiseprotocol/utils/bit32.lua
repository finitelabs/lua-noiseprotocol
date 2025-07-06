--- @module "noiseprotocol.utils.bit32"
--- 32-bit bitwise operations

local bit32 = {}

-- 32-bit mask for ensuring results stay within 32-bit range
local MASK32 = 0xFFFFFFFF

--- Ensure value fits in 32-bit unsigned integer
--- @param n number Input value
--- @return integer result 32-bit unsigned integer
function bit32.mask(n)
  return math.floor(n % 0x100000000)
end

--- Bitwise AND operation
--- @param a integer First operand (32-bit)
--- @param b integer Second operand (32-bit)
--- @return integer result Result of a AND b
function bit32.band(a, b)
  a = bit32.mask(a)
  b = bit32.mask(b)

  local result = 0
  local bit_val = 1

  for _ = 0, 31 do
    if (a % 2 == 1) and (b % 2 == 1) then
      result = result + bit_val
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit_val = bit_val * 2

    if a == 0 and b == 0 then
      break
    end
  end

  return result
end

--- Bitwise OR operation
--- @param a integer First operand (32-bit)
--- @param b integer Second operand (32-bit)
--- @return integer result Result of a OR b
function bit32.bor(a, b)
  a = bit32.mask(a)
  b = bit32.mask(b)

  local result = 0
  local bit_val = 1

  for _ = 0, 31 do
    if (a % 2 == 1) or (b % 2 == 1) then
      result = result + bit_val
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit_val = bit_val * 2

    if a == 0 and b == 0 then
      break
    end
  end

  return result
end

--- Bitwise XOR operation
--- @param a integer First operand (32-bit)
--- @param b integer Second operand (32-bit)
--- @return integer result Result of a XOR b
function bit32.bxor(a, b)
  a = bit32.mask(a)
  b = bit32.mask(b)

  local result = 0
  local bit_val = 1

  for _ = 0, 31 do
    if (a % 2) ~= (b % 2) then
      result = result + bit_val
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit_val = bit_val * 2

    if a == 0 and b == 0 then
      break
    end
  end

  return result
end

--- Bitwise NOT operation
--- @param a integer Operand (32-bit)
--- @return integer result Result of NOT a
function bit32.bnot(a)
  return bit32.mask(MASK32 - bit32.mask(a))
end

--- Left shift operation
--- @param a integer Value to shift (32-bit)
--- @param n integer Number of positions to shift
--- @return integer result Result of a << n
function bit32.lshift(a, n)
  assert(n >= 0, "Shift amount must be non-negative")
  if n >= 32 then
    return 0
  end
  return bit32.mask(bit32.mask(a) * math.pow(2, n))
end

--- Right shift operation
--- @param a integer Value to shift (32-bit)
--- @param n integer Number of positions to shift
--- @return integer result Result of a >> n
function bit32.rshift(a, n)
  assert(n >= 0, "Shift amount must be non-negative")
  a = bit32.mask(a)
  if n >= 32 then
    return 0
  end
  return math.floor(a / math.pow(2, n))
end

--- Left rotate operation
--- @param x integer Value to rotate (32-bit)
--- @param n integer Number of positions to rotate
--- @return integer result Result of rotating x left by n positions
function bit32.rol(x, n)
  n = n % 32
  x = bit32.mask(x)
  return bit32.mask(bit32.lshift(x, n) + bit32.rshift(x, 32 - n))
end

--- Right rotate operation
--- @param x integer Value to rotate (32-bit)
--- @param n integer Number of positions to rotate
--- @return integer result Result of rotating x right by n positions
function bit32.ror(x, n)
  n = n % 32
  x = bit32.mask(x)
  return bit32.mask(bit32.rshift(x, n) + bit32.lshift(x, 32 - n))
end

--- 32-bit addition with overflow handling
--- @param a integer First operand (32-bit)
--- @param b integer Second operand (32-bit)
--- @return integer result Result of (a + b) mod 2^32
function bit32.add(a, b)
  return bit32.mask(bit32.mask(a) + bit32.mask(b))
end

--- Run comprehensive self-test with test vectors
--- @return boolean result True if all tests pass, false otherwise
function bit32.selftest()
  print("Running 32-bit operations test vectors...")
  local passed = 0
  local total = 0

  --- @class B32TestVector
  --- @field name string Test name
  --- @field fn fun(...): integer Function to test
  --- @field inputs any Input values
  --- @field expected integer Expected result

  --- @type B32TestVector[]
  local test_vectors = {
    -- Mask function tests
    {
      name = "mask - zero",
      fn = bit32.mask,
      inputs = { 0 },
      expected = 0,
    },
    {
      name = "mask - max 32-bit",
      fn = bit32.mask,
      inputs = { 0xFFFFFFFF },
      expected = 0xFFFFFFFF,
    },
    {
      name = "mask - overflow",
      fn = bit32.mask,
      inputs = { 0x100000000 },
      expected = 0,
    },
    {
      name = "mask - negative",
      fn = bit32.mask,
      inputs = { -1 },
      expected = 0xFFFFFFFF,
    },

    -- AND operation tests
    {
      name = "AND - alternating bytes",
      fn = bit32.band,
      inputs = { 0xFF00FF00, 0x00FF00FF },
      expected = 0x00000000,
    },
    {
      name = "AND - all ones",
      fn = bit32.band,
      inputs = { 0xFFFFFFFF, 0xFFFFFFFF },
      expected = 0xFFFFFFFF,
    },
    {
      name = "AND - with zero",
      fn = bit32.band,
      inputs = { 0x12345678, 0 },
      expected = 0,
    },
    {
      name = "AND - single bit",
      fn = bit32.band,
      inputs = { 0x80000000, 0x80000000 },
      expected = 0x80000000,
    },

    -- OR operation tests
    {
      name = "OR - alternating bytes",
      fn = bit32.bor,
      inputs = { 0xFF00FF00, 0x00FF00FF },
      expected = 0xFFFFFFFF,
    },
    {
      name = "OR - all zeros",
      fn = bit32.bor,
      inputs = { 0, 0 },
      expected = 0,
    },
    {
      name = "OR - with max",
      fn = bit32.bor,
      inputs = { 0x12345678, 0xFFFFFFFF },
      expected = 0xFFFFFFFF,
    },

    -- XOR operation tests
    {
      name = "XOR - alternating bytes",
      fn = bit32.bxor,
      inputs = { 0xFF00FF00, 0x00FF00FF },
      expected = 0xFFFFFFFF,
    },
    {
      name = "XOR - same values",
      fn = bit32.bxor,
      inputs = { 0x12345678, 0x12345678 },
      expected = 0,
    },
    {
      name = "XOR - with zero",
      fn = bit32.bxor,
      inputs = { 0x12345678, 0 },
      expected = 0x12345678,
    },

    -- NOT operation tests
    {
      name = "NOT - alternating bytes",
      fn = bit32.bnot,
      inputs = { 0xFF00FF00 },
      expected = 0x00FF00FF,
    },
    {
      name = "NOT - zero",
      fn = bit32.bnot,
      inputs = { 0 },
      expected = 0xFFFFFFFF,
    },
    {
      name = "NOT - max value",
      fn = bit32.bnot,
      inputs = { 0xFFFFFFFF },
      expected = 0,
    },
    {
      name = "NOT - single bit",
      fn = bit32.bnot,
      inputs = { 1 },
      expected = 0xFFFFFFFE,
    },

    -- Left shift tests
    {
      name = "lshift - by 8",
      fn = bit32.lshift,
      inputs = { 0x12345678, 8 },
      expected = 0x34567800,
    },
    {
      name = "lshift - by 0",
      fn = bit32.lshift,
      inputs = { 0x12345678, 0 },
      expected = 0x12345678,
    },
    {
      name = "lshift - by 31",
      fn = bit32.lshift,
      inputs = { 1, 31 },
      expected = 0x80000000,
    },
    {
      name = "lshift - by 32",
      fn = bit32.lshift,
      inputs = { 0x12345678, 32 },
      expected = 0,
    },

    -- Right shift tests
    {
      name = "rshift - by 8",
      fn = bit32.rshift,
      inputs = { 0x12345678, 8 },
      expected = 0x00123456,
    },
    {
      name = "rshift - by 0",
      fn = bit32.rshift,
      inputs = { 0x12345678, 0 },
      expected = 0x12345678,
    },
    {
      name = "rshift - by 31",
      fn = bit32.rshift,
      inputs = { 0x80000000, 31 },
      expected = 1,
    },
    {
      name = "rshift - by 32",
      fn = bit32.rshift,
      inputs = { 0x12345678, 32 },
      expected = 0,
    },

    -- Left rotate tests
    {
      name = "rol - by 8",
      fn = bit32.rol,
      inputs = { 0x12345678, 8 },
      expected = 0x34567812,
    },
    {
      name = "rol - by 0",
      fn = bit32.rol,
      inputs = { 0x12345678, 0 },
      expected = 0x12345678,
    },
    {
      name = "rol - by 32",
      fn = bit32.rol,
      inputs = { 0x12345678, 32 },
      expected = 0x12345678,
    },
    {
      name = "rol - by 16",
      fn = bit32.rol,
      inputs = { 0x12345678, 16 },
      expected = 0x56781234,
    },

    -- Right rotate tests
    {
      name = "ror - by 8",
      fn = bit32.ror,
      inputs = { 0x12345678, 8 },
      expected = 0x78123456,
    },
    {
      name = "ror - by 0",
      fn = bit32.ror,
      inputs = { 0x12345678, 0 },
      expected = 0x12345678,
    },
    {
      name = "ror - by 32",
      fn = bit32.ror,
      inputs = { 0x12345678, 32 },
      expected = 0x12345678,
    },
    {
      name = "ror - by 16",
      fn = bit32.ror,
      inputs = { 0x12345678, 16 },
      expected = 0x56781234,
    },

    -- Addition tests
    {
      name = "add - with overflow",
      fn = bit32.add,
      inputs = { 0xFFFFFFFF, 0x00000002 },
      expected = 0x00000001,
    },
    {
      name = "add - zero + zero",
      fn = bit32.add,
      inputs = { 0, 0 },
      expected = 0,
    },
    {
      name = "add - max + zero",
      fn = bit32.add,
      inputs = { 0xFFFFFFFF, 0 },
      expected = 0xFFFFFFFF,
    },
    {
      name = "add - half overflow",
      fn = bit32.add,
      inputs = { 0x80000000, 0x80000000 },
      expected = 0,
    },
    {
      name = "add - normal",
      fn = bit32.add,
      inputs = { 0x12345678, 0x87654321 },
      expected = 0x99999999,
    },
  }
  ---@diagnostic disable-next-line: access-invisible
  local unpack_fn = unpack or table.unpack

  for _, test in ipairs(test_vectors) do
    total = total + 1
    local result = test.fn(unpack_fn(test.inputs))
    if result == test.expected then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name)
      print(string.format("    Expected: 0x%08X", test.expected))
      print(string.format("    Got:      0x%08X", result))
    end
  end

  print(string.format("\n32-bit operations result: %d/%d tests passed\n", passed, total))
  return passed == total
end

return bit32
