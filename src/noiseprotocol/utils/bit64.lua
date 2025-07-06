--- @module "noiseprotocol.utils.bit64"
--- 64-bit bitwise operations using high/low pairs

local bit32 = require("noiseprotocol.utils.bit32")

local bit64 = {}

-- Type definitions
--- @alias Int64HighLow [integer, integer] Array with [1]=high 32 bits, [2]=low 32 bits

--- 64-bit addition
--- @param a Int64HighLow First operand {high, low}
--- @param b Int64HighLow Second operand {high, low}
--- @return Int64HighLow result {high, low} sum
function bit64.add(a, b)
  local low = a[2] + b[2]
  local high = a[1] + b[1]

  -- Handle carry from low to high
  if low >= 0x100000000 then
    high = high + 1
    low = low % 0x100000000
  end

  -- Keep high within 32 bits
  high = high % 0x100000000

  return { high, low }
end

--- 64-bit right rotate
--- @param x Int64HighLow Value to rotate {high, low}
--- @param n integer Number of positions to rotate
--- @return Int64HighLow result {high, low} rotated value
function bit64.ror(x, n)
  n = n % 64
  if n == 0 then
    return { x[1], x[2] }
  end

  local high, low = x[1], x[2]

  if n == 32 then
    -- Special case: swap high and low
    return { low, high }
  elseif n < 32 then
    -- Rotate within 32-bit boundaries
    local new_low = bit32.bor(bit32.rshift(low, n), bit32.lshift(high, 32 - n))
    local new_high = bit32.bor(bit32.rshift(high, n), bit32.lshift(low, 32 - n))
    return { new_high, new_low }
  else
    -- n > 32: rotate by (n - 32) after swapping
    n = n - 32
    local new_low = bit32.bor(bit32.rshift(high, n), bit32.lshift(low, 32 - n))
    local new_high = bit32.bor(bit32.rshift(low, n), bit32.lshift(high, 32 - n))
    return { new_high, new_low }
  end
end

--- 64-bit right shift
--- @param x Int64HighLow Value to shift {high, low}
--- @param n integer Number of positions to shift
--- @return Int64HighLow result {high, low} shifted value
function bit64.shr(x, n)
  if n == 0 then
    return { x[1], x[2] }
  elseif n >= 64 then
    return { 0, 0 }
  elseif n >= 32 then
    -- Shift by 32 or more: high becomes 0, low gets bits from high
    return { 0, bit32.rshift(x[1], n - 32) }
  else
    -- Shift by less than 32
    local new_low = bit32.bor(bit32.rshift(x[2], n), bit32.lshift(x[1], 32 - n))
    local new_high = bit32.rshift(x[1], n)
    return { new_high, new_low }
  end
end

--- 64-bit XOR
--- @param a Int64HighLow First operand {high, low}
--- @param b Int64HighLow Second operand {high, low}
--- @return Int64HighLow result {high, low} XOR result
function bit64.xor(a, b)
  return {
    bit32.bxor(a[1], b[1]),
    bit32.bxor(a[2], b[2]),
  }
end

--- 64-bit AND
--- @param a Int64HighLow First operand {high, low}
--- @param b Int64HighLow Second operand {high, low}
--- @return Int64HighLow result {high, low} AND result
function bit64.band(a, b)
  return {
    bit32.band(a[1], b[1]),
    bit32.band(a[2], b[2]),
  }
end

--- 64-bit NOT
--- @param a Int64HighLow Operand {high, low}
--- @return Int64HighLow result {high, low} NOT result
function bit64.bnot(a)
  return {
    bit32.bnot(a[1]),
    bit32.bnot(a[2]),
  }
end

--- Run comprehensive self-test with test vectors
--- @return boolean result True if all tests pass, false otherwise
function bit64.selftest()
  print("Running 64-bit operations test vectors...")
  local passed = 0
  local total = 0

  --- @class B64TestVector
  --- @field name string Test name
  --- @field fn fun(...): Int64HighLow Function to test
  --- @field inputs any Input values
  --- @field expected Int64HighLow Expected result {high, low}

  --- @type B64TestVector[]
  local test_vectors = {
    -- Addition tests
    {
      name = "add - normal with carry",
      fn = bit64.add,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, { 0x87654321, 0x12345678 } },
      expected = { 0x99999999, 0xACF13568 },
    },
    {
      name = "add - zero + zero",
      fn = bit64.add,
      inputs = { { 0, 0 }, { 0, 0 } },
      expected = { 0, 0 },
    },
    {
      name = "add - max + zero",
      fn = bit64.add,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF }, { 0, 0 } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFF },
    },
    {
      name = "add - overflow in low word only",
      fn = bit64.add,
      inputs = { { 0, 0xFFFFFFFF }, { 0, 1 } },
      expected = { 1, 0 },
    },
    {
      name = "add - overflow in high word",
      fn = bit64.add,
      inputs = { { 0xFFFFFFFF, 0 }, { 1, 0 } },
      expected = { 0, 0 },
    },
    {
      name = "add - double overflow",
      fn = bit64.add,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF }, { 0, 1 } },
      expected = { 0, 0 },
    },
    {
      name = "add - max + max",
      fn = bit64.add,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF }, { 0xFFFFFFFF, 0xFFFFFFFF } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFE },
    },

    -- XOR tests
    {
      name = "xor - alternating patterns",
      fn = bit64.xor,
      inputs = { { 0xFFFFFFFF, 0x00000000 }, { 0x00000000, 0xFFFFFFFF } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFF },
    },
    {
      name = "xor - same values",
      fn = bit64.xor,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, { 0x12345678, 0x9ABCDEF0 } },
      expected = { 0, 0 },
    },
    {
      name = "xor - with zero",
      fn = bit64.xor,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, { 0, 0 } },
      expected = { 0x12345678, 0x9ABCDEF0 },
    },
    {
      name = "xor - all ones",
      fn = bit64.xor,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF }, { 0xFFFFFFFF, 0xFFFFFFFF } },
      expected = { 0, 0 },
    },

    -- AND tests
    {
      name = "and - alternating patterns",
      fn = bit64.band,
      inputs = { { 0xFFFF0000, 0x0000FFFF }, { 0x0000FFFF, 0xFFFF0000 } },
      expected = { 0x00000000, 0x00000000 },
    },
    {
      name = "and - all ones",
      fn = bit64.band,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF }, { 0xFFFFFFFF, 0xFFFFFFFF } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFF },
    },
    {
      name = "and - with zero",
      fn = bit64.band,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, { 0, 0 } },
      expected = { 0, 0 },
    },
    {
      name = "and - single bit high",
      fn = bit64.band,
      inputs = { { 0x80000000, 0 }, { 0x80000000, 0 } },
      expected = { 0x80000000, 0 },
    },
    {
      name = "and - single bit low",
      fn = bit64.band,
      inputs = { { 0, 1 }, { 0, 1 } },
      expected = { 0, 1 },
    },

    -- NOT tests
    {
      name = "not - alternating pattern",
      fn = bit64.bnot,
      inputs = { { 0xFFFF0000, 0x0000FFFF } },
      expected = { 0x0000FFFF, 0xFFFF0000 },
    },
    {
      name = "not - zero",
      fn = bit64.bnot,
      inputs = { { 0, 0 } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFF },
    },
    {
      name = "not - max",
      fn = bit64.bnot,
      inputs = { { 0xFFFFFFFF, 0xFFFFFFFF } },
      expected = { 0, 0 },
    },
    {
      name = "not - single bit",
      fn = bit64.bnot,
      inputs = { { 0, 1 } },
      expected = { 0xFFFFFFFF, 0xFFFFFFFE },
    },

    -- Right rotate tests
    {
      name = "ror - by 16",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 16 },
      expected = { 0xDEF01234, 0x56789ABC },
    },
    {
      name = "ror - by 0",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 0 },
      expected = { 0x12345678, 0x9ABCDEF0 },
    },
    {
      name = "ror - by 32 (swap)",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 32 },
      expected = { 0x9ABCDEF0, 0x12345678 },
    },
    {
      name = "ror - by 64 (full rotation)",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 64 },
      expected = { 0x12345678, 0x9ABCDEF0 },
    },
    {
      name = "ror - by 48 (n > 32)",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 48 },
      expected = { 0x56789ABC, 0xDEF01234 },
    },
    {
      name = "ror - by 8",
      fn = bit64.ror,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 8 },
      expected = { 0xF0123456, 0x789ABCDE },
    },

    -- Right shift tests
    {
      name = "shr - by 16",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 16 },
      expected = { 0x00001234, 0x56789ABC },
    },
    {
      name = "shr - by 0",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 0 },
      expected = { 0x12345678, 0x9ABCDEF0 },
    },
    {
      name = "shr - by 32",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 32 },
      expected = { 0, 0x12345678 },
    },
    {
      name = "shr - by 63",
      fn = bit64.shr,
      inputs = { { 0x80000000, 0 }, 63 },
      expected = { 0, 1 },
    },
    {
      name = "shr - by 64",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 64 },
      expected = { 0, 0 },
    },
    {
      name = "shr - by >64",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 100 },
      expected = { 0, 0 },
    },
    {
      name = "shr - by 48 (n > 32)",
      fn = bit64.shr,
      inputs = { { 0x12345678, 0x9ABCDEF0 }, 48 },
      expected = { 0, 0x00001234 },
    },
  }
  ---@diagnostic disable-next-line: access-invisible
  local unpack_fn = unpack or table.unpack

  for _, test in ipairs(test_vectors) do
    total = total + 1
    local result = test.fn(unpack_fn(test.inputs))
    if result[1] == test.expected[1] and result[2] == test.expected[2] then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name)
      print(string.format("    Expected: {0x%08X, 0x%08X}", test.expected[1], test.expected[2]))
      print(string.format("    Got:      {0x%08X, 0x%08X}", result[1], result[2]))
    end
  end

  print(string.format("\n64-bit operations result: %d/%d tests passed\n", passed, total))
  return passed == total
end

return bit64
