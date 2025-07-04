--- @module "utils"
--- Utility Library

local utils = {}

-- ============================================================================
-- BIT OPERATIONS
-- ============================================================================

-- 32-bit mask for ensuring results stay within 32-bit range
local MASK32 = 0xFFFFFFFF

--- Ensure value fits in 32-bit unsigned integer
--- @param n number Input value
--- @return integer result 32-bit unsigned integer
local function mask32(n)
  return math.floor(n % 0x100000000)
end

--- Bitwise AND operation
--- @param a integer First operand (32-bit)
--- @param b integer Second operand (32-bit)
--- @return integer result Result of a AND b
function utils.band32(a, b)
  a = mask32(a)
  b = mask32(b)

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
function utils.bor32(a, b)
  a = mask32(a)
  b = mask32(b)

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
function utils.bxor32(a, b)
  a = mask32(a)
  b = mask32(b)

  local result = 0
  local bit_val = 1

  for _ = 0, 31 do
    local bit_a = a % 2
    local bit_b = b % 2
    if bit_a ~= bit_b then
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

--- Bitwise NOT operation (32-bit)
--- @param a integer Operand (32-bit)
--- @return integer result Result of NOT a
function utils.bnot32(a)
  return utils.bxor32(mask32(a), MASK32)
end

--- Left shift operation
--- @param a integer Value to shift (32-bit)
--- @param n integer Number of positions to shift (0-31)
--- @return integer result Result of a << n
function utils.lshift32(a, n)
  a = mask32(a)
  n = n % 32

  if n == 0 then
    return a
  end

  local result = a
  for _ = 1, n do
    result = result * 2
  end

  return mask32(result)
end

--- Right shift operation (logical)
--- @param a integer Value to shift (32-bit)
--- @param n integer Number of positions to shift (0-31)
--- @return integer result Result of a >> n
function utils.rshift32(a, n)
  a = mask32(a)
  n = n % 32

  if n == 0 then
    return a
  end

  local result = a
  for _ = 1, n do
    result = math.floor(result / 2)
  end

  return result
end

--- Rotate left operation
--- @param a integer Value to rotate (32-bit)
--- @param n integer Number of positions to rotate (0-31)
--- @return integer result Result of rotating a left by n positions
function utils.rol32(a, n)
  a = mask32(a)
  n = n % 32

  if n == 0 then
    return a
  end

  local left_part = utils.lshift32(a, n)
  local right_part = utils.rshift32(a, 32 - n)

  return utils.bor32(left_part, right_part)
end

--- Rotate right operation
--- @param a integer Value to rotate (32-bit)
--- @param n integer Number of positions to rotate (0-31)
--- @return integer result Result of rotating a right by n positions
function utils.ror32(a, n)
  a = mask32(a)
  n = n % 32

  if n == 0 then
    return a
  end

  local right_part = utils.rshift32(a, n)
  local left_part = utils.lshift32(a, 32 - n)

  return utils.bor32(right_part, left_part)
end

--- Addition with 32-bit wrap
--- @param a integer First operand
--- @param b integer Second operand
--- @return integer result Result of (a + b) mod 2^32
function utils.add32(a, b)
  return mask32(a + b)
end

-- 64-bit arithmetic operations using 32-bit high/low pairs
-- These are used for algorithms like SHA-512 that require 64-bit arithmetic
-- but need to work within LuaJIT's 2^53-1 integer limit

--- @alias Int64HighLow [integer, integer]

--- Add two 64-bit numbers represented as {high, low} pairs
--- @param a Int64HighLow {high, low} first number
--- @param b Int64HighLow {high, low} second number
--- @return Int64HighLow {high, low} sum
function utils.add64(a, b)
  local low = a[2] + b[2]
  local high = a[1] + b[1] + math.floor(low / 0x100000000)
  return { utils.band32(high, 0xFFFFFFFF), utils.band32(low, 0xFFFFFFFF) }
end

--- Right rotate 64-bit number
--- @param x Int64HighLow {high, low} number to rotate
--- @param n integer rotation amount
--- @return Int64HighLow {high, low} rotated result
function utils.ror64(x, n)
  if n == 0 then
    return { x[1], x[2] }
  end
  n = n % 64 -- Normalize rotation amount
  if n >= 32 then
    -- Rotate by 32 or more: swap and continue
    return utils.ror64({ x[2], x[1] }, n - 32)
  end
  -- n < 32
  local high = utils.bor32(utils.rshift32(x[1], n), utils.band32(utils.lshift32(x[2], 32 - n), 0xFFFFFFFF))
  local low = utils.bor32(utils.rshift32(x[2], n), utils.band32(utils.lshift32(x[1], 32 - n), 0xFFFFFFFF))
  return { utils.band32(high, 0xFFFFFFFF), utils.band32(low, 0xFFFFFFFF) }
end

--- Right shift 64-bit number
--- @param x Int64HighLow {high, low} number to shift
--- @param n integer shift amount
--- @return Int64HighLow {high, low} shifted result
function utils.shr64(x, n)
  if n == 0 then
    return { x[1], x[2] }
  end
  if n >= 32 then
    return { 0, utils.rshift32(x[1], n - 32) }
  end
  -- n < 32
  local high = utils.rshift32(x[1], n)
  local low = utils.bor32(utils.rshift32(x[2], n), utils.lshift32(x[1], 32 - n))
  return { utils.band32(high, 0xFFFFFFFF), utils.band32(low, 0xFFFFFFFF) }
end

--- XOR two 64-bit numbers
--- @param a Int64HighLow {high, low} first number
--- @param b Int64HighLow {high, low} second number
--- @return Int64HighLow {high, low} XOR result
function utils.xor64(a, b)
  return { utils.bxor32(a[1], b[1]), utils.bxor32(a[2], b[2]) }
end

--- AND two 64-bit numbers
--- @param a Int64HighLow {high, low} first number
--- @param b Int64HighLow {high, low} second number
--- @return Int64HighLow {high, low} AND result
function utils.and64(a, b)
  return { utils.band32(a[1], b[1]), utils.band32(a[2], b[2]) }
end

--- NOT a 64-bit number
--- @param a Int64HighLow {high, low} number
--- @return Int64HighLow {high, low} NOT result
function utils.not64(a)
  return { utils.band32(utils.bnot32(a[1]), 0xFFFFFFFF), utils.band32(utils.bnot32(a[2]), 0xFFFFFFFF) }
end

-- ============================================================================
-- BYTE OPERATIONS
-- ============================================================================

--- Convert binary data to hex string
--- @param data string Binary data
--- @return string hex Lowercase hex string
function utils.to_hex(data)
  local hex = ""
  for i = 1, #data do
    hex = hex .. string.format("%02x", string.byte(data, i))
  end
  return hex
end

--- Convert hex string to binary data
--- @param hex string Hex string (case insensitive)
--- @return string data Binary data
function utils.from_hex(hex)
  -- Remove any whitespace and convert to lowercase
  hex = hex:gsub("%s+", ""):lower()

  -- Ensure even length
  if #hex % 2 ~= 0 then
    hex = "0" .. hex
  end

  local result = ""
  for i = 1, #hex, 2 do
    local byte_str = hex:sub(i, i + 1)
    local byte_val = tonumber(byte_str, 16)
    if not byte_val then
      error("Invalid hex character in string: " .. byte_str)
    end
    result = result .. string.char(byte_val)
  end
  return result
end

--- Convert 32-bit unsigned integer to 4 bytes (little-endian)
--- @param value integer 32-bit unsigned integer
--- @return string bytes 4-byte string in little-endian format
function utils.u32_to_le_bytes(value)
  value = value % 0x100000000 -- Ensure 32-bit
  return string.char(
    value % 256,
    math.floor(value / 256) % 256,
    math.floor(value / 65536) % 256,
    math.floor(value / 16777216) % 256
  )
end

--- Convert 32-bit unsigned integer to 4 bytes (big-endian)
--- @param value integer 32-bit unsigned integer
--- @return string bytes 4-byte string in big-endian format
function utils.u32_to_be_bytes(value)
  value = value % 0x100000000 -- Ensure 32-bit
  return string.char(
    math.floor(value / 16777216) % 256,
    math.floor(value / 65536) % 256,
    math.floor(value / 256) % 256,
    value % 256
  )
end

--- Convert 64-bit number (as {high, low} table) to 8 bytes (big-endian)
--- @param n Int64HighLow {high, low} 64-bit number representation
--- @return string bytes 8-byte string in big-endian format
function utils.u64_to_be_bytes(n)
  return string.char(
    utils.band32(utils.rshift32(n[1], 24), 0xFF),
    utils.band32(utils.rshift32(n[1], 16), 0xFF),
    utils.band32(utils.rshift32(n[1], 8), 0xFF),
    utils.band32(n[1], 0xFF),
    utils.band32(utils.rshift32(n[2], 24), 0xFF),
    utils.band32(utils.rshift32(n[2], 16), 0xFF),
    utils.band32(utils.rshift32(n[2], 8), 0xFF),
    utils.band32(n[2], 0xFF)
  )
end

--- Convert 4 bytes (little-endian) to 32-bit unsigned integer
--- @param data string 4-byte string
--- @param offset? integer Starting offset (default: 1)
--- @return integer value 32-bit unsigned integer
function utils.le_bytes_to_u32(data, offset)
  offset = offset or 1
  local a, b, c, d = string.byte(data, offset, offset + 3)
  return a + b * 256 + c * 65536 + d * 16777216
end

--- Convert 4 bytes (big-endian) to 32-bit unsigned integer
--- @param data string 4-byte string
--- @param offset? integer Starting offset (default: 1)
--- @return integer value 32-bit unsigned integer
function utils.be_bytes_to_u32(data, offset)
  offset = offset or 1
  local a, b, c, d = string.byte(data, offset, offset + 3)
  return d + c * 256 + b * 65536 + a * 16777216
end

--- Convert 8 bytes (big-endian) to 64-bit number (as {high, low} table)
--- @param data string 8-byte string in big-endian format
--- @param offset? integer Starting offset (default: 1)
--- @return Int64HighLow {high, low} 64-bit number representation
function utils.be_bytes_to_u64(data, offset)
  offset = offset or 1
  local b1, b2, b3, b4, b5, b6, b7, b8 = string.byte(data, offset, offset + 7)

  local high =
    utils.bor32(utils.bor32(utils.lshift32(b1, 24), utils.lshift32(b2, 16)), utils.bor32(utils.lshift32(b3, 8), b4))
  local low =
    utils.bor32(utils.bor32(utils.lshift32(b5, 24), utils.lshift32(b6, 16)), utils.bor32(utils.lshift32(b7, 8), b8))
  return { high, low }
end

--- XOR two byte strings of equal length
--- @param a string First byte string
--- @param b string Second byte string
--- @return string result XOR result
function utils.xor_bytes(a, b)
  if #a ~= #b then
    error("Byte strings must be of equal length for XOR operation")
  end

  local result = ""
  for i = 1, #a do
    local byte_a = string.byte(a, i)
    local byte_b = string.byte(b, i)
    result = result .. string.char(utils.bxor32(byte_a, byte_b))
  end
  return result
end

--- Compare two byte strings in constant time (for security)
--- @param a string First byte string
--- @param b string Second byte string
--- @return boolean equal True if strings are equal
function utils.constant_time_compare(a, b)
  if #a ~= #b then
    return false
  end

  local result = 0
  for i = 1, #a do
    local byte_a = string.byte(a, i)
    local byte_b = string.byte(b, i)
    result = utils.bor32(result, utils.bxor32(byte_a, byte_b))
  end

  return result == 0
end

--- Convert 64-bit unsigned integer {high, low} to 8 bytes (little-endian)
--- @param value Int64HighLow|integer 64-bit unsigned integer as {high, low} or single number
--- @return string bytes 8-byte string in little-endian format
function utils.u64_to_le_bytes(value)
  local low, high
  if type(value) == "table" then
    high, low = value[1], value[2]
  else
    -- For single numbers up to 2^53-1
    low = value % 0x100000000
    high = math.floor(value / 0x100000000)
  end

  return string.char(
    low % 256,
    math.floor(low / 256) % 256,
    math.floor(low / 65536) % 256,
    math.floor(low / 16777216) % 256,
    high % 256,
    math.floor(high / 256) % 256,
    math.floor(high / 65536) % 256,
    math.floor(high / 16777216) % 256
  )
end

--- Convert 8 bytes (little-endian) to 64-bit number (as {high, low} table)
--- @param data string 8-byte string in little-endian format
--- @param offset? integer Starting offset (default: 1)
--- @return Int64HighLow {high, low} 64-bit number representation
function utils.le_bytes_to_u64(data, offset)
  offset = offset or 1
  local b1, b2, b3, b4, b5, b6, b7, b8 = string.byte(data, offset, offset + 7)

  local low =
    utils.bor32(utils.bor32(utils.lshift32(b4, 24), utils.lshift32(b3, 16)), utils.bor32(utils.lshift32(b2, 8), b1))
  local high =
    utils.bor32(utils.bor32(utils.lshift32(b8, 24), utils.lshift32(b7, 16)), utils.bor32(utils.lshift32(b6, 8), b5))
  return { high, low }
end

--- Pad data to 16-byte boundary
--- @param data string Input data
--- @return string padded_data Data padded to 16-byte boundary
function utils.pad_to_16(data)
  local len = #data
  local padding_len = (16 - (len % 16)) % 16
  if padding_len == 0 then
    return data
  else
    return data .. string.rep("\0", padding_len)
  end
end


--- Run comprehensive self-test for all utils functions
--- @return boolean result True if all tests pass, false otherwise
function utils.selftest()
  local function test_32bit_operations()
    print("Running 32-bit operations test vectors...")
    local passed = 0
    local total = 9

    -- Test AND
    if utils.band32(0xFF, 0xAA) == 0xAA then
      print("  ✅ PASS: 32-bit AND operation")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit AND operation")
    end

    -- Test OR
    if utils.bor32(0x0F, 0xF0) == 0xFF then
      print("  ✅ PASS: 32-bit OR operation")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit OR operation")
    end

    -- Test XOR
    if utils.bxor32(0xFF, 0xAA) == 0x55 then
      print("  ✅ PASS: 32-bit XOR operation")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit XOR operation")
    end

    -- Test NOT
    if utils.bnot32(0x0) == 0xFFFFFFFF then
      print("  ✅ PASS: 32-bit NOT operation")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit NOT operation")
    end

    -- Test left shift
    if utils.lshift32(1, 4) == 16 then
      print("  ✅ PASS: 32-bit left shift")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit left shift")
    end

    -- Test right shift
    if utils.rshift32(16, 4) == 1 then
      print("  ✅ PASS: 32-bit right shift")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit right shift")
    end

    -- Test left rotate
    if utils.rol32(0x80000000, 1) == 1 then
      print("  ✅ PASS: 32-bit left rotate")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit left rotate")
    end

    -- Test right rotate
    if utils.ror32(1, 1) == 0x80000000 then
      print("  ✅ PASS: 32-bit right rotate")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit right rotate")
    end

    -- Test 32-bit addition
    if utils.add32(0xFFFFFFFF, 1) == 0 then
      print("  ✅ PASS: 32-bit addition with overflow")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit addition with overflow")
    end

    print(string.format("\n32-bit operations result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function test_64bit_operations()
    print("Running 64-bit operations test vectors...")
    local passed = 0
    local total = 6

    -- Test 64-bit addition
    local a64 = { 0x12345678, 0x9ABCDEF0 }
    local b64 = { 0x87654321, 0x0FEDCBA9 }
    local sum64 = utils.add64(a64, b64)
    if sum64[1] == 0x99999999 and sum64[2] == 0xAAAAAA99 then
      print("  ✅ PASS: 64-bit addition")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit addition")
    end

    -- Test 64-bit XOR
    local xor64_result = utils.xor64(a64, b64)
    if xor64_result[1] == 0x95511559 and xor64_result[2] == 0x95511559 then
      print("  ✅ PASS: 64-bit XOR")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit XOR")
    end

    -- Test 64-bit AND
    local and64_result = utils.and64(a64, b64)
    if and64_result[1] == 0x02244220 and and64_result[2] == 0x0AACCAA0 then
      print("  ✅ PASS: 64-bit AND")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit AND")
    end

    -- Test 64-bit NOT
    local not64_result = utils.not64(a64)
    if not64_result[1] == 0xEDCBA987 and not64_result[2] == 0x6543210F then
      print("  ✅ PASS: 64-bit NOT")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit NOT")
    end

    -- Test 64-bit right rotate
    local ror64_result = utils.ror64(a64, 8)
    if ror64_result[1] == 0xF0123456 and ror64_result[2] == 0x789ABCDE then
      print("  ✅ PASS: 64-bit right rotate")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit right rotate")
    end

    -- Test 64-bit right shift
    local shr64_result = utils.shr64(a64, 8)
    if shr64_result[1] == 0x00123456 and shr64_result[2] == 0x789ABCDE then
      print("  ✅ PASS: 64-bit right shift")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit right shift")
    end

    print(string.format("\n64-bit operations result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function test_byte_operations()
    print("Running byte operations test vectors...")
    local passed = 0
    local total = 6

    -- Test hex conversion
    local test_bytes = string.char(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF)
    local hex_result = utils.to_hex(test_bytes)
    local expected_hex = "0123456789abcdef"
    if hex_result == expected_hex then
      print("  ✅ PASS: Hex conversion")
      passed = passed + 1
    else
      print("  ❌ FAIL: Hex conversion")
    end

    -- Test from_hex conversion
    local from_hex_result = utils.from_hex(expected_hex)
    if from_hex_result == test_bytes then
      print("  ✅ PASS: From hex conversion")
      passed = passed + 1
    else
      print("  ❌ FAIL: From hex conversion")
    end

    -- Test 32-bit little-endian conversions
    local val32 = 0x12345678
    local le_bytes = utils.u32_to_le_bytes(val32)
    local le_back = utils.le_bytes_to_u32(le_bytes)
    if le_back == val32 then
      print("  ✅ PASS: 32-bit little-endian conversions")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit little-endian conversions")
    end

    -- Test 32-bit big-endian conversions
    local be_bytes = utils.u32_to_be_bytes(val32)
    local be_back = utils.be_bytes_to_u32(be_bytes)
    if be_back == val32 then
      print("  ✅ PASS: 32-bit big-endian conversions")
      passed = passed + 1
    else
      print("  ❌ FAIL: 32-bit big-endian conversions")
    end

    -- Test 64-bit little-endian conversions
    local val64 = { 0x12345678, 0x9ABCDEF0 }
    local le64_bytes = utils.u64_to_le_bytes(val64)
    local le64_back = utils.le_bytes_to_u64(le64_bytes)
    if le64_back[1] == val64[1] and le64_back[2] == val64[2] then
      print("  ✅ PASS: 64-bit little-endian conversions")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit little-endian conversions")
    end

    -- Test 64-bit big-endian conversions
    local be64_bytes = utils.u64_to_be_bytes(val64)
    local be64_back = utils.be_bytes_to_u64(be64_bytes)
    if be64_back[1] == val64[1] and be64_back[2] == val64[2] then
      print("  ✅ PASS: 64-bit big-endian conversions")
      passed = passed + 1
    else
      print("  ❌ FAIL: 64-bit big-endian conversions")
    end

    print(string.format("\nByte operations result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local bit32_passed = test_32bit_operations()
  local bit64_passed = test_64bit_operations()
  local byte_passed = test_byte_operations()

  return bit32_passed and bit64_passed and byte_passed
end

return utils
