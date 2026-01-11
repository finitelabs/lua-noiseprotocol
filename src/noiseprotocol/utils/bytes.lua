--- @module "noiseprotocol.utils.bytes"
--- Byte manipulation and conversion utilities
local bytes = {}

local bit32 = require("vendor.bitn").bit32

--- Convert binary string to hexadecimal string
--- @param str string Binary string
--- @return string hex Hexadecimal representation
function bytes.to_hex(str)
  return (str:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

--- Convert hexadecimal string to binary string
--- @param hex string Hexadecimal string
--- @return string str Binary string
function bytes.from_hex(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

--- Convert 32-bit unsigned integer to 4 bytes (little-endian)
--- @param n integer 32-bit unsigned integer
--- @return string bytes 4-byte string in little-endian order
function bytes.u32_to_le_bytes(n)
  n = bit32.mask(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

--- Convert 32-bit unsigned integer to 4 bytes (big-endian)
--- @param n integer 32-bit unsigned integer
--- @return string bytes 4-byte string in big-endian order
function bytes.u32_to_be_bytes(n)
  n = bit32.mask(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

--- Convert 64-bit value to 8 bytes (big-endian)
--- @param x Int64HighLow|table {high, low} 64-bit value
--- @return string bytes 8-byte string in big-endian order
function bytes.u64_to_be_bytes(x)
  local high, low = x[1], x[2]
  return bytes.u32_to_be_bytes(high) .. bytes.u32_to_be_bytes(low)
end

--- Convert 64-bit value to 8 bytes (little-endian)
--- @param x Int64HighLow|table|integer {high, low} 64-bit value or simple integer
--- @return string bytes 8-byte string in little-endian order
function bytes.u64_to_le_bytes(x)
  -- Handle simple integer case (< 2^53)
  if type(x) == "number" then
    local low = x % 0x100000000
    local high = math.floor(x / 0x100000000)
    return bytes.u32_to_le_bytes(low) .. bytes.u32_to_le_bytes(high)
  else
    -- Handle {high, low} pair
    local high, low = x[1], x[2]
    return bytes.u32_to_le_bytes(low) .. bytes.u32_to_le_bytes(high)
  end
end

--- Convert 4 bytes to 32-bit unsigned integer (little-endian)
--- @param str string Binary string (at least 4 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return integer n 32-bit unsigned integer
function bytes.le_bytes_to_u32(str, offset)
  offset = offset or 1
  assert(#str >= offset + 3, "Insufficient bytes for u32")
  local b1, b2, b3, b4 = string.byte(str, offset, offset + 3)
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

--- Convert 4 bytes to 32-bit unsigned integer (big-endian)
--- @param str string Binary string (at least 4 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return integer n 32-bit unsigned integer
function bytes.be_bytes_to_u32(str, offset)
  offset = offset or 1
  assert(#str >= offset + 3, "Insufficient bytes for u32")
  local b1, b2, b3, b4 = string.byte(str, offset, offset + 3)
  return b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
end

--- Convert 8 bytes to 64-bit value (big-endian)
--- @param str string Binary string (at least 8 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return Int64HighLow value {high, low} 64-bit value
function bytes.be_bytes_to_u64(str, offset)
  offset = offset or 1
  assert(#str >= offset + 7, "Insufficient bytes for u64")
  local high = bytes.be_bytes_to_u32(str, offset)
  local low = bytes.be_bytes_to_u32(str, offset + 4)
  return { high, low }
end

--- Convert 8 bytes to 64-bit value (little-endian)
--- @param str string Binary string (at least 8 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return Int64HighLow value {high, low} 64-bit value
function bytes.le_bytes_to_u64(str, offset)
  offset = offset or 1
  assert(#str >= offset + 7, "Insufficient bytes for u64")
  local low = bytes.le_bytes_to_u32(str, offset)
  local high = bytes.le_bytes_to_u32(str, offset + 4)
  return { high, low }
end

--- XOR two byte strings
--- @param a string First byte string
--- @param b string Second byte string
--- @return string result XORed byte string
function bytes.xor_bytes(a, b)
  assert(#a == #b, "Strings must be same length for XOR")
  local result = {}
  for i = 1, #a do
    result[i] = string.char(bit32.bxor(string.byte(a, i), string.byte(b, i)))
  end
  return table.concat(result)
end

--- Constant-time comparison of two strings
--- @param a string First string
--- @param b string Second string
--- @return boolean equal True if strings are equal
function bytes.constant_time_compare(a, b)
  if #a ~= #b then
    return false
  end
  local result = 0
  for i = 1, #a do
    result = bit32.bor(result, bit32.bxor(string.byte(a, i), string.byte(b, i)))
  end
  return result == 0
end

--- Pad data to 16-byte boundary with zeros
--- @param data string Data to pad
--- @return string padded Padded data
function bytes.pad_to_16(data)
  local len = #data
  local padding_len = (16 - (len % 16)) % 16
  if padding_len == 0 then
    return data
  end
  return data .. string.rep("\0", padding_len)
end

--- Run comprehensive self-test with test vectors
--- @return boolean result True if all tests pass, false otherwise
function bytes.selftest()
  print("Running byte operations test vectors...")
  local passed = 0
  local total = 0

  local test_vectors = {
    -- Hex conversion tests
    {
      name = "hex - basic roundtrip",
      test = function()
        local data = "Hello"
        local hex = bytes.to_hex(data)
        local back = bytes.from_hex(hex)
        return hex == "48656c6c6f" and back == data
      end,
    },
    {
      name = "hex - empty string",
      test = function()
        local data = ""
        local hex = bytes.to_hex(data)
        local back = bytes.from_hex(hex)
        return hex == "" and back == ""
      end,
    },
    {
      name = "hex - single byte min",
      test = function()
        local data = string.char(0x00)
        local hex = bytes.to_hex(data)
        return hex == "00"
      end,
    },
    {
      name = "hex - single byte max",
      test = function()
        local data = string.char(0xFF)
        local hex = bytes.to_hex(data)
        return hex == "ff"
      end,
    },
    {
      name = "hex - all byte values",
      test = function()
        -- Test a few representative byte values
        local data = string.char(0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)
        local hex = bytes.to_hex(data)
        return hex == "00017f80feff"
      end,
    },
    {
      name = "hex - uppercase input",
      test = function()
        local hex = "48656C6C6F"
        local data = bytes.from_hex(hex)
        return data == "Hello"
      end,
    },
    {
      name = "hex - binary data",
      test = function()
        local data = string.char(0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0)
        local hex = bytes.to_hex(data)
        local back = bytes.from_hex(hex)
        return hex == "8090a0b0c0d0e0f0" and back == data
      end,
    },

    -- 32-bit conversion tests
    {
      name = "u32 LE - basic",
      test = function()
        local n = 0x12345678
        local bytes_str = bytes.u32_to_le_bytes(n)
        local back = bytes.le_bytes_to_u32(bytes_str)
        local b1, b2, b3, b4 = string.byte(bytes_str, 1, 4)
        return back == n and b1 == 0x78 and b2 == 0x56 and b3 == 0x34 and b4 == 0x12
      end,
    },
    {
      name = "u32 LE - zero",
      test = function()
        local n = 0
        local bytes_str = bytes.u32_to_le_bytes(n)
        local back = bytes.le_bytes_to_u32(bytes_str)
        return back == 0 and bytes_str == string.char(0, 0, 0, 0)
      end,
    },
    {
      name = "u32 LE - max value",
      test = function()
        local n = 0xFFFFFFFF
        local bytes_str = bytes.u32_to_le_bytes(n)
        local back = bytes.le_bytes_to_u32(bytes_str)
        return back == 0xFFFFFFFF and bytes_str == string.char(0xFF, 0xFF, 0xFF, 0xFF)
      end,
    },
    {
      name = "u32 LE - needs masking",
      test = function()
        local n = 0x100000000 -- Should be masked to 0
        local bytes_str = bytes.u32_to_le_bytes(n)
        return bytes_str == string.char(0, 0, 0, 0)
      end,
    },
    {
      name = "u32 LE - single bit patterns",
      test = function()
        local n = 0x80000000
        local bytes_str = bytes.u32_to_le_bytes(n)
        local back = bytes.le_bytes_to_u32(bytes_str)
        return back == 0x80000000 and bytes_str == string.char(0, 0, 0, 0x80)
      end,
    },
    {
      name = "u32 LE - with offset",
      test = function()
        local data = "XXX" .. string.char(0x78, 0x56, 0x34, 0x12) .. "YYY"
        local n = bytes.le_bytes_to_u32(data, 4)
        return n == 0x12345678
      end,
    },
    {
      name = "u32 BE - basic",
      test = function()
        local n = 0x12345678
        local bytes_str = bytes.u32_to_be_bytes(n)
        local back = bytes.be_bytes_to_u32(bytes_str)
        local b1, b2, b3, b4 = string.byte(bytes_str, 1, 4)
        return back == n and b1 == 0x12 and b2 == 0x34 and b3 == 0x56 and b4 == 0x78
      end,
    },
    {
      name = "u32 BE - zero",
      test = function()
        local n = 0
        local bytes_str = bytes.u32_to_be_bytes(n)
        local back = bytes.be_bytes_to_u32(bytes_str)
        return back == 0 and bytes_str == string.char(0, 0, 0, 0)
      end,
    },
    {
      name = "u32 BE - max value",
      test = function()
        local n = 0xFFFFFFFF
        local bytes_str = bytes.u32_to_be_bytes(n)
        local back = bytes.be_bytes_to_u32(bytes_str)
        return back == 0xFFFFFFFF and bytes_str == string.char(0xFF, 0xFF, 0xFF, 0xFF)
      end,
    },
    {
      name = "u32 BE - with offset",
      test = function()
        local data = "XXX" .. string.char(0x12, 0x34, 0x56, 0x78) .. "YYY"
        local n = bytes.be_bytes_to_u32(data, 4)
        return n == 0x12345678
      end,
    },

    -- 64-bit conversion tests
    {
      name = "u64 LE - basic table",
      test = function()
        local n = { 0x12345678, 0x9ABCDEF0 }
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        local b1, b2, b3, b4, b5, b6, b7, b8 = string.byte(bytes_str, 1, 8)
        return back[1] == n[1]
          and back[2] == n[2]
          and b1 == 0xF0
          and b2 == 0xDE
          and b3 == 0xBC
          and b4 == 0x9A
          and b5 == 0x78
          and b6 == 0x56
          and b7 == 0x34
          and b8 == 0x12
      end,
    },
    {
      name = "u64 LE - number input",
      test = function()
        local n = 0x123456789ABCD -- Small enough for Lua number
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        -- Check the conversion worked correctly
        local expected_low = n % 0x100000000
        local expected_high = math.floor(n / 0x100000000)
        return back[1] == expected_high and back[2] == expected_low
      end,
    },
    {
      name = "u64 LE - zero",
      test = function()
        local n = { 0, 0 }
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        return back[1] == 0 and back[2] == 0 and bytes_str == string.rep(string.char(0), 8)
      end,
    },
    {
      name = "u64 LE - max value",
      test = function()
        local n = { 0xFFFFFFFF, 0xFFFFFFFF }
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        return back[1] == 0xFFFFFFFF and back[2] == 0xFFFFFFFF and bytes_str == string.rep(string.char(0xFF), 8)
      end,
    },
    {
      name = "u64 LE - high word only",
      test = function()
        local n = { 0x12345678, 0 }
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        return back[1] == 0x12345678 and back[2] == 0
      end,
    },
    {
      name = "u64 LE - low word only",
      test = function()
        local n = { 0, 0x12345678 }
        local bytes_str = bytes.u64_to_le_bytes(n)
        local back = bytes.le_bytes_to_u64(bytes_str)
        return back[1] == 0 and back[2] == 0x12345678
      end,
    },
    {
      name = "u64 LE - with offset",
      test = function()
        local data = "XXX" .. bytes.u64_to_le_bytes({ 0x12345678, 0x9ABCDEF0 }) .. "YYY"
        local n = bytes.le_bytes_to_u64(data, 4)
        return n[1] == 0x12345678 and n[2] == 0x9ABCDEF0
      end,
    },
    {
      name = "u64 BE - basic",
      test = function()
        local n = { 0x12345678, 0x9ABCDEF0 }
        local bytes_str = bytes.u64_to_be_bytes(n)
        local back = bytes.be_bytes_to_u64(bytes_str)
        local b1, b2, b3, b4, b5, b6, b7, b8 = string.byte(bytes_str, 1, 8)
        return back[1] == n[1]
          and back[2] == n[2]
          and b1 == 0x12
          and b2 == 0x34
          and b3 == 0x56
          and b4 == 0x78
          and b5 == 0x9A
          and b6 == 0xBC
          and b7 == 0xDE
          and b8 == 0xF0
      end,
    },
    {
      name = "u64 BE - zero",
      test = function()
        local n = { 0, 0 }
        local bytes_str = bytes.u64_to_be_bytes(n)
        local back = bytes.be_bytes_to_u64(bytes_str)
        return back[1] == 0 and back[2] == 0 and bytes_str == string.rep(string.char(0), 8)
      end,
    },
    {
      name = "u64 BE - with offset",
      test = function()
        local data = "XXX" .. bytes.u64_to_be_bytes({ 0x12345678, 0x9ABCDEF0 }) .. "YYY"
        local n = bytes.be_bytes_to_u64(data, 4)
        return n[1] == 0x12345678 and n[2] == 0x9ABCDEF0
      end,
    },

    -- XOR tests
    {
      name = "xor - basic",
      test = function()
        local a = string.char(0x01, 0x02, 0x03, 0x04)
        local b = string.char(0xFF, 0xFE, 0xFD, 0xFC)
        local result = bytes.xor_bytes(a, b)
        local r1, r2, r3, r4 = string.byte(result, 1, 4)
        return r1 == 0xFE and r2 == 0xFC and r3 == 0xFE and r4 == 0xF8
      end,
    },
    {
      name = "xor - empty strings",
      test = function()
        local a = ""
        local b = ""
        local result = bytes.xor_bytes(a, b)
        return result == ""
      end,
    },
    {
      name = "xor - single byte",
      test = function()
        local a = string.char(0x00)
        local b = string.char(0xFF)
        local result = bytes.xor_bytes(a, b)
        return result == string.char(0xFF)
      end,
    },
    {
      name = "xor - with self",
      test = function()
        local a = "test"
        local result = bytes.xor_bytes(a, a)
        return result == string.char(0, 0, 0, 0)
      end,
    },
    {
      name = "xor - all zeros pattern",
      test = function()
        local a = string.char(0xAA, 0xBB, 0xCC, 0xDD)
        local b = string.char(0xAA, 0xBB, 0xCC, 0xDD)
        local result = bytes.xor_bytes(a, b)
        return result == string.char(0, 0, 0, 0)
      end,
    },
    {
      name = "xor - identity with zeros",
      test = function()
        local a = string.char(0x12, 0x34, 0x56, 0x78)
        local b = string.char(0, 0, 0, 0)
        local result = bytes.xor_bytes(a, b)
        return result == a
      end,
    },

    -- Constant-time comparison tests
    {
      name = "constant_time_compare - equal",
      test = function()
        local a = "test"
        local b = "test"
        return bytes.constant_time_compare(a, b) == true
      end,
    },
    {
      name = "constant_time_compare - not equal",
      test = function()
        local a = "test"
        local b = "text"
        return bytes.constant_time_compare(a, b) == false
      end,
    },
    {
      name = "constant_time_compare - different lengths",
      test = function()
        local a = "test"
        local b = "testing"
        return bytes.constant_time_compare(a, b) == false
      end,
    },
    {
      name = "constant_time_compare - empty strings",
      test = function()
        local a = ""
        local b = ""
        return bytes.constant_time_compare(a, b) == true
      end,
    },
    {
      name = "constant_time_compare - single char equal",
      test = function()
        local a = "a"
        local b = "a"
        return bytes.constant_time_compare(a, b) == true
      end,
    },
    {
      name = "constant_time_compare - single char not equal",
      test = function()
        local a = "a"
        local b = "b"
        return bytes.constant_time_compare(a, b) == false
      end,
    },
    {
      name = "constant_time_compare - binary with nulls",
      test = function()
        local a = string.char(0x00, 0x01, 0xFF)
        local b = string.char(0x00, 0x01, 0xFF)
        return bytes.constant_time_compare(a, b) == true
      end,
    },

    -- Padding tests
    {
      name = "pad_to_16 - no padding needed",
      test = function()
        local data = string.rep("a", 16)
        local padded = bytes.pad_to_16(data)
        return padded == data and #padded == 16
      end,
    },
    {
      name = "pad_to_16 - padding needed",
      test = function()
        local data = "Hello"
        local padded = bytes.pad_to_16(data)
        return #padded == 16 and padded:sub(1, 5) == "Hello" and padded:sub(6) == string.rep("\0", 11)
      end,
    },
    {
      name = "pad_to_16 - empty string",
      test = function()
        local data = ""
        local padded = bytes.pad_to_16(data)
        return padded == "" and #padded == 0
      end,
    },
    {
      name = "pad_to_16 - exactly 32 bytes",
      test = function()
        local data = string.rep("a", 32)
        local padded = bytes.pad_to_16(data)
        return padded == data and #padded == 32
      end,
    },
    {
      name = "pad_to_16 - one byte short",
      test = function()
        local data = string.rep("a", 15)
        local padded = bytes.pad_to_16(data)
        return #padded == 16 and padded:sub(1, 15) == data and padded:sub(16) == "\0"
      end,
    },
    {
      name = "pad_to_16 - one byte over",
      test = function()
        local data = string.rep("a", 17)
        local padded = bytes.pad_to_16(data)
        return #padded == 32 and padded:sub(1, 17) == data and padded:sub(18) == string.rep("\0", 15)
      end,
    },
    {
      name = "pad_to_16 - large data",
      test = function()
        local data = string.rep("a", 1000)
        local padded = bytes.pad_to_16(data)
        local expected_len = math.ceil(1000 / 16) * 16
        return #padded == expected_len and padded:sub(1, 1000) == data
      end,
    },
  }

  -- Run error handling tests separately with pcall
  local error_tests = {
    {
      name = "u32 LE - insufficient bytes",
      test = function()
        local ok, err = pcall(bytes.le_bytes_to_u32, "XX")
        return not ok and err:match("Insufficient bytes")
      end,
    },
    {
      name = "u32 BE - insufficient bytes",
      test = function()
        local ok, err = pcall(bytes.be_bytes_to_u32, "XX")
        return not ok and err:match("Insufficient bytes")
      end,
    },
    {
      name = "u64 LE - insufficient bytes",
      test = function()
        local ok, err = pcall(bytes.le_bytes_to_u64, "XXXXXX")
        return not ok and err:match("Insufficient bytes")
      end,
    },
    {
      name = "u64 BE - insufficient bytes",
      test = function()
        local ok, err = pcall(bytes.be_bytes_to_u64, "XXXXXX")
        return not ok and err:match("Insufficient bytes")
      end,
    },
    {
      name = "xor - length mismatch",
      test = function()
        local ok, err = pcall(bytes.xor_bytes, "abc", "abcd")
        return not ok and err:match("same length")
      end,
    },
  }

  -- Run main tests
  for _, test in ipairs(test_vectors) do
    total = total + 1
    if test.test() then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name)
    end
  end

  -- Run error tests
  for _, test in ipairs(error_tests) do
    total = total + 1
    if test.test() then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name)
    end
  end

  print(string.format("\nByte operations result: %d/%d tests passed\n", passed, total))
  return passed == total
end

return bytes
