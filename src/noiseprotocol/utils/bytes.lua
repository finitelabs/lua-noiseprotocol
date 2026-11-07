--- @module "noiseprotocol.utils.bytes"
--- Byte manipulation and conversion utilities
--- @class noiseprotocol.utils.bytes
local bytes = {}

local bitn = require("bitn")
local bit32 = bitn.bit32
local bit64 = bitn.bit64

-- Local references for performance
local bit32_raw_bor = bit32.raw_bor
local bit32_raw_bxor = bit32.raw_bxor
local bit32_u32_to_le_bytes = bit32.u32_to_le_bytes
local bit32_u32_to_be_bytes = bit32.u32_to_be_bytes
local bit32_le_bytes_to_u32 = bit32.le_bytes_to_u32
local bit32_be_bytes_to_u32 = bit32.be_bytes_to_u32
local bit64_from_number = bit64.from_number
local bit64_u64_to_le_bytes = bit64.u64_to_le_bytes
local bit64_u64_to_be_bytes = bit64.u64_to_be_bytes
local bit64_le_bytes_to_u64 = bit64.le_bytes_to_u64
local bit64_be_bytes_to_u64 = bit64.be_bytes_to_u64
local string_byte = string.byte
local string_char = string.char
local string_format = string.format
local string_rep = string.rep
local table_concat = table.concat

--- Convert binary string to hexadecimal string
--- @param str string Binary string
--- @return string hex Hexadecimal representation
function bytes.to_hex(str)
  return (str:gsub(".", function(c)
    return string_format("%02x", string_byte(c))
  end))
end

--- Convert hexadecimal string to binary string
--- @param hex string Hexadecimal string
--- @return string str Binary string
function bytes.from_hex(hex)
  return (hex:gsub("..", function(cc)
    return string_char(tonumber(cc, 16))
  end))
end

--- Convert 32-bit unsigned integer to 4 bytes (little-endian)
--- @param n integer 32-bit unsigned integer
--- @return string bytes 4-byte string in little-endian order
function bytes.u32_to_le_bytes(n)
  return bit32_u32_to_le_bytes(n)
end

--- Convert 32-bit unsigned integer to 4 bytes (big-endian)
--- @param n integer 32-bit unsigned integer
--- @return string bytes 4-byte string in big-endian order
function bytes.u32_to_be_bytes(n)
  return bit32_u32_to_be_bytes(n)
end

--- Convert 64-bit value to 8 bytes (big-endian)
--- @param x Int64HighLow {high, low} 64-bit value
--- @return string bytes 8-byte string in big-endian order
function bytes.u64_to_be_bytes(x)
  return bit64_u64_to_be_bytes(x)
end

--- Convert 64-bit value to 8 bytes (little-endian)
--- @param x Int64HighLow|integer {high, low} 64-bit value or simple integer
--- @return string bytes 8-byte string in little-endian order
function bytes.u64_to_le_bytes(x)
  if type(x) == "number" then
    return bit64_u64_to_le_bytes(bit64_from_number(x))
  end
  --- @cast x Int64HighLow
  return bit64_u64_to_le_bytes(x)
end

--- Convert 4 bytes to 32-bit unsigned integer (little-endian)
--- @param str string Binary string (at least 4 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return integer n 32-bit unsigned integer
function bytes.le_bytes_to_u32(str, offset)
  return bit32_le_bytes_to_u32(str, offset)
end

--- Convert 4 bytes to 32-bit unsigned integer (big-endian)
--- @param str string Binary string (at least 4 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return integer n 32-bit unsigned integer
function bytes.be_bytes_to_u32(str, offset)
  return bit32_be_bytes_to_u32(str, offset)
end

--- Convert 8 bytes to 64-bit value (big-endian)
--- @param str string Binary string (at least 8 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return Int64HighLow value {high, low} 64-bit value
function bytes.be_bytes_to_u64(str, offset)
  return bit64_be_bytes_to_u64(str, offset)
end

--- Convert 8 bytes to 64-bit value (little-endian)
--- @param str string Binary string (at least 8 bytes)
--- @param offset? integer Starting position (default: 1)
--- @return Int64HighLow value {high, low} 64-bit value
function bytes.le_bytes_to_u64(str, offset)
  return bit64_le_bytes_to_u64(str, offset)
end

--- XOR two byte strings
--- @param a string First byte string
--- @param b string Second byte string
--- @return string result XORed byte string
function bytes.xor_bytes(a, b)
  assert(#a == #b, "Strings must be same length for XOR")
  local result = {}
  -- Using raw_bxor for performance; XOR on bytes (0-255) is always safe
  for i = 1, #a do
    result[i] = string_char(bit32_raw_bxor(string_byte(a, i), string_byte(b, i)))
  end
  return table_concat(result)
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
    result = bit32_raw_bor(result, bit32_raw_bxor(string_byte(a, i), string_byte(b, i)))
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
  return data .. string_rep("\0", padding_len)
end

return bytes
