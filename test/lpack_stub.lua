--- @diagnostic disable: duplicate-set-field
-- Installs string.pack/string.unpack in the shape Control4's LuaJIT ships (lpack),
-- as measured on a controller: single-letter codes with no size suffix, '<' and
-- '=' little-endian, '>' big-endian, a NUL ends the format, a digit or unknown
-- code raises, and unpack(data, fmt, pos) returns the next position before the
-- values, with nil for a value the data cannot supply. Loaded ahead of bitn so a
-- byte helper that assumes the 5.3 dialect fails here rather than on a controller.
local SIZE = { b = 1, B = 1, c = 1, h = 2, H = 2, i = 4, I = 4, l = 4, L = 4 }

local function pack_int(value, size, big_endian)
  value = value % 2 ^ (8 * size)
  local out = {}
  for _ = 1, size do
    out[#out + 1] = string.char(value % 256)
    value = math.floor(value / 256)
  end
  if big_endian then
    local reversed = {}
    for i = size, 1, -1 do
      reversed[#reversed + 1] = out[i]
    end
    out = reversed
  end
  return table.concat(out)
end

local function unpack_int(data, pos, size, big_endian)
  if #data < pos + size - 1 then
    return pos, nil
  end
  local value = 0
  for i = 0, size - 1 do
    local weight = big_endian and (size - 1 - i) or i
    value = value + string.byte(data, pos + i) * 2 ^ (8 * weight)
  end
  return pos + size, value
end

local function codes(fmt)
  local out = {}
  for c in fmt:gmatch(".") do
    if c == "\0" then
      break
    end
    out[#out + 1] = c
  end
  return out
end

function string.pack(fmt, ...)
  local args, i, out, big_endian = { ... }, 0, {}, false
  for _, c in ipairs(codes(fmt)) do
    if c == "<" or c == "=" then
      big_endian = false
    elseif c == ">" then
      big_endian = true
    elseif SIZE[c] then
      i = i + 1
      out[#out + 1] = pack_int(args[i], SIZE[c], big_endian)
    else
      error("lpack stub: unsupported code '" .. c .. "'")
    end
  end
  return table.concat(out)
end

function string.unpack(data, fmt, pos)
  pos = pos or 1
  local out, n, big_endian = {}, 0, false
  for _, c in ipairs(codes(fmt)) do
    if c == "<" or c == "=" then
      big_endian = false
    elseif c == ">" then
      big_endian = true
    elseif SIZE[c] then
      n = n + 1
      pos, out[n] = unpack_int(data, pos, SIZE[c], big_endian)
    else
      error("lpack stub: unsupported code '" .. c .. "'")
    end
  end
  return pos, (table.unpack or unpack)(out, 1, n)
end
