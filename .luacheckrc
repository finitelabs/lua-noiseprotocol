std = "min"
globals = {
 unpack = {}
}
ignore = {
  "212/_.*",
  "211/_.*",
  "213/_.*",
}
compat = true
unused_args = false
max_line_length = false

-- The stub replaces string.pack and string.unpack on purpose.
files["test/lpack_stub.lua"] = { ignore = { "122" } }
