--- Main chunk of build/noiseprotocol-tests.lua, the with-tests build: the library, as
--- `require("noiseprotocol")` returns it, plus `selftest()` over the suites in test/.

--- @class noiseprotocol.with_tests: noiseprotocol
local noiseprotocol = require("noiseprotocol")
local test_utils_bytes = require("test_utils_bytes")
local test_noiseprotocol = require("test_noiseprotocol")

--- Run the byte-utility tests, then the protocol's vectors and functional tests.
--- @return boolean result True if all tests pass, false otherwise
function noiseprotocol.selftest()
  local bytes_ok = test_utils_bytes()
  return test_noiseprotocol() and bytes_ok
end

return noiseprotocol
