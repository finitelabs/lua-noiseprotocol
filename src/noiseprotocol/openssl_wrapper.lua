--- @module "noiseprotocol.openssl_wrapper"
--- OpenSSL wrapper for the Noise Protocol Framework
---
--- This module provides a centralized interface for enabling and accessing OpenSSL
--- acceleration for cryptographic operations. OpenSSL support can be enabled via:
--- 1. Environment variable: NOISE_USE_OPENSSL=1 or NOISE_USE_OPENSSL=true
--- 2. Calling noise.use_openssl(true/false) from the main module
---
--- By default, native Lua implementations are used for maximum portability.
--- When OpenSSL is enabled and available, it provides hardware-accelerated
--- implementations for:
--- - SHA256/SHA512 hash functions
--- - BLAKE2s/BLAKE2b hash functions
--- - ChaCha20-Poly1305 AEAD cipher
--- - AES-GCM AEAD cipher
--- - ChaCha20 stream cipher
---
--- Note: X25519 and X448 currently use native implementations only as they are
--- not currently supported by lua-openssl.

local openssl_wrapper = {}

local _openssl_module
local _use_openssl = os.getenv("NOISE_USE_OPENSSL") == "1" or os.getenv("NOISE_USE_OPENSSL") == "true"

--- Enable or disable OpenSSL acceleration for cryptographic operations
--- @param use boolean True to enable OpenSSL, false to disable
function openssl_wrapper.use(use)
  _use_openssl = use
end

--- Get the cached OpenSSL module if enabled and available
--- @return table|nil openssl The OpenSSL module or nil if not enabled/available
--- @throws error If OpenSSL is enabled but the module cannot be loaded
function openssl_wrapper.get()
  if not _use_openssl then
    _openssl_module = nil
  elseif _openssl_module == nil then
    local ok, openssl_module = pcall(require, "openssl")
    if not ok or openssl_module == nil then
      error("OpenSSL module not found. Please install it to use Noise Protocol with OpenSSL.")
    end
    --- @cast openssl_module table
    _openssl_module = openssl_module
  end
  return _openssl_module
end

return openssl_wrapper
