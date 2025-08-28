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

--- OpenSSL Feature Enum
---
--- Identifies specific OpenSSL capabilities required by crypto operations.
--- Use these features with `openssl_wrapper.get()` to check if the installed
--- OpenSSL version supports the functionality needed.
---
--- @enum OpenSSLFeature
local OpenSSLFeature = {
  --- Additional Authenticated Data support for AEAD ciphers (ChaCha20-Poly1305, AES-GCM)
  AAD = "AAD",
}

--- Feature version requirements mapping
---
--- Defines the minimum OpenSSL version required for each feature to work correctly.
--- Used internally by `get()` to determine feature availability based on
--- the installed OpenSSL version.
---
--- @type table<OpenSSLFeature, string>
local FeatureVersions = {
  [OpenSSLFeature.AAD] = "0.9.2",
}

-- Export Feature enum for external use
openssl_wrapper.Feature = OpenSSLFeature

--- @type table?
local _openssl_module
--- @type table<OpenSSLFeature, boolean>
local _openssl_module_features = {}
local _use_openssl = os.getenv("NOISE_USE_OPENSSL") == "1" or os.getenv("NOISE_USE_OPENSSL") == "true"

--- Enable or disable OpenSSL acceleration for cryptographic operations
--- @param use boolean True to enable OpenSSL, false to disable
function openssl_wrapper.use(use)
  _use_openssl = use
end

--- Parse semantic version string into comparable components
--- @param version_str string Version string like "0.9.1" or "1.0.0-rc1"
--- @return number major Major version number
--- @return number minor Minor version number
--- @return number patch Patch version number
local function parse_version(version_str)
  local major, minor, patch = version_str:match("(%d+)%.(%d+)%.(%d+)")
  return tonumber(major) or 0, tonumber(minor) or 0, tonumber(patch) or 0
end

--- Compare two semantic versions
--- @param current_version string Current version string
--- @param required_version string Required minimum version string
--- @return boolean supported True if current version >= required version
local function version_supports(current_version, required_version)
  local cur_major, cur_minor, cur_patch = parse_version(current_version)
  local req_major, req_minor, req_patch = parse_version(required_version)

  -- Compare major.minor.patch
  if cur_major > req_major then
    return true
  elseif cur_major == req_major then
    if cur_minor > req_minor then
      return true
    elseif cur_minor == req_minor then
      return cur_patch >= req_patch
    end
  end

  return false
end

--- Get the OpenSSL module if enabled and supports required features
---
--- Checks if OpenSSL is enabled and supports all specified features before
--- returning the module. This ensures that the returned module can safely
--- be used for the requested cryptographic operations.
---
--- @param ... OpenSSLFeature One or more required features that must be supported
--- @return table|nil openssl The OpenSSL module if available and supports all features, nil otherwise
--- @throws error If OpenSSL is enabled but the module cannot be loaded
function openssl_wrapper.get(...)
  local required_features = { ... }

  if not _use_openssl then
    _openssl_module = nil
  elseif _openssl_module == nil then
    local ok, openssl_module = pcall(require, "openssl")
    if not ok or openssl_module == nil then
      error("OpenSSL module not found. Please install it to use Noise Protocol with OpenSSL.")
    end
    --- @cast openssl_module table
    _openssl_module = openssl_module
    _openssl_module_features = {}
    local current_version = type(_openssl_module.version) == "function" and _openssl_module.version()
    if current_version then
      -- Cache all supported features
      for _, feature in ipairs(OpenSSLFeature) do
        local required_version = FeatureVersions[feature]

        if not required_version then
          error("Unknown feature: " .. tostring(feature))
        end
        _openssl_module_features[feature] = version_supports(current_version, required_version)
      end
    end
  end
  -- Check all requested features
  for _, required_feature in ipairs(required_features) do
    if not _openssl_module_features[required_feature] then
      return nil
    end
  end
  return _openssl_module
end

return openssl_wrapper
