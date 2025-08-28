--- @module "noiseprotocol.crypto"
local crypto = {
  -- Hash functions
  sha256 = require("noiseprotocol.crypto.sha256"),
  sha512 = require("noiseprotocol.crypto.sha512"),
  blake2 = require("noiseprotocol.crypto.blake2"),

  -- AEAD ciphers
  chacha20_poly1305 = require("noiseprotocol.crypto.chacha20_poly1305"),
  aes_gcm = require("noiseprotocol.crypto.aes_gcm"),

  -- Stream ciphers
  chacha20 = require("noiseprotocol.crypto.chacha20"),

  -- MAC
  poly1305 = require("noiseprotocol.crypto.poly1305"),

  -- DH functions
  x25519 = require("noiseprotocol.crypto.x25519"),
  x448 = require("noiseprotocol.crypto.x448"),
}

return crypto
