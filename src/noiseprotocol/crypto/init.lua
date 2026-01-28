--- @module "noiseprotocol.crypto"
--- Cryptographic primitives for the Noise Protocol Framework
--- @class noiseprotocol.crypto
local crypto = {
  -- Hash functions

  --- @type noiseprotocol.crypto.sha256
  sha256 = require("noiseprotocol.crypto.sha256"),
  --- @type noiseprotocol.crypto.sha512
  sha512 = require("noiseprotocol.crypto.sha512"),
  --- @type noiseprotocol.crypto.blake2
  blake2 = require("noiseprotocol.crypto.blake2"),

  -- AEAD ciphers

  --- @type noiseprotocol.crypto.chacha20_poly1305
  chacha20_poly1305 = require("noiseprotocol.crypto.chacha20_poly1305"),
  --- @type noiseprotocol.crypto.aes_gcm
  aes_gcm = require("noiseprotocol.crypto.aes_gcm"),

  -- Stream ciphers

  --- @type noiseprotocol.crypto.chacha20
  chacha20 = require("noiseprotocol.crypto.chacha20"),

  -- MAC

  --- @type noiseprotocol.crypto.poly1305
  poly1305 = require("noiseprotocol.crypto.poly1305"),

  -- DH functions

  --- @type noiseprotocol.crypto.x25519
  x25519 = require("noiseprotocol.crypto.x25519"),
  --- @type noiseprotocol.crypto.x448
  x448 = require("noiseprotocol.crypto.x448"),
}

return crypto
