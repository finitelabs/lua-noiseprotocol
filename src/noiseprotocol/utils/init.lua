--- @module "noiseprotocol.utils"
--- Common utility functions for the Noise Protocol Framework

return {
  bit32 = require("noiseprotocol.utils.bit32"),
  bit64 = require("noiseprotocol.utils.bit64"),
  bytes = require("noiseprotocol.utils.bytes"),
  benchmark = require("noiseprotocol.utils.benchmark"),
}
