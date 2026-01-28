--- @module "noiseprotocol.utils"
--- Common utility functions for the Noise Protocol Framework
--- @class noiseprotocol.utils
local utils = {
  --- @type noiseprotocol.utils.bytes
  bytes = require("noiseprotocol.utils.bytes"),
  --- @type noiseprotocol.utils.benchmark
  benchmark = require("noiseprotocol.utils.benchmark"),
}

return utils
