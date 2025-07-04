local noise = require("noise")
local utils = require("utils")
local json = require("vendor.json")

-- Parse test vectors from file
local function parse_vectors(filename)
  local file = io.open(filename, "r")
  if not file then
    error("Could not open test vectors file: " .. filename)
  end

  local content = file:read("*all")
  file:close()
  return json.decode(content).vectors
end

local function psks_from_hex(hex_psks)
  local psks = {}
  if hex_psks then
    for i, hex in ipairs(hex_psks) do
      psks[i] = utils.from_hex(hex)
    end
  end
  return psks
end

-- Run a single test vector
local function run_test_vector(vector)
  -- Create initiator config
  --- @type NoiseConfig
  local init_config = {
    protocol_name = vector.protocol_name,
    initiator = true,
    psks = psks_from_hex(vector.init_psks),
    prologue = vector.init_prologue and utils.from_hex(vector.init_prologue),
    ephemeral_key = vector.init_ephemeral and utils.from_hex(vector.init_ephemeral),
    static_key = vector.init_static and utils.from_hex(vector.init_static),
    remote_static_key = vector.init_remote_static and utils.from_hex(vector.init_remote_static),
  }

  -- Create responder config
  --- @type NoiseConfig
  local resp_config = {
    protocol_name = vector.protocol_name,
    initiator = false,
    psks = psks_from_hex(vector.resp_psks),
    prologue = vector.resp_prologue and utils.from_hex(vector.resp_prologue),
    ephemeral_key = vector.resp_ephemeral and utils.from_hex(vector.resp_ephemeral),
    static_key = vector.resp_static and utils.from_hex(vector.resp_static),
    remote_static_key = vector.resp_remote_static and utils.from_hex(vector.resp_remote_static),
  }

  local initiator = noise.NoiseConnection:new(init_config)
  local responder = noise.NoiseConnection:new(resp_config)

  initiator:start_handshake()
  responder:start_handshake()

  -- Process messages
  local errors = {}
  local is_initiator_turn = true

  -- Check if this is a one-way pattern (N, K, X) using the pattern property
  local is_one_way = (
    initiator.pattern == noise.NoisePattern.N
    or initiator.pattern == noise.NoisePattern.K
    or initiator.pattern == noise.NoisePattern.X
  )

  for msg_idx, msg_data in ipairs(vector.messages) do
    assert(msg_data.ciphertext and msg_data.payload, "Message must contain ciphertext and payload")

    -- For one-way patterns, initiator always sends
    local sender = (is_one_way or is_initiator_turn) and initiator or responder
    local receiver = (is_one_way or is_initiator_turn) and responder or initiator

    -- Send message
    local payload = utils.from_hex(msg_data.payload)
    local ciphertext

    -- Check if this is a handshake or transport message
    if sender.handshake_complete then
      ciphertext = sender:send_message(payload)
    else
      ciphertext = sender:write_handshake_message(payload)
    end

    -- Compare with expected ciphertext
    local expected_ct = utils.from_hex(msg_data.ciphertext)
    if ciphertext ~= expected_ct then
      table.insert(
        errors,
        string.format(
          "Message %d: Ciphertext mismatch\n  Expected: %s\n  Got:      %s",
          msg_idx - 1,
          msg_data.ciphertext,
          utils.to_hex(ciphertext)
        )
      )
    end

    -- Receiver processes message
    local received_payload
    if receiver.handshake_complete then
      received_payload = receiver:receive_message(ciphertext)
    else
      received_payload = receiver:read_handshake_message(ciphertext)
    end

    if received_payload ~= payload then
      table.insert(
        errors,
        string.format(
          "Message %d: Payload mismatch after decryption\n  Expected: %s\n  Got:      %s",
          msg_idx - 1,
          utils.to_hex(payload),
          utils.to_hex(received_payload or "")
        )
      )
    end

    -- Don't switch turns for one-way patterns
    if not is_one_way then
      is_initiator_turn = not is_initiator_turn
    end
  end

  return #errors == 0, errors
end

-- Run all test vectors
local function run_all_tests(filename)
  print("Parsing test vectors from " .. filename .. "...")
  local vectors = parse_vectors(filename)
  print("Found " .. #vectors .. " test vectors")

  local passed = 0
  local failed = 0

  -- Group results by pattern/cipher/hash
  local results = {}

  for _, vector in ipairs(vectors) do
    -- FIXME: Skip test vectors that use 448 DH function (not supported)
    if not vector.protocol_name:find("_448_") then
      -- Initialize results tracking for this configuration
      local key = vector.protocol_name:gsub("^Noise_[^_]+_", "")
      if not results[key] then
        results[key] = { passed = 0, failed = 0 }
      end

      local success, result1, result2 = pcall(run_test_vector, vector)

      if success then
        local test_passed = result1
        local errors = result2
        if test_passed then
          passed = passed + 1
          results[key].passed = results[key].passed + 1
          print("✅ PASSED: " .. vector.protocol_name)
        else
          -- Show test failures
          failed = failed + 1
          results[key].failed = results[key].failed + 1
          print("\n❌ FAILED: " .. vector.protocol_name)
          for _, err in ipairs(errors) do
            print("  " .. err)
          end
        end
      else
        failed = failed + 1
        results[key].failed = results[key].failed + 1
        print("\n❌ ERROR: " .. vector.protocol_name)
        print("  " .. tostring(result1))
      end
    end
  end

  print("\n\nTest Results:")
  print(string.format("  ✅ Passed:  %d", passed))
  print(string.format("  ❌ Failed:  %d", failed))
  print(string.format("  Total:     %d", #vectors))

  -- Print summary by configuration
  print("\nResults by configuration:")
  local configs = {}
  for k, _ in pairs(results) do
    table.insert(configs, k)
  end
  table.sort(configs)

  for _, config in ipairs(configs) do
    local result = results[config]
    local total = result.passed + result.failed
    if result.failed == 0 then
      print(string.format("  ✅ %s: %d/%d passed", config, result.passed, total))
    else
      print(string.format("  ❌ %s: %d/%d passed", config, result.passed, total))
    end
  end

  return passed
end

-- Main
return function(filename)
  assert(filename, "Test vectors file not specified")
  return run_all_tests(filename)
end
