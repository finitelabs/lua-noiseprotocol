local noise = require("noiseprotocol")
local utils = require("noiseprotocol.utils")
local json = require("vendor.json")
local bytes = utils.bytes

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
      psks[i] = bytes.from_hex(hex)
    end
  end
  return psks
end

local function should_skip_vector(vector)
  -- FIXME: Skip test vectors that use 448 DH function (not supported)
  return vector.protocol_name:find("_448_") ~= nil
end

--- Run a single test vector
--- @param vector table Test vector data
--- @return boolean success True if test passed
--- @return string[] errors List of error messages if test failed
local function run_test_vector(vector)
  -- Create initiator config
  --- @type NoiseConfig
  local init_config = {
    protocol_name = vector.protocol_name,
    initiator = true,
    psks = psks_from_hex(vector.init_psks),
    prologue = vector.init_prologue and bytes.from_hex(vector.init_prologue),
    ephemeral_key = vector.init_ephemeral and bytes.from_hex(vector.init_ephemeral),
    static_key = vector.init_static and bytes.from_hex(vector.init_static),
    remote_static_key = vector.init_remote_static and bytes.from_hex(vector.init_remote_static),
  }

  -- Create responder config
  --- @type NoiseConfig
  local resp_config = {
    protocol_name = vector.protocol_name,
    initiator = false,
    psks = psks_from_hex(vector.resp_psks),
    prologue = vector.resp_prologue and bytes.from_hex(vector.resp_prologue),
    ephemeral_key = vector.resp_ephemeral and bytes.from_hex(vector.resp_ephemeral),
    static_key = vector.resp_static and bytes.from_hex(vector.resp_static),
    remote_static_key = vector.resp_remote_static and bytes.from_hex(vector.resp_remote_static),
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
    local payload = bytes.from_hex(msg_data.payload)
    local ciphertext

    -- Check if this is a handshake or transport message
    if sender.handshake_complete then
      ciphertext = sender:send_message(payload)
    else
      ciphertext = sender:write_handshake_message(payload)
    end

    -- Compare with expected ciphertext
    local expected_ct = bytes.from_hex(msg_data.ciphertext)
    if ciphertext ~= expected_ct then
      table.insert(
        errors,
        string.format(
          "Message %d: Ciphertext mismatch\n  Expected: %s\n  Got:      %s",
          msg_idx - 1,
          msg_data.ciphertext,
          bytes.to_hex(ciphertext)
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
          bytes.to_hex(payload),
          bytes.to_hex(received_payload or "")
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

-- Run test vectors with optional parallel distribution
local function run_all_tests(filename, worker_id, num_workers)
  local vectors = parse_vectors(filename)

  -- For parallel execution, only print from worker 0
  if not worker_id or worker_id == 0 then
    print("Parsing test vectors from " .. filename .. "...")
    print("Found " .. #vectors .. " test vectors")
  end

  local passed = 0
  local failed = 0
  local errors_list = {}

  -- Group results by pattern/cipher/hash
  local results = {}

  for idx, vector in ipairs(vectors) do
    -- Skip if this vector is not assigned to this worker
    if not worker_id or ((idx - 1) % num_workers == worker_id) then
      if not should_skip_vector(vector) then
        -- Initialize results tracking for this configuration
        local key = vector.protocol_name:gsub("^Noise_[^_]+_", "")
        if not results[key] then
          results[key] = { passed = 0, failed = 0 }
        end

        local success, test_passed, test_errors = pcall(run_test_vector, vector)

        if success then
          if test_passed then
            passed = passed + 1
            results[key].passed = results[key].passed + 1
            if not worker_id then -- Only print in sequential mode
              print("✅ PASSED: " .. vector.protocol_name)
            end
          else
            failed = failed + 1
            results[key].failed = results[key].failed + 1
            table.insert(errors_list, {
              protocol = vector.protocol_name,
              errors = test_errors,
            })
            if not worker_id then -- Only print in sequential mode
              print("\n❌ FAILED: " .. vector.protocol_name)
              for _, err in ipairs(test_errors) do
                print("  " .. err)
              end
            end
          end
        else
          -- Error in test execution
          failed = failed + 1
          results[key].failed = results[key].failed + 1
          table.insert(errors_list, {
            protocol = vector.protocol_name,
            errors = { tostring(test_passed) }, -- test_passed contains the error message
          })
          if not worker_id then -- Only print in sequential mode
            print("\n❌ ERROR: " .. vector.protocol_name)
            print("  " .. tostring(test_passed))
          end
        end
      else
        -- Skip this vector
        if not worker_id then -- Only print in sequential mode
          print("⏭ SKIPPED: " .. vector.protocol_name)
        end
      end
    end
  end

  -- For parallel execution, output in parseable format
  if worker_id then
    print(string.format("RESULTS:%d:%d", passed, failed))

    -- Output errors if any
    for _, error_info in ipairs(errors_list) do
      print(string.format("ERROR:❌ %s", error_info.protocol))
      for _, err in ipairs(error_info.errors) do
        print(string.format("ERROR:  %s", err))
      end
    end

    return failed == 0
  end

  -- For sequential execution, print summary
  print("\n\nTest Results:")
  print(string.format("  ✅ Passed:  %d", passed))
  print(string.format("  ❌ Failed:  %d", failed))
  print(string.format("  ⏭  Skipped: %d", #vectors - passed - failed))

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

  return failed == 0
end

-- Get the number of vectors in a file
local function count_vectors(filename)
  local vectors = parse_vectors(filename)
  return #vectors
end

-- Get summary info about vectors in a file
local function get_vector_info(filename)
  local vectors = parse_vectors(filename)
  local total = #vectors
  local skipped = 0

  for _, vector in ipairs(vectors) do
    if should_skip_vector(vector) then
      skipped = skipped + 1
    end
  end

  return {
    total = total,
    testable = total - skipped,
    skipped = skipped,
  }
end

-- Module exports
local M = {
  parse_vectors = parse_vectors,
  run_test_vector = run_test_vector,
  run_all_tests = run_all_tests,
  count_vectors = count_vectors,
  get_vector_info = get_vector_info,
}

-- Main entry point when called as script
if arg and arg[0] and arg[0]:match("test_noise_vectors%.lua$") then
  -- Called as a standalone script
  if #arg < 1 then
    print("Usage: lua test_noise_vectors.lua <filename> [worker_id] [num_workers]")
    os.exit(1)
  end

  local filename = arg[1]
  local worker_id = arg[2] and tonumber(arg[2])
  local num_workers = arg[3] and tonumber(arg[3])

  -- Validate parallel args
  if worker_id or num_workers then
    assert(worker_id and num_workers, "Both worker_id and num_workers must be specified for parallel mode")
    assert(worker_id >= 0 and worker_id < num_workers, "worker_id must be between 0 and num_workers-1")
  end

  local success = run_all_tests(filename, worker_id, num_workers)
  os.exit(success and 0 or 1)
else
  -- Used as a module
  return M
end
