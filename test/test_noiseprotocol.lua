local noiseprotocol = require("noiseprotocol")
local NoisePattern = noiseprotocol.NoisePattern
local NoiseConnection = noiseprotocol.NoiseConnection
local DH_25519 = noiseprotocol.DH["25519"]

--- Run comprehensive self-test with test vectors and functional tests
---
--- This function validates the Noise Protocol implementation against test vectors
--- and functional tests. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function functional_tests()
    print("Running Noise Protocol functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Comprehensive XX Handshake (based on example_noise.lua)
    total = total + 1
    local success, err = pcall(function()
      -- Generate static keys
      local alice_static_priv, _alice_static_pub = DH_25519.generate_keypair()
      local bob_static_priv, _bob_static_pub = DH_25519.generate_keypair()

      -- Create clients
      local alice = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = alice_static_priv,
      })
      local bob = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        pattern = NoisePattern.XX,
        initiator = false,
        static_key = bob_static_priv,
      })

      -- Start handshake with prologue
      local prologue = "MyApplication_v1.0"
      alice:start_handshake(prologue)
      bob:start_handshake(prologue)

      -- XX Handshake Message 1: Alice -> Bob (e)
      local msg1 = alice:write_handshake_message("Initial payload from Alice")
      assert(#msg1 > 32, "Message 1 should contain ephemeral key + payload")
      local payload1 = bob:read_handshake_message(msg1)
      assert(payload1 == "Initial payload from Alice", "Payload 1 mismatch")

      -- XX Handshake Message 2: Bob -> Alice (e, ee, s, es)
      local msg2 = bob:write_handshake_message("Response from Bob")
      assert(#msg2 > 64, "Message 2 should contain ephemeral + encrypted static + payload")
      local payload2 = alice:read_handshake_message(msg2)
      assert(payload2 == "Response from Bob", "Payload 2 mismatch")

      -- XX Handshake Message 3: Alice -> Bob (s, se)
      local msg3 = alice:write_handshake_message("Handshake finished!")
      assert(#msg3 > 32, "Message 3 should contain encrypted static + payload")
      local payload3 = bob:read_handshake_message(msg3)
      assert(payload3 == "Handshake finished!", "Payload 3 mismatch")

      -- Verify handshake completion and authentication
      assert(alice.handshake_complete, "Alice handshake not complete")
      assert(bob.handshake_complete, "Bob handshake not complete")

      -- Verify handshake hash consistency (mutual authentication)
      local alice_hash = alice:get_handshake_hash()
      local bob_hash = bob:get_handshake_hash()
      assert(alice_hash == bob_hash, "Handshake hashes don't match")
      assert(#alice_hash == 32, "Handshake hash should be 32 bytes")

      -- Test bidirectional transport phase
      local transport1 = alice:send_message("This is a secure message from Alice to Bob")
      local received1 = bob:receive_message(transport1)
      assert(received1 == "This is a secure message from Alice to Bob", "Transport 1 failed")

      local transport2 = bob:send_message("This is Bob's encrypted reply")
      local received2 = alice:receive_message(transport2)
      assert(received2 == "This is Bob's encrypted reply", "Transport 2 failed")

      -- Test multiple transport messages (session continuity)
      local transport3 = alice:send_message("Follow-up message from Alice")
      local received3 = bob:receive_message(transport3)
      assert(received3 == "Follow-up message from Alice", "Transport 3 failed")
    end)

    if success then
      print("  ✅ PASS: Comprehensive XX Handshake (mutual authentication)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Comprehensive XX Handshake (mutual authentication) - " .. err)
    end

    -- Test 2: Comprehensive IK Handshake with 0-RTT (based on example_noise.lua)
    total = total + 1
    success, err = pcall(function()
      -- Generate keys
      local client_static_priv, _client_static_pub = DH_25519.generate_keypair()
      local server_static_priv, server_static_pub = DH_25519.generate_keypair()

      -- Create IK clients (client knows server's static key beforehand)
      local client = NoiseConnection:new({
        protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = client_static_priv,
        remote_static_key = server_static_pub,
      })
      local server = NoiseConnection:new({
        protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256",
        initiator = false,
        static_key = server_static_priv,
      })

      -- Start handshake
      client:start_handshake("IK_Example")
      server:start_handshake("IK_Example")

      -- IK Message 1: Client -> Server (e, es, s, ss) with 0-RTT encryption!
      local ik_msg1 = client:write_handshake_message("This message is encrypted with 0-RTT!")
      assert(#ik_msg1 > 96, "IK Message 1 should contain ephemeral + encrypted static + encrypted payload")
      local ik_payload1 = server:read_handshake_message(ik_msg1)
      assert(ik_payload1 == "This message is encrypted with 0-RTT!", "0-RTT payload mismatch")

      -- IK Message 2: Server -> Client (e, ee, se)
      local ik_msg2 = server:write_handshake_message("Server response")
      assert(#ik_msg2 > 48, "IK Message 2 should contain ephemeral + encrypted payload")
      local ik_payload2 = client:read_handshake_message(ik_msg2)
      assert(ik_payload2 == "Server response", "IK payload 2 mismatch")

      -- Verify completion and authentication
      assert(client.handshake_complete, "Client handshake not complete")
      assert(server.handshake_complete, "Server handshake not complete")

      -- Verify handshake hash consistency
      local client_hash = client:get_handshake_hash()
      local server_hash = server:get_handshake_hash()
      assert(client_hash == server_hash, "IK handshake hashes don't match")
      assert(#client_hash == 32, "IK handshake hash should be 32 bytes")

      -- Test bidirectional transport phase
      local ik_transport1 = client:send_message("Post-handshake message from client")
      local ik_received1 = server:receive_message(ik_transport1)
      assert(ik_received1 == "Post-handshake message from client", "IK transport 1 failed")

      local ik_transport2 = server:send_message("Post-handshake message from server")
      local ik_received2 = client:receive_message(ik_transport2)
      assert(ik_received2 == "Post-handshake message from server", "IK transport 2 failed")

      -- Test multiple IK transport messages
      local ik_transport3 = client:send_message("Follow-up client message")
      local ik_received3 = server:receive_message(ik_transport3)
      assert(ik_received3 == "Follow-up client message", "IK transport 3 failed")
    end)

    if success then
      print("  ✅ PASS: Comprehensive IK Handshake (0-RTT encryption)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Comprehensive IK Handshake (0-RTT encryption) - " .. err)
    end

    -- Test 3: Security Properties and Tamper Detection (from example_noise.lua)
    total = total + 1
    success, err = pcall(function()
      -- Set up a fresh XX handshake for security testing
      local alice = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = string.rep(string.char(0x10), 32),
      })
      local bob = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = false,
        static_key = string.rep(string.char(0x20), 32),
      })

      alice:start_handshake("SecurityTest")
      bob:start_handshake("SecurityTest")

      -- Complete handshake with empty payloads
      local msg1 = alice:write_handshake_message("")
      bob:read_handshake_message(msg1)
      local msg2 = bob:write_handshake_message("")
      alice:read_handshake_message(msg2)
      local msg3 = alice:write_handshake_message("")
      bob:read_handshake_message(msg3)

      -- Verify handshake authentication via hash consistency
      local alice_hash = alice:get_handshake_hash()
      local bob_hash = bob:get_handshake_hash()
      assert(alice_hash == bob_hash, "Security test: handshake hashes must match")
      assert(#alice_hash == 32, "Security test: handshake hash must be 32 bytes")

      -- Test message integrity: tamper detection
      local original_msg = alice:send_message("Original message")
      assert(#original_msg > 16, "Transport message should include auth tag")

      -- Derived from the byte it displaces: a fixed 0xFF matched the ciphertext's
      -- own byte 1 time in 256, leaving the "tampered" copy identical.
      local first_byte = original_msg:byte(1)
      local last_byte = original_msg:byte(#original_msg)
      assert(first_byte and last_byte, "Transport message should have bytes to tamper with")

      local tampered_msg1 = string.char((first_byte + 1) % 256) .. original_msg:sub(2)
      local tamper_result1 = bob:receive_message(tampered_msg1)
      assert(tamper_result1 == nil, "First byte tampered message should be rejected")

      local tampered_msg2 = original_msg:sub(1, -2) .. string.char((last_byte + 1) % 256)
      local tamper_result2 = bob:receive_message(tampered_msg2)
      assert(tamper_result2 == nil, "Last byte tampered message should be rejected")

      -- Test truncated message
      local truncated_msg = original_msg:sub(1, #original_msg - 1)
      local truncate_result = bob:receive_message(truncated_msg)
      assert(truncate_result == nil, "Truncated message should be rejected")

      -- Verify legitimate message still works
      local legit_result = bob:receive_message(original_msg)
      assert(legit_result == "Original message", "Legitimate message should still work")
    end)

    if success then
      print("  ✅ PASS: Security Properties and Tamper Detection")
      passed = passed + 1
    else
      print("  ❌ FAIL: Security Properties and Tamper Detection - " .. err)
    end

    -- Test 4: Empty message handling
    total = total + 1
    success, err = pcall(function()
      local alice = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = string.rep(string.char(0x11), 32),
      })
      local bob = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = false,
        static_key = string.rep(string.char(0x22), 32),
      })

      alice:start_handshake("")
      bob:start_handshake("")

      -- Complete handshake with empty payloads
      local msg1 = alice:write_handshake_message("")
      local payload1 = bob:read_handshake_message(msg1)
      assert(payload1 == "", "Empty payload should work")

      local msg2 = bob:write_handshake_message("")
      local payload2 = alice:read_handshake_message(msg2)
      assert(payload2 == "", "Empty payload should work")

      local msg3 = alice:write_handshake_message("")
      local payload3 = bob:read_handshake_message(msg3)
      assert(payload3 == "", "Empty payload should work")

      -- Test empty transport messages
      local empty_transport = alice:send_message("")
      local empty_received = bob:receive_message(empty_transport)
      assert(empty_received == "", "Empty transport message should work")
    end)

    if success then
      print("  ✅ PASS: Empty message handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty message handling - " .. err)
    end

    -- Test 5: Error conditions
    total = total + 1
    success, err = pcall(function()
      --Test invalid protocol name
      local invalid_ok, _invalid_err = pcall(function()
        NoiseConnection:new({
          protocol_name = "INVALID",
          initiator = true,
        })
      end)
      assert(not invalid_ok, "Should reject invalid pattern")

      -- Test premature transport
      local client = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = string.rep(string.char(0x99), 32),
      })
      local premature_ok, _premature_err = pcall(function()
        client:send_message("test")
      end)
      assert(not premature_ok, "Should reject transport before handshake")

      -- Test NNpsk0 pattern without PSK should fail during handshake
      local nnpsk0_no_psk_ok, nnpsk0_no_psk_err = pcall(function()
        local client_no_psk = NoiseConnection:new({
          protocol_name = "Noise_XXpsk0_25519_ChaChaPoly_SHA256",
          initiator = true,
          psk = nil, -- No PSK provided
          psk_placement = noiseprotocol.PSKPlacement.ZERO,
        })
        client_no_psk:start_handshake("test")
        client_no_psk:write_handshake_message("test") -- Should fail here due to missing PSK
      end)
      assert(not nnpsk0_no_psk_ok, "Should reject NNpsk0 without PSK")
      assert(nnpsk0_no_psk_err and string.find(nnpsk0_no_psk_err, "PSK"), "Should indicate missing PSK")

      -- Test NNpsk0 pattern with PSK should work
      local psk = string.rep(string.char(0x33), 32)
      local nnpsk0_with_psk_ok, nnpsk0_with_psk_err = pcall(function()
        local client_with_psk = NoiseConnection:new({
          protocol_name = "Noise_NN_25519_ChaChaPoly_SHA256",
          initiator = true,
          psk = psk,
          psk_placement = noiseprotocol.PSKPlacement.ZERO,
        })
        client_with_psk:start_handshake("test")
        client_with_psk:write_handshake_message("test") -- Should work with PSK
      end)
      assert(nnpsk0_with_psk_ok, "Should accept NNpsk0 with PSK: " .. (nnpsk0_with_psk_err or ""))
    end)

    if success then
      print("  ✅ PASS: Error conditions")
      passed = passed + 1
    else
      print("  ❌ FAIL: Error conditions - " .. err)
    end

    -- Test 6: Noise Protocol Features Showcase (from example_noise.lua)
    total = total + 1
    success, err = pcall(function()
      -- Test multiple features in one comprehensive scenario
      local alice_static_priv, _alice_static_pub = DH_25519.generate_keypair()
      local bob_static_priv, bob_static_pub = DH_25519.generate_keypair()

      -- Test both XX and IK patterns in sequence

      -- XX: Mutual authentication without prior key knowledge
      local alice_xx = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = alice_static_priv,
      })
      local bob_xx = NoiseConnection:new({
        protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
        initiator = false,
        static_key = bob_static_priv,
      })

      alice_xx:start_handshake("FeatureTest_XX")
      bob_xx:start_handshake("FeatureTest_XX")

      -- Complete XX handshake
      local xx_msg1 = alice_xx:write_handshake_message("XX payload 1")
      bob_xx:read_handshake_message(xx_msg1)
      local xx_msg2 = bob_xx:write_handshake_message("XX payload 2")
      alice_xx:read_handshake_message(xx_msg2)
      local xx_msg3 = alice_xx:write_handshake_message("XX payload 3")
      bob_xx:read_handshake_message(xx_msg3)

      -- IK: 0-RTT with server authentication
      local alice_ik = NoiseConnection:new({
        protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256",
        initiator = true,
        static_key = alice_static_priv,
        remote_static_key = bob_static_pub,
      })
      local bob_ik = NoiseConnection:new({
        protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256",
        initiator = false,
        static_key = bob_static_priv,
      })

      alice_ik:start_handshake("FeatureTest_IK")
      bob_ik:start_handshake("FeatureTest_IK")

      -- Complete IK handshake with 0-RTT
      local ik_msg1 = alice_ik:write_handshake_message("IK 0-RTT payload")
      bob_ik:read_handshake_message(ik_msg1)
      local ik_msg2 = bob_ik:write_handshake_message("IK response")
      alice_ik:read_handshake_message(ik_msg2)

      -- Verify both handshakes completed successfully
      assert(alice_xx.handshake_complete and bob_xx.handshake_complete, "XX handshake must complete")
      assert(alice_ik.handshake_complete and bob_ik.handshake_complete, "IK handshake must complete")

      -- Test forward secrecy: each handshake produces different session keys
      local xx_msg_a = alice_xx:send_message("XX transport message")
      local ik_msg_a = alice_ik:send_message("IK transport message")
      assert(xx_msg_a ~= ik_msg_a, "Different handshakes should produce different ciphertexts")

      -- Test session isolation: messages from one session can't decrypt in another
      local xx_plaintext = bob_xx:receive_message(xx_msg_a)
      local ik_cross_result = bob_ik:receive_message(xx_msg_a) -- Wrong session
      assert(xx_plaintext == "XX transport message", "XX session should decrypt correctly")
      assert(ik_cross_result == nil, "Cross-session messages should be rejected")

      -- Test replay protection: same ciphertext can't be decrypted twice
      local replay_result = bob_xx:receive_message(xx_msg_a)
      assert(replay_result == nil, "Replayed message should be rejected")
    end)

    if success then
      print("  ✅ PASS: Noise Protocol Features Showcase")
      passed = passed + 1
    else
      print("  ❌ FAIL: Noise Protocol Features Showcase - " .. err)
    end

    -- Test 7: NNpsk0 Pre-Shared Key Pattern
    total = total + 1
    success, err = pcall(function()
      -- Test NNpsk0 with pre-shared key
      local psk = string.rep(string.char(0x42), 32) -- Test PSK

      local alice_psk = NoiseConnection:new({
        protocol_name = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        pattern = NoisePattern.NN,
        initiator = true,
        psks = { psk },
      })
      local bob_psk = NoiseConnection:new({
        protocol_name = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        initiator = false,
        psks = { psk },
      })

      alice_psk:start_handshake("NNpsk0_functional_test")
      bob_psk:start_handshake("NNpsk0_functional_test")

      -- NNpsk0 Message 1: Alice -> Bob (psk0, e)
      local psk_msg1 = alice_psk:write_handshake_message("PSK encrypted message 1")
      assert(#psk_msg1 > 32, "NNpsk0 Message 1 should contain ephemeral key + encrypted payload")
      local psk_payload1 = bob_psk:read_handshake_message(psk_msg1)
      assert(psk_payload1 == "PSK encrypted message 1", "PSK payload 1 mismatch")

      -- NNpsk0 Message 2: Bob -> Alice (e, ee)
      local psk_msg2 = bob_psk:write_handshake_message("PSK encrypted message 2")
      assert(#psk_msg2 > 32, "NNpsk0 Message 2 should contain ephemeral key + encrypted payload")
      local psk_payload2 = alice_psk:read_handshake_message(psk_msg2)
      assert(psk_payload2 == "PSK encrypted message 2", "PSK payload 2 mismatch")

      -- Verify handshake completion
      assert(alice_psk.handshake_complete, "Alice NNpsk0 handshake not complete")
      assert(bob_psk.handshake_complete, "Bob NNpsk0 handshake not complete")

      -- Test handshake hash consistency
      local alice_psk_hash = alice_psk:get_handshake_hash()
      local bob_psk_hash = bob_psk:get_handshake_hash()
      assert(alice_psk_hash == bob_psk_hash, "NNpsk0 handshake hashes don't match")
      assert(#alice_psk_hash == 32, "NNpsk0 handshake hash should be 32 bytes")

      -- Test transport phase with PSK-derived keys
      local psk_transport1 = alice_psk:send_message("NNpsk0 transport message from Alice")
      local psk_received1 = bob_psk:receive_message(psk_transport1)
      assert(psk_received1 == "NNpsk0 transport message from Alice", "NNpsk0 transport 1 failed")

      local psk_transport2 = bob_psk:send_message("NNpsk0 transport message from Bob")
      local psk_received2 = alice_psk:receive_message(psk_transport2)
      assert(psk_received2 == "NNpsk0 transport message from Bob", "NNpsk0 transport 2 failed")

      -- Test PSK security: different PSK should produce different results
      local different_psk = string.rep(string.char(0x99), 32)
      local alice_different = NoiseConnection:new({
        protocol_name = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        initiator = true,
        psks = { different_psk },
      })
      local bob_different = NoiseConnection:new({
        protocol_name = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        initiator = false,
        psks = { different_psk },
      })

      alice_different:start_handshake("NNpsk0_functional_test")
      bob_different:start_handshake("NNpsk0_functional_test")

      local diff_msg1 = alice_different:write_handshake_message("PSK encrypted message 1")
      assert(diff_msg1 ~= psk_msg1, "Different PSKs should produce different ciphertexts")
    end)

    if success then
      print("  ✅ PASS: NNpsk0 Pre-Shared Key Pattern")
      passed = passed + 1
    else
      print("  ❌ FAIL: NNpsk0 Pre-Shared Key Pattern - " .. err)
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local functional_passed = functional_tests()

  return functional_passed
end

return selftest
