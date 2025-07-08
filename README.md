# lua-noiseprotocol

A pure Lua implementation of the
[Noise Protocol Framework](https://noiseprotocol.org) with **zero external
dependencies**. This library provides a complete, portable implementation that
runs on Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT.

## Features

- **Zero Dependencies**: Pure Lua implementation, no C extensions or external
  libraries required
- **Portable**: Runs on any Lua interpreter (5.1+)
- **Complete**: Full implementation of the Noise Protocol Framework
- **Cryptographic Primitives**: Includes all Diffie-Hellman (DH), AEAD encryption, and hashing
  algorithms listed in the specification
- **Well-tested**: Comprehensive test suite with RFC test vectors

## Installation

Clone this repository:

```bash
git clone https://github.com/finitelabs/lua-noiseprotocol.git
cd lua-noiseprotocol
```

Add the `src` directory to your Lua path, or copy the files to your project.

## Usage

### Basic Example

Here's a complete example of the Noise XX pattern from the specification:

```lua
local noise = require("noiseprotocol")

-- Optionally enable OpenSSL support if available
-- noise.use_openssl(true)

-- Generate static keys for both parties
local alice_static_key = noise.DH["25519"].generate_keypair()
local bob_static_key = noise.DH["25519"].generate_keypair()

-- Create initiator (Alice) and responder (Bob)
local alice = noise.NoiseConnection:new({
  protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
  initiator = true,
  static_key = alice_static_key
})

local bob = noise.NoiseConnection:new({
  protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256",
  initiator = false,
  static_key = bob_static_key
})

-- Start handshake with optional prologue
local prologue = "MyAppv1.0"
alice:start_handshake(prologue)
bob:start_handshake(prologue)

-- XX Handshake:
-- -> e
local msg1 = alice:write_handshake_message("")
bob:read_handshake_message(msg1)

-- <- e, ee, s, es
local msg2 = bob:write_handshake_message("")
alice:read_handshake_message(msg2)

-- -> s, se
local msg3 = alice:write_handshake_message("")
bob:read_handshake_message(msg3)

-- Handshake complete!
-- Both parties now have authenticated each other's static keys
print("Handshake complete!")
-- Print first 16 bytes of handshake hash as hex
local utils = require("noiseprotocol.utils")
local hash = alice:get_handshake_hash()
print("Alice handshake hash:", bytes.to_hex(hash):sub(1, 32)) -- 32 hex chars = 16 bytes

-- Transport phase - send encrypted messages
local ciphertext1 = alice:send_message("Hello Bob!")
local plaintext1 = bob:receive_message(ciphertext1)
print("Bob received:", plaintext1)

local ciphertext2 = bob:send_message("Hello Alice!")
local plaintext2 = alice:receive_message(ciphertext2)
print("Alice received:", plaintext2)
```

### Supported Patterns

All one-way and interactive patterns from the Noise specification are supported:

- One-way: N, K, X
- Interactive: NN, NK, NX, KN, KK, KX, XN, XK, XX
- Interactive + initiator auth: IN, IK, IX
- PSK patterns: NNpsk0, NNpsk2, etc.

### Supported Algorithms

- **DH**: 25519, 448
- **AEAD**: ChaChaPoly, AESGCM
- **Hash**: SHA256, SHA512, BLAKE2s, BLAKE2b

## Testing

Run the test suite:

```bash
# Run all tests with default Lua interpreter
./run_tests.sh

# Run with specific Lua version
LUA_BINARY=lua5.1 ./run_tests.sh

# Run specific modules
./run_tests.sh chacha20 poly1305

# Run test matrix across all Lua versions
./run_tests_matrix.sh
```

## Current Limitations

- Pure Lua performance is slower than native implementations
- No constant-time guarantees (not suitable for production use without
  additional hardening)

## Future Plans

- Performance optimizations for the pure Lua implementation

## Security Warning

This is a pure Lua implementation intended for portability and ease of use.
While we implement the algorithms correctly and pass all test vectors, the
implementation:

- Cannot guarantee constant-time operations
- Has not been independently audited
- Is significantly slower than native implementations

For production use, especially in security-critical applications, consider using
native cryptographic libraries.

## License

GNU Affero General Public License v3.0 - see LICENSE file for details

## Contributing

Contributions are welcome! Please ensure all tests pass and add new tests for
any new functionality.

---

<a href="https://www.buymeacoffee.com/derek.miller" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
