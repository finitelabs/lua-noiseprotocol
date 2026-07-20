# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a pure Lua implementation of the Noise Protocol Framework with zero external dependencies. It provides secure channel establishment protocols with support for various handshake patterns, cipher suites, and optional OpenSSL acceleration.

**Key Characteristics:**
- Pure Lua implementation (5.1+ and LuaJIT compatible)
- Zero dependencies for maximum portability (the full single-file bundle vendors everything)
- Complete Noise Protocol Framework implementation
- Cryptographic primitives provided by [lua-crypto](https://github.com/finitelabs/lua-crypto) (vendored as `vendor/crypto.lua`)
- Optional OpenSSL acceleration via `crypto.use_openssl(true)` (from lua-crypto)
- Extensive test coverage with RFC test vectors

## Development Commands

### Testing
```bash
# Run all tests with default Lua interpreter
./run_tests.sh
make test

# Run with specific Lua version
LUA_BINARY=lua5.1 ./run_tests.sh
LUA_BINARY=luajit ./run_tests.sh

# Run specific test suites
./run_tests.sh utils_bytes noise
make test-noise

# Run test matrix across all Lua versions
./run_tests_matrix.sh
make test-matrix

# Run Noise Protocol test vectors
./run_tests.sh noise_vectors
NOISE_VECTORS_DIR=vectors_full ./run_tests.sh noise_vectors  # Full test set
NOISE_VECTOR_WORKERS=8 ./run_tests.sh noise_vectors          # Parallel execution
```

### Code Quality
```bash
# Format all code
make format

# Check formatting
make format-check

# Lint code
make lint

# Run all quality checks
make check
```

### Building
```bash
# Build single-file distributions (noiseprotocol.lua [core] + noiseprotocol-portable.lua)
make build

# Install development dependencies
make install-deps

# Clean generated files
make clean
```

## Architecture Overview

### Module Structure
```
src/noiseprotocol/
├── init.lua                    # Main module with the complete Noise implementation
└── utils/                      # Utility modules
    ├── bytes.lua              # Byte manipulation utilities (uses bitn)
    └── benchmark.lua          # Performance measurement helper
vendor/
├── bitn.lua                    # Portable bitwise operations (lua-bitn)
└── crypto.lua                  # Cryptographic primitives (lua-crypto, canonical core build: bitn excluded)
```

The cryptographic primitives (hashes, AEAD ciphers, MACs, X25519/X448) live in
[lua-crypto](https://github.com/finitelabs/lua-crypto). The `vendor/crypto.lua`
here is lua-crypto's canonical `crypto.lua` (core) build (bitn excluded, since
this repo already vendors `bitn.lua`). To update it, drop in a newer lua-crypto
release artifact.

### Build variants
- `noiseprotocol.lua` — canonical **core** build: excludes `bitn` and `crypto`
  (`amalg -i bitn -i crypto`), expects them on the Lua path. Composes with
  libraries that share those dependencies without duplicating them.
- `noiseprotocol-portable.lua` — **portable**: bundles the Noise implementation
  plus `crypto` and `bitn` for zero-dependency drop-in use.

### Key Classes and APIs

**NoiseConnection** (`src/noiseprotocol/init.lua`)
- Main API for establishing secure connections
- Handles handshake patterns (XX, IK, NK, etc.) and PSK variants
- Manages transport phase encryption/decryption

**Cryptographic Primitives** (vendored from lua-crypto as `vendor/crypto.lua`)
- Exposed to Noise code via `require("crypto")` and re-exported as `noiseprotocol.crypto`
- Tested in lua-crypto's own CI; exercised here end-to-end by the `noise` /
  `noise_vectors` suites

**HandshakeState, SymmetricState, CipherState** (`src/noiseprotocol/init.lua`)
- Core protocol state machines following Noise specification
- Used internally by NoiseConnection

### Noise Protocol Patterns
Supports all standard patterns from the Noise specification:
- One-way: N, K, X
- Interactive: NN, NK, NX, KN, KK, KX, XN, XK, XX
- Immediate patterns: IN, IK, IX
- PSK variants: NNpsk0, XXpsk2, etc.
- Deferred patterns: K1K, X1X, etc.

### Test Vector Management
- `tests/vectors_sampled/` - Default sampled vectors (~5% of full set)
- `tests/vectors_full/` - Complete test vectors from Cacophony/Snow
- Use `NOISE_VECTORS_DIR=vectors_full` for comprehensive testing
- Parallel test execution with `NOISE_VECTOR_WORKERS=N`

## Important Implementation Notes

### Security Considerations
- Pure Lua implementation lacks constant-time guarantees
- Not suitable for production without additional hardening
- Intended for portability and educational use
- Always use OpenSSL acceleration when available in production

### Performance
- LuaJIT significantly outperforms standard Lua interpreters
- X448 is notably slower than X25519 in pure Lua
- The vendored crypto uses pre-allocated arrays for performance; not thread-safe for concurrent coroutines

### Compatibility
- Supports Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT
- Uses conditional implementations for version-specific features
- `bit32` operations use fallbacks for older Lua versions

### Testing Best Practices
- Always run full test suite before commits
- Use `make test` for standard testing workflow
- Run `make test-matrix` for multi-version compatibility
- Noise vectors test with sampled set by default for speed
- Use full vectors (`NOISE_VECTORS_DIR=vectors_full`) for comprehensive validation

### Code Style
- Use `make format` before committing changes
- Follow existing naming conventions and module patterns
- Add tests for new functionality following existing patterns
