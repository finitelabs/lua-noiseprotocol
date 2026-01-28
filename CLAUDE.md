# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a pure Lua implementation of the Noise Protocol Framework with zero external dependencies. It provides secure channel establishment protocols with support for various handshake patterns, cipher suites, and optional OpenSSL acceleration.

**Key Characteristics:**
- Pure Lua implementation (5.1+ and LuaJIT compatible)
- Zero dependencies for maximum portability
- Complete Noise Protocol Framework implementation
- Optional OpenSSL acceleration via `noiseprotocol.openssl_wrapper`
- Performance-focused crypto implementations
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
./run_tests.sh chacha20 poly1305 x25519
make test-x25519

# Run test matrix across all Lua versions
./run_tests_matrix.sh
make test-matrix

# Run Noise Protocol test vectors
./run_tests.sh noise_vectors
NOISE_VECTORS_DIR=vectors_full ./run_tests.sh noise_vectors  # Full test set
NOISE_VECTOR_WORKERS=8 ./run_tests.sh noise_vectors          # Parallel execution
```

### Benchmarking
```bash
# Run all benchmarks (uses LuaJIT by default for performance)
./run_benchmarks.sh
make bench

# Run specific benchmarks
./run_benchmarks.sh x25519 chacha20_poly1305
make bench-x448

# Use different Lua interpreter
LUA_BINARY=lua5.1 ./run_benchmarks.sh
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
# Build single-file distribution
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
├── init.lua                    # Main module with complete Noise implementation
├── crypto/                     # Cryptographic primitives
│   ├── init.lua               # Crypto module aggregator
│   ├── x25519.lua / x448.lua  # Diffie-Hellman functions
│   ├── chacha20.lua           # Stream cipher
│   ├── chacha20_poly1305.lua  # ChaCha20-Poly1305 AEAD
│   ├── aes_gcm.lua            # AES-GCM AEAD
│   ├── poly1305.lua           # Poly1305 MAC
│   ├── sha256.lua / sha512.lua / blake2.lua  # Hash functions
├── utils/                      # Utility modules
│   ├── bytes.lua              # Byte manipulation utilities
│   └── benchmark.lua          # Performance measurement tools
└── openssl_wrapper.lua        # Optional OpenSSL acceleration
vendor/
└── bitn.lua                    # Unified bitwise operations for all Lua versions
```

### Key Classes and APIs

**NoiseConnection** (`src/noiseprotocol/init.lua:1563`)
- Main API for establishing secure connections
- Handles handshake patterns (XX, IK, NK, etc.) and PSK variants
- Manages transport phase encryption/decryption

**Cryptographic Primitives** (`src/noiseprotocol/crypto/`)
- All modules provide `selftest()` and `benchmark()` functions
- Pure Lua implementations with consistent APIs
- Support for OpenSSL acceleration where available

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
- Benchmarks should be run with LuaJIT for realistic performance data
- X448 is notably slower than X25519 in pure Lua
- Crypto modules use pre-allocated arrays for performance; not thread-safe for concurrent coroutines

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
- All crypto modules must implement `selftest()` and `benchmark()`
- Add tests for new functionality following existing patterns