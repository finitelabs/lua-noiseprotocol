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

### typecheck

`make typecheck` runs lua-language-server against the committed
`.luarc-typecheck.json`. It catches what luacheck does not: undefined or duplicate
`@alias`, returns that disagree with `@return`, fields missing from a `@class`.

`--configpath` displaces each individual setting the committed config declares,
not each table, so a knob is only closed if it is named. The candidate set is not a
matter of taste: `cli/check_worker.lua` derives `--check` suppression from
`diagnostics.disable` and `diagnostics.severity`, and every other vector is read by
a checker or the provider, so it can be enumerated with

    grep -rhoE "config\.get\([^,]*, *'Lua\.[A-Za-z.]+'" \
      script/core/diagnostics/*.lua script/provider/diagnostic.lua

Of the 17 keys that turns up on 3.19.0, six were measured as live bypasses and are
declared here: `enable`, `disable`, `severity`, `globals`, `globalsRegex` and
`enableScheme` under `diagnostics`, plus `special` under `runtime`.

`enableScheme` is the dangerous one and the reason "declare it empty" is not a rule
to apply blindly. It gates whether a document is diagnosed at all rather than
suppressing a code, its default is `["file"]`, and declaring `[]` silences the
entire check exactly as a local `["git"]` would. It is declared as `["file"]`.

Any setting this file does not name, under any table, is still reachable from a
local `.luarc.json`. Re-run the enumeration above when upgrading the server rather
than assuming this list stayed complete.

The server version is not pinned locally, though. `install-deps` takes whatever
Homebrew has while CI pins 3.19.0, so compare the version the target prints if a
local result disagrees with CI.

`vendor/` is both a `library` and an `ignoreDir`, which is load-bearing: with only
`ignoreDir` the vendored definitions are lost and their uses become
`undefined-doc-name`, and with only `library` the vendored code is diagnosed here.

`runtime.version` is pinned to LuaJIT because that is what Control4 runs. Unset,
the server assumes Lua 5.4 and checks the wrong language. That makes no difference
to the findings in this repo today, so it is pinned as the correct setting rather
than to change a count.

Part of `check`, so CI enforces it. CI pins the server version so the count cannot
move under an upstream release; 3.18.2 and 3.19.0 agree here.
