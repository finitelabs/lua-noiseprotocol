# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a pure Lua implementation of the Noise Protocol Framework with zero external dependencies. It provides secure channel establishment protocols with support for various handshake patterns, cipher suites, and optional OpenSSL acceleration.

**Key Characteristics:**
- Pure Lua implementation (5.1+ and LuaJIT compatible)
- Zero dependencies for maximum portability (the full single-file bundle vendors everything)
- Complete Noise Protocol Framework implementation
- Cryptographic primitives provided by [lua-crypto](https://github.com/finitelabs/lua-crypto) (vendored as `vendor/crypto.lua`)
- Optional OpenSSL acceleration via `noiseprotocol.use_openssl(true)`
- Extensive test coverage with the Cacophony/Snow test vectors

Noise is a Trevor Perrin specification, not an RFC; there are no RFC vectors for
it and the repo does not pin a spec revision.

### Cipher suites

DH `25519`, `448`; ciphers `ChaChaPoly`, `AESGCM`; hashes `SHA256`, `SHA512`,
`BLAKE2s`, `BLAKE2b`. Protocol names are
`Noise_<pattern>_<dh>_<cipher>_<hash>`, e.g. `Noise_XX_25519_ChaChaPoly_SHA256`,
with `+`-joined modifiers.

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

# Check LuaCATS annotations with lua-language-server
make typecheck

# Full gate: format-check + lint + typecheck
make check
```

`make check` is the gate CI runs. `make all` is `format lint test build`, which
rewrites `src/` in place and runs neither `format-check` nor `typecheck` — it is
not a substitute for `check`.

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
    ├── init.lua               # Utils aggregator
    ├── bytes.lua              # Byte manipulation utilities (uses bitn)
    └── benchmark.lua          # Timing helper (no caller in src/ or tests/)
vendor/
├── bitn.lua                    # Portable bitwise operations (lua-bitn)
└── crypto.lua                  # Cryptographic primitives (lua-crypto, canonical core build: bitn excluded)
tests/                          # test_noise_vectors.lua + vendored json.lua
.luarc-typecheck.json           # Hardened config for `make typecheck` (see below)
.luacheckrc
run_tests.sh, run_tests_matrix.sh
.github/workflows/{build,release}.yml
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

**NoiseConnection** (`src/noiseprotocol/init.lua`) — the main API:
`NoiseConnection:new(config)`, `:start_handshake(prologue)`,
`:write_handshake_message(payload) -> message`,
`:read_handshake_message(message) -> payload`, `:send_message`,
`:receive_message`, `:get_handshake_hash`.

Note these are **not** `write_message`/`read_message` — those names belong to
`HandshakeState`, one layer down.

The error contract is mixed: misuse raises through `assert`, but
`:receive_message` returns **nil** on authentication failure rather than raising.
A caller that only wraps in `pcall` will read a failed decryption as success with
a nil payload.

**Cryptographic Primitives** (vendored from lua-crypto as `vendor/crypto.lua`)
- Exposed to Noise code via `require("crypto")` and re-exported as `noiseprotocol.crypto`
- Tested in lua-crypto's own CI; exercised here end-to-end by the `noise` /
  `noise_vectors` suites

**HandshakeState, SymmetricState, CipherState** (`src/noiseprotocol/init.lua`)
- Core protocol state machines following Noise specification
- Used internally by NoiseConnection

### Noise Protocol Patterns

All 38 spec patterns are implemented — 3 one-way (N, K, X), 12 fundamental, and
23 deferred — and `psk0` through `psk3` are supported, with a 32-byte PSK
enforced.

**The `fallback` modifier is not.** It parses and then raises
`"Fallback modifier not yet supported"`. "Supports all standard patterns" is true
of patterns and not of modifiers.

**Nonces cap at 2^32-1, not the spec's 2^64-1.** `MAX_NONCE = 2^32 - 1` is
asserted on both encrypt and decrypt, so a long-lived transport session raises
`"Nonce overflow"` far earlier than the specification allows. Rekey before then.

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
- Enable OpenSSL acceleration where it is available, via
  `noiseprotocol.use_openssl(true)`

### Performance
- The vendored crypto uses pre-allocated arrays; not thread-safe for concurrent
  coroutines

### Compatibility
- Supports Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT

### Testing Best Practices
- **`make test` is not the full suite.** Its default module list is
  `utils_bytes noise`, which excludes `noise_vectors` entirely. The full run is
  `./run_tests.sh all` / `make test-all`, which is what CI runs.
- Run `make test-matrix` for multi-version compatibility
- Noise vectors test with the sampled set by default for speed; use
  `NOISE_VECTORS_DIR=vectors_full` for comprehensive validation

### `NOISE_USE_OPENSSL` does nothing

`run_tests_matrix.sh` and build.yml's "Run tests using OpenSSL" step both set
`NOISE_USE_OPENSSL=1`, but nothing reads that variable. The vendored crypto reads
**`CRYPTO_USE_OPENSSL`**. That CI step currently re-runs the same pure-Lua path as
the step before it, so the accelerated configuration is unverified in CI. Use
`CRYPTO_USE_OPENSSL=1` when testing acceleration locally.

### Code Style
- 2-space indentation, 120 column width, double quotes preferred
- Use `make format` before committing changes

There is no `.stylua.toml`; these live only as CLI flags in the Makefile, so bare
`stylua src/` outside `make` reformats differently. `.luacheckrc` sets
`std = "min"`, `compat = true`, `globals = {unpack}` and `max_line_length = false`,
so the column limit is enforced by stylua alone.

### typecheck

`make typecheck` runs lua-language-server against the committed
`.luarc-typecheck.json`. It catches what luacheck does not: undefined or duplicate
`@alias`, returns that disagree with `@return`, fields missing from a `@class`.

`--configpath` displaces each individual setting the committed config declares,
not each table, so a knob is only closed if it is named. Suppression keys can be
enumerated from the diagnostics read sites:

    grep -rhoE "config\.get\([^,]*, *'Lua\.[A-Za-z.]+'" \
      script/core/diagnostics/*.lua script/provider/diagnostic.lua

Treat that as a floor, not a ceiling: its file scope is the shape of its blind
spot. Anything that gates file loading or rewrites source before analysis is read
elsewhere, and has to be enumerated separately from `script/plugin.lua` and
`script/workspace.lua`. `runtime.plugin` is the case that matters, and the grep
cannot surface it by construction. `check_worker.lua` does `require 'plugin'`, so
an `OnSetText` returning an empty edit blanks every file in the repo and the check
passes having analysed nothing.

Two traps decide how a key gets declared, and neither is answered by the key's
type:

Empty is not always inert, so read the read site. `neededFileStatus` and
`groupFileStatus` are per-key lookups that fall back to the built-in default, so
`{}` leaves behaviour untouched. `enableScheme` defaults to `["file"]`, which makes
`[]` silence the whole check exactly as a local `["git"]` would. It is declared as
`["file"]` for that reason.

Immunity is per-code, so one planted probe does not measure a key.
`check_worker.lua`'s `downgrade_checks_to_opened` force-overwrites only codes whose
default status is `Any`, leaving everything defaulting to `Opened` under local
control, which is precisely the type-check group this gate exists for. An
`undefined-global` probe therefore reports `neededFileStatus` as inert while a
`return-type-mismatch` probe shows it silencing the check. Probe with a type-check
code.

Declared here as measured live bypasses: `enable`, `disable`, `severity`,
`globals`, `globalsRegex`, `enableScheme`, `neededFileStatus` and `groupFileStatus`
under `diagnostics`, plus `special` and `plugin` under `runtime`. `pluginArgs`,
`groupSeverity`, `maxPreload` and `preloadFileSize` are declared as belt and
braces rather than measured bypasses: `groupSeverity` relabels a finding that is
still counted and still exits non-zero, and `preloadFileSize: 0` fails loud rather
than hiding anything. Declaring them costs nothing and saves re-deriving that.

Any setting this file does not name, under any table, is still reachable from a
local `.luarc.json`. Re-run both enumerations when upgrading the server rather than
assuming this list stayed complete.

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
