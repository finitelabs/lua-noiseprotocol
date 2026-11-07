# Luarocks path for amalg and other tools
LUAROCKS_PATH := $(shell luarocks path --lr-path 2>/dev/null)

# Lua path for local modules (src, vendor)
LUA_PATH_LOCAL := ./?.lua;./?/init.lua;./src/?.lua;./src/?/init.lua;./vendor/?.lua;$(LUAROCKS_PATH)

# Lua path for the with-tests build: the library plus test/
LUA_PATH_TESTS := ./test/?.lua;$(LUA_PATH_LOCAL)

LUA_BINARY ?= lua

# Default target
.PHONY: all
all: format lint test build

# Run tests
.PHONY: test
test:
	./run_tests.sh

# Run test matrix
.PHONY: test-matrix
test-matrix:
	./run_tests_matrix.sh

# Run specific test suite for test matrix
.PHONY: test-matrix-%
test-matrix-%:
	./run_tests_matrix.sh $*

# Run specific test suite
.PHONY: test-%
test-%:
	./run_tests.sh $*

# Run the tests against what ships: build/noiseprotocol.lua with src/ off the path, then the
# with-tests build's own selftest()
.PHONY: test-bundle
test-bundle:
	TEST_BUNDLE=build/noiseprotocol.lua ./run_tests.sh all
	LUA_PATH= $(LUA_BINARY) -e 'os.exit(dofile("build/noiseprotocol-tests.lua").selftest() and 0 or 1)'

# Run the full suite on the OpenSSL-accelerated path
.PHONY: test-openssl
test-openssl:
	./run_tests.sh --require-openssl all


build/amalg.cache: $(shell find src -name '*.lua')
	@echo "Generating amalgamation cache..."
	@mkdir -p build
	@if command -v amalg.lua >/dev/null 2>&1; then \
		LUA_PATH="$(LUA_PATH_LOCAL)" lua -lamalg src/noiseprotocol/init.lua && mv amalg.cache build || exit 1; \
		echo "Generated amalg.cache"; \
	else \
		echo "Error: amalg not found."; \
		echo "Please install amalg: luarocks install amalg"; \
		echo "Or run: make install-deps"; \
		exit 1; \
	fi

# The with-tests build's modules: everything test/with_tests.lua loads
build/amalg-tests.cache: $(shell find src test -name '*.lua')
	@echo "Generating amalgamation cache for the with-tests build..."
	@mkdir -p build
	@LUA_PATH="$(LUA_PATH_TESTS)" lua -lamalg test/with_tests.lua && mv amalg.cache build/amalg-tests.cache

# Build single-file distributions
.PHONY: build
build: build/amalg.cache build/amalg-tests.cache
	@echo "Building single-file distribution..."
	@if command -v amalg.lua >/dev/null 2>&1; then \
		LUA_PATH="$(LUA_PATH_LOCAL)" amalg.lua -o build/noiseprotocol.lua -C ./build/amalg.cache -i "bitn" -i "crypto" || exit 1; \
		echo "Built build/noiseprotocol.lua (core; bitn + crypto excluded, expected on the path)"; \
		LUA_PATH="$(LUA_PATH_TESTS)" amalg.lua -o build/noiseprotocol-tests.lua -C ./build/amalg-tests.cache || exit 1; \
		echo "Built build/noiseprotocol-tests.lua (with tests; all dependencies bundled)"; \
		if grep -n -E 'selftest|benchmark' build/noiseprotocol.lua; then \
			echo "build/noiseprotocol.lua carries test code; tests belong in test/ and bench/"; \
			exit 1; \
		fi; \
		LUA_PATH="$(LUA_PATH_LOCAL)" amalg.lua -o build/noiseprotocol-portable.lua -C ./build/amalg.cache || exit 1; \
		echo "Built build/noiseprotocol-portable.lua (portable; all dependencies bundled)"; \
		VERSION=$$(git describe --exact-match --tags 2>/dev/null || echo "dev"); \
		if [ "$$VERSION" != "dev" ]; then \
			echo "Injecting version $$VERSION..."; \
			sed -i.bak 's/VERSION = "dev"/VERSION = "'$$VERSION'"/' build/noiseprotocol.lua && rm build/noiseprotocol.lua.bak; \
			sed -i.bak 's/VERSION = "dev"/VERSION = "'$$VERSION'"/' build/noiseprotocol-tests.lua && rm build/noiseprotocol-tests.lua.bak; \
			sed -i.bak 's/VERSION = "dev"/VERSION = "'$$VERSION'"/' build/noiseprotocol-portable.lua && rm build/noiseprotocol-portable.lua.bak; \
		fi; \
		echo "Testing version function..."; \
		TESTS_VERSION=$$(LUA_PATH= lua -e 'local b = dofile("build/noiseprotocol-tests.lua"); print(b.version())' 2>/dev/null || echo "test failed"); \
		if [ "$$TESTS_VERSION" != "$$VERSION" ]; then echo "Version test failed for build/noiseprotocol-tests.lua: $$TESTS_VERSION"; fi; \
		CORE_VERSION=$$(LUA_PATH="$(LUA_PATH_LOCAL)" lua -e 'local n = require("build.noiseprotocol"); print(n.version())' 2>/dev/null || echo "test failed"); \
		PORTABLE_VERSION=$$(LUA_PATH="$(LUA_PATH_LOCAL)" lua -e 'local n = require("build.noiseprotocol-portable"); print(n.version())' 2>/dev/null || echo "test failed"); \
		if [ "$$CORE_VERSION" = "$$VERSION" ] && [ "$$PORTABLE_VERSION" = "$$VERSION" ]; then \
			echo "Version correctly set to: $$VERSION (core + portable)"; \
		else \
			echo "Version test failed. Expected: $$VERSION, core: $$CORE_VERSION, portable: $$PORTABLE_VERSION"; \
		fi; \
	else \
		echo "Error: amalg not found."; \
		echo "Please install amalg: luarocks install amalg"; \
		echo "Or run: make install-deps"; \
		exit 1; \
	fi

# Install all development dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing development dependencies..."
	@echo ""
	@echo "=== Installing system tools ==="
	@if command -v brew >/dev/null 2>&1; then \
		echo "Using Homebrew to install tools..."; \
		brew install lua-language-server stylua || true; \
	else \
		echo "Please install the following manually:"; \
		echo "  - lua-language-server: https://github.com/LuaLS/lua-language-server/releases"; \
		echo "  - stylua: https://github.com/JohnnyMorganz/StyLua/releases"; \
		echo "  - luarocks: https://github.com/luarocks/luarocks/wiki/Download"; \
	fi
	@echo ""
	@echo "=== Installing Lua tools ==="
	@if command -v luarocks >/dev/null 2>&1; then \
		echo "Using LuaRocks to install tools..."; \
		luarocks install luacheck || exit 1; \
		luarocks install amalg || exit 1; \
	else \
		echo "luarocks not found. Please install it first."; \
		echo "  macOS: brew install luarocks"; \
		echo "  Linux: apt-get install luarocks"; \
		exit 1; \
	fi

# Format Lua code with stylua
.PHONY: format
format:
	@if command -v stylua >/dev/null 2>&1; then \
		echo "Running stylua..."; \
		stylua --indent-type Spaces --column-width 120 --line-endings Unix \
			--indent-width 2 --quote-style AutoPreferDouble \
			src/ test/ 2>/dev/null; \
	else \
		echo "stylua not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Check Lua formatting
.PHONY: format-check
format-check:
	@if command -v stylua >/dev/null 2>&1; then \
		echo "Running stylua check..."; \
		stylua --check --indent-type Spaces --column-width 120 --line-endings Unix \
			--indent-width 2 --quote-style AutoPreferDouble \
			src/ test/; \
	else \
		echo "stylua not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Lint the code with luacheck
.PHONY: lint
lint:
	@if command -v luacheck >/dev/null 2>&1; then \
		echo "Running luacheck..."; \
		luacheck src/ test/; \
	else \
		echo "luacheck not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Type-check annotations with the Lua language server. Catches what luacheck does
# not: undefined or duplicate `@alias`, returns that disagree with `@return`.
#
# `vendor/` is both a `library` and an `ignoreDir`: with only the first its code is
# diagnosed here, with only the second its definitions are lost. `runtime.version`
# is pinned to LuaJIT because that is what Control4 runs, not to change a count.
.PHONY: typecheck
typecheck:
	@if command -v lua-language-server >/dev/null 2>&1; then \
		echo "Running lua-language-server $$(lua-language-server --version)..."; \
		lua-language-server --check "$(CURDIR)" --checklevel=Warning \
			--configpath="$(CURDIR)/.luarc-typecheck.json" --logpath="$(CURDIR)/build/luals"; \
	else \
		echo "lua-language-server not found. Install with: make install-deps"; \
		exit 1; \
	fi

.PHONY: check
check: format-check lint typecheck
	@echo "Code quality checks complete."

# Clean generated files
.PHONY: clean
clean:
	rm -rf build/

# Help
.PHONY: help
help:
	@echo "Noise Protocol Framework - Makefile targets"
	@echo ""
	@echo "Testing:"
	@echo "  make test               - Run all tests"
	@echo "  make test-<name>        - Run specific test (e.g., make test-x25519)"
	@echo "  make test-openssl       - Run all tests, requiring OpenSSL acceleration"
	@echo "  make test-matrix        - Run tests across all Lua versions"
	@echo "  make test-matrix-<name> - Run specific test across all Lua versions"
	@echo "  make test-bundle        - Run the tests against the built files (after make build)"
	@echo ""
	@echo "Building:"
	@echo "  make build              - Build the single files, noiseprotocol-tests.lua included"
	@echo ""
	@echo "Code Quality:"
	@echo "  make check              - Run format-check, lint, and typecheck"
	@echo "  make format             - Format code with stylua"
	@echo "  make format-check       - Check code formatting"
	@echo "  make lint               - Lint code with luacheck"
	@echo "  make typecheck          - Check annotations with lua-language-server"
	@echo ""
	@echo "Setup:"
	@echo "  make install-deps       - Install development dependencies"
	@echo "  make clean              - Remove generated files"
	@echo ""
	@echo "  make help               - Show this help"
