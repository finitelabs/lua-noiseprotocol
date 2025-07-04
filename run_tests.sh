#!/bin/bash

# Lua Crypto Library Test Runner
# Runs all test suites for ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD
#
# Usage: ./run_tests.sh [module_names...]
#
# Examples:
#   ./run_tests.sh                    # Run all modules
#   ./run_tests.sh bitops poly1305    # Run only bitops and poly1305
#   ./run_tests.sh noise              # Run only noise protocol tests
#
# Available modules: utils, poly1305, chacha20, chacha20_poly1305, aes_gcm, x25519, x448, sha256, sha512, blake2, noise, noise_vectors

set -e  # Exit on any error

echo "🔐 Lua Crypto Library - Test Suite Runner"
echo "========================================="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall results
TOTAL_MODULES=0
PASSED_MODULES=()
PASSED_COUNT=0
FAILED_MODULES=()

LUA_BINARY="${LUA_BINARY:-luajit}"  # Use luajit by default, can be overridden

# Get script directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Add repository root to Lua's package path
# This allows require() to find modules in the repository root
export LUA_PATH="$SCRIPT_DIR/?.lua;$SCRIPT_DIR/?/init.lua;$SCRIPT_DIR/src/?.lua;$SCRIPT_DIR/src/?/init.lua;$LUA_PATH"

# Parse command line arguments to determine which modules to run
DEFAULT_MODULES_TO_RUN=("utils" "poly1305" "chacha20" "chacha20_poly1305" "aes_gcm" "x25519" "sha256" "sha512" "blake2" "noise")
MODULES_TO_RUN=("$@")
if [ ${#MODULES_TO_RUN[@]} -eq 0 ]; then
    # No arguments provided, run all modules except noise_vectors
    MODULES_TO_RUN=("${DEFAULT_MODULES_TO_RUN[@]}")
    echo "Running all modules (excluding noise_vectors)..."
elif [ "${MODULES_TO_RUN[0]}" = "all" ]; then
    # "all" argument provided, run all modules including noise_vectors
    MODULES_TO_RUN=("${DEFAULT_MODULES_TO_RUN[@]}" "noise_vectors")
    echo "Running all modules (including noise_vectors)..."
else
    echo "Running specified modules: ${MODULES_TO_RUN[*]}"
fi
echo

# Function to check if a module should be run
should_run_module() {
    local module_key="$1"
    for module in "${MODULES_TO_RUN[@]}"; do
        if [ "$module" = "$module_key" ]; then
            return 0
        fi
    done
    return 1
}

# Function to run a test and capture result
run_test() {
    local module_name="$1"
    local module_key="$2"
    local lua_command="$3"

    if ! should_run_module "$module_key"; then
        return 0
    fi

    echo -e "${BLUE}Testing $module_name...${NC}"
    echo "----------------------------------------"

    TOTAL_MODULES=$((TOTAL_MODULES + 1))

    if "${LUA_BINARY}" -e "$lua_command" 2>&1; then
        echo -e "${GREEN}✅ $module_name: ALL TESTS PASSED${NC}"
        PASSED_MODULES+=("$module_name")
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "${RED}❌ $module_name: TESTS FAILED${NC}"
        FAILED_MODULES+=("$module_name")
    fi

    echo
}

# Check if the lua binary is available
if ! command -v "${LUA_BINARY}" &> /dev/null; then
    echo -e "${RED}❌ Error: '${LUA_BINARY}' command not found.${NC}"
    exit 1
fi

# Run utils tests
run_test "Utility Functions (bit and bytes)" "utils" "
local result = require('utils').selftest()
if not result then
    os.exit(1)
end
"

# Run Poly1305 tests
run_test "Poly1305 MAC" "poly1305" "
local result = require('crypto.poly1305').selftest()
if not result then
    os.exit(1)
end
"

# Run ChaCha20 tests
run_test "ChaCha20 Stream Cipher" "chacha20" "
local result = require('crypto.chacha20').selftest()
if not result then
    os.exit(1)
end
"

# Run ChaCha20-Poly1305 AEAD tests
run_test "ChaCha20-Poly1305 AEAD" "chacha20_poly1305" "
local result = require('crypto.chacha20_poly1305').selftest()
if not result then
    os.exit(1)
end
"

# Run AESGCM AEAD tests
run_test "AESGCM AEAD" "aes_gcm" "
local result = require('crypto.aes_gcm').selftest()
if not result then
    os.exit(1)
end
"

# Run X25519 tests
run_test "X25519 Curve25519 ECDH" "x25519" "
local result = require('crypto.x25519').selftest()
if not result then
    os.exit(1)
end
"

# Run X448 tests
run_test "X448 Curve448 ECDH" "x448" "
local result = require('crypto.x448').selftest()
if not result then
    os.exit(1)
end
"

# Run SHA-256 tests
run_test "SHA-256 Cryptographic Hash" "sha256" "
local result = require('crypto.sha256').selftest()
if not result then
    os.exit(1)
end
"

# Run SHA-512 tests
run_test "SHA-512 Cryptographic Hash" "sha512" "
local result = require('crypto.sha512').selftest()
if not result then
    os.exit(1)
end
"

# Run BLAKE2 tests
run_test "BLAKE2s/BLAKE2b Cryptographic Hash" "blake2" "
local result = require('crypto.blake2').selftest()
if not result then
    os.exit(1)
end
"

# Run Noise Protocol tests
run_test "Noise Protocol Framework" "noise" "
local result = require('noise').selftest()
if not result then
    os.exit(1)
end
"

# Run Noise vector tests
run_test "Noise Vectors" "noise_vectors" "
local test_noise_vectors = require('tests.test_noise_vectors')
local repo_root = os.getenv('SCRIPT_DIR') or '.'
if not test_noise_vectors(repo_root .. \"/tests/vectors/cacophony_vectors.json\") then
    os.exit(1)
end
if not test_noise_vectors(repo_root .. \"/tests/vectors/snow_vectors.json\") then
    os.exit(1)
end
"

# Summary
echo "========================================="
echo "📊 TEST SUMMARY"
echo "========================================="

if [ $PASSED_COUNT -eq $TOTAL_MODULES ]; then
    echo -e "${GREEN}🎉 ALL MODULES PASSED: $PASSED_COUNT/$TOTAL_MODULES${NC}"
    echo
    echo "Passed modules:"
    for module in "${PASSED_MODULES[@]}"; do
        echo "• $module: ✅ PASS"
    done
    exit 0
else
    echo -e "${RED}💥 SOME MODULES FAILED: $PASSED_COUNT/$TOTAL_MODULES passed${NC}"
    echo
    echo "Failed modules:"
    for module in "${FAILED_MODULES[@]}"; do
        echo "• $module: ❌ FAIL"
    done
    exit 1
fi
