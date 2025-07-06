#!/bin/bash

# Lua Crypto Library Benchmark Runner
# Runs performance benchmarks for crypto modules
#
# Usage: ./run_benchmarks.sh [module_names...]
#
# Examples:
#   ./run_benchmarks.sh                    # Run all benchmarks
#   ./run_benchmarks.sh x448 x25519       # Run only x448 and x25519 benchmarks
#
# Available modules: x448 (more to be added)

set -e  # Exit on any error

echo "⚡ Lua Crypto Library - Benchmark Runner"
echo "========================================"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall results
TOTAL_MODULES=0
COMPLETED_MODULES=()
FAILED_MODULES=()

LUA_BINARY="${LUA_BINARY:-luajit}"  # Use luajit by default, can be overridden

# Check if the lua binary is available
if ! command -v "${LUA_BINARY}" &> /dev/null; then
    echo -e "${RED}❌ Error: '${LUA_BINARY}' command not found.${NC}"
    exit 1
fi
echo "Lua version: $(${LUA_BINARY} -v)"
echo

# Get script directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Add repository root to Lua's package path
export LUA_PATH="$SCRIPT_DIR/?.lua;$SCRIPT_DIR/?/init.lua;$SCRIPT_DIR/src/?.lua;$SCRIPT_DIR/src/?/init.lua;$LUA_PATH"
export SCRIPT_DIR

# Parse command line arguments to determine which modules to run
DEFAULT_MODULES_TO_RUN=("aes_gcm" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "sha256" "sha512" "x448" "x25519")
ALL_VALID_MODULES=("aes_gcm" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "sha256" "sha512" "x448" "x25519")
MODULES_TO_RUN=("$@")

# Validate modules if specified
if [ ${#MODULES_TO_RUN[@]} -gt 0 ] && [ "${MODULES_TO_RUN[0]}" != "all" ]; then
    for module in "${MODULES_TO_RUN[@]}"; do
        valid=0
        for valid_module in "${ALL_VALID_MODULES[@]}"; do
            if [ "$module" = "$valid_module" ]; then
                valid=1
                break
            fi
        done
        if [ $valid -eq 0 ]; then
            echo -e "${RED}❌ Error: Unknown module '$module' or benchmark not implemented${NC}"
            echo "Available modules: ${ALL_VALID_MODULES[*]}"
            exit 1
        fi
    done
fi

if [ ${#MODULES_TO_RUN[@]} -eq 0 ]; then
    # No arguments provided, run all benchmarks
    MODULES_TO_RUN=("${DEFAULT_MODULES_TO_RUN[@]}")
    echo "Running default benchmarks: ${MODULES_TO_RUN[*]}"
elif [ "${MODULES_TO_RUN[0]}" = "all" ]; then
    MODULES_TO_RUN=("${ALL_VALID_MODULES[@]}")
    echo "Running all benchmarks: ${MODULES_TO_RUN[*]}"
else
    echo "Running specified benchmarks: ${MODULES_TO_RUN[*]}"
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

# Function to run a benchmark and capture result
run_benchmark() {
    local module_name="$1"
    local module_key="$2"
    local lua_command="$3"

    if ! should_run_module "$module_key"; then
        return
    fi

    echo -e "${BLUE}Benchmarking $module_name...${NC}"
    echo "----------------------------------------"

    TOTAL_MODULES=$((TOTAL_MODULES + 1))

    if "${LUA_BINARY}" -e "$lua_command" 2>&1; then
        echo -e "${GREEN}✅ $module_name: BENCHMARK COMPLETED${NC}"
        COMPLETED_MODULES+=("$module_name")
    else
        echo -e "${RED}❌ $module_name: BENCHMARK FAILED${NC}"
        FAILED_MODULES+=("$module_name")
    fi

    echo
}

run_module_benchmark() {
  local module_name="$1"
  local module_key="$2"
  local lua_module="$3"
  run_benchmark "${module_name}" "${module_key}" "
    require('${lua_module}').benchmark()
  "
}

# Run benchmarks
run_module_benchmark "AES-GCM AEAD" "aes_gcm" "noiseprotocol.crypto.aes_gcm"
run_module_benchmark "BLAKE2 Hash" "blake2" "noiseprotocol.crypto.blake2"
run_module_benchmark "ChaCha20 Stream Cipher" "chacha20" "noiseprotocol.crypto.chacha20"
run_module_benchmark "ChaCha20-Poly1305 AEAD" "chacha20_poly1305" "noiseprotocol.crypto.chacha20_poly1305"
run_module_benchmark "Poly1305 MAC" "poly1305" "noiseprotocol.crypto.poly1305"
run_module_benchmark "SHA-256 Hash" "sha256" "noiseprotocol.crypto.sha256"
run_module_benchmark "SHA-512 Hash" "sha512" "noiseprotocol.crypto.sha512"
run_module_benchmark "X25519 Curve25519 ECDH" "x25519" "noiseprotocol.crypto.x25519"
run_module_benchmark "X448 Curve448 ECDH" "x448" "noiseprotocol.crypto.x448"

# Summary
echo "========================================="
echo "📊 BENCHMARK SUMMARY"
echo "========================================="

if [ ${#FAILED_MODULES[@]} -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL BENCHMARKS COMPLETED: $TOTAL_MODULES/$TOTAL_MODULES${NC}"
else
    echo -e "${RED}⚠️  SOME BENCHMARKS FAILED: ${#FAILED_MODULES[@]}/$TOTAL_MODULES${NC}"
fi

if [ ${#COMPLETED_MODULES[@]} -gt 0 ]; then
    echo
    echo "Completed benchmarks:"
    for module in "${COMPLETED_MODULES[@]}"; do
        echo "• $module: ✅ COMPLETE"
    done
fi

if [ ${#FAILED_MODULES[@]} -gt 0 ]; then
    echo
    echo "Failed benchmarks:"
    for module in "${FAILED_MODULES[@]}"; do
        echo "• $module: ❌ FAILED"
    done
    exit 1
fi
