#!/bin/bash

# Noise Protocol Library Benchmark Runner
# Runs performance benchmarks for crypto modules
#
# Usage: ./run_benchmarks.sh [module_names...]
#
# Examples:
#   ./run_benchmarks.sh                   # Run all benchmarks
#   ./run_benchmarks.sh x448 x25519       # Run only x448 and x25519 benchmarks
#
# Available modules: aes_gcm, blake2, chacha20, chacha20_poly1305, poly1305, sha256, sha512, x448, x25519

set -e  # Exit on any error

echo "============================================="
echo "⚡ Noise Protocol Library - Benchmark Runner"
echo "============================================="
echo

# Colors for output
green='\033[0;32m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m' # No Color

# Track overall results
completed_modules=()
failed_modules=()

lua_binary="${LUA_BINARY:-luajit}"  # Use luajit by default, can be overridden

# Check if the lua binary is available
if ! command -v "$lua_binary" &> /dev/null; then
    echo -e "${red}❌ Error: '$lua_binary' command not found.${nc}"
    exit 1
fi
echo "$($lua_binary -v)"
echo

# Get script directory
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Add repository root to Lua's package path
lua_path="$script_dir/?.lua;$script_dir/?/init.lua;$script_dir/src/?.lua;$script_dir/src/?/init.lua;$script_dir/vendor/?.lua;$LUA_PATH"

# Parse command line arguments to determine which modules to run
default_modules=("aes_gcm" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "sha256" "sha512" "x448" "x25519")
all_modules=("aes_gcm" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "sha256" "sha512" "x448" "x25519")
modules_to_run=("$@")

# Validate modules if specified
if [ ${#modules_to_run[@]} -gt 0 ] && [ "${modules_to_run[0]}" != "all" ]; then
    for module in "${modules_to_run[@]}"; do
        valid=0
        for valid_module in "${all_modules[@]}"; do
            if [ "$module" = "$valid_module" ]; then
                valid=1
                break
            fi
        done
        if [ $valid -eq 0 ]; then
            echo -e "${red}❌ Error: Unknown module '$module' or benchmark not implemented${nc}"
            echo "Available modules: ${all_modules[*]}"
            exit 1
        fi
    done
fi

if [ ${#modules_to_run[@]} -eq 0 ]; then
    # No arguments provided, run all benchmarks
    modules_to_run=("${default_modules[@]}")
    echo "Running default benchmarks: ${modules_to_run[*]}"
elif [ "${modules_to_run[0]}" = "all" ]; then
    modules_to_run=("${all_modules[@]}")
    echo "Running all benchmarks: ${modules_to_run[*]}"
else
    echo "Running specified benchmarks: ${modules_to_run[*]}"
fi
echo

# Function to check if a module should be run
should_run_module() {
    local module_key="$1"
    for module in "${modules_to_run[@]}"; do
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

    echo "---------------------------------------------"
    echo -e "${blue}Benchmarking $module_name...${nc}"
    echo "---------------------------------------------"

    if LUA_PATH="$lua_path" "$lua_binary" -e "$lua_command" 2>&1; then
        echo -e "\n${green}✅ $module_name: BENCHMARK COMPLETED${nc}"
        completed_modules+=("$module_name")
    else
        echo -e "\n${red}❌ $module_name: BENCHMARK FAILED${nc}"
        failed_modules+=("$module_name")
    fi

    echo
}

run_module_benchmark() {
  local module_name="$1"
  local module_key="$2"
  local lua_module="$3"
  run_benchmark "$module_name" "$module_key" "
    require('$lua_module').benchmark()
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

completed_count=${#completed_modules[@]}
failed_count=${#failed_modules[@]}
total_count=$((completed_count + failed_count))

# If only one module is run, no need to summarize
if [ $total_count -eq 1 ]; then
    exit 0
fi

# Summary
echo "============================================="
echo "📊 BENCHMARK SUMMARY"
echo "============================================="

if [ ${#failed_modules[@]} -eq 0 ]; then
    echo -e "${green}🎉 ALL BENCHMARKS COMPLETED: $completed_count/$total_count${nc}"
    echo
    echo "Completed benchmarks:"
    for module in "${completed_modules[@]}"; do
        echo "• $module: ✅ COMPLETE"
    done
else
    echo -e "${red}⚠️  SOME BENCHMARKS FAILED: $failed_count/$total_count${nc}"
    echo
    echo "Failed benchmarks:"
    for module in "${failed_modules[@]}"; do
        echo "• $module: ❌ FAILED"
    done
    exit 1
fi
