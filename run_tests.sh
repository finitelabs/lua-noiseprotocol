#!/bin/bash

# Noise Protocol Library Test Runner
# Runs all test suites for ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD
#
# Usage: ./run_tests.sh [module_names...]
#
# Examples:
#   ./run_tests.sh                    # Run all modules
#   ./run_tests.sh bitops poly1305    # Run only bitops and poly1305
#   ./run_tests.sh noise              # Run only noise protocol tests
#
# Available modules: utils, utils_bit32, utils_bit64, utils_bytes, poly1305, chacha20, chacha20_poly1305, aes_gcm, x25519, x448, sha256, sha512, blake2, noise, noise_vectors

set -e  # Exit on any error

echo "============================================="
echo "🔐 Noise Protocol Library - Test Suite Runner"
echo "============================================="
echo

# Colors for output
green='\033[0;32m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m' # No Color

# Track overall results
passed_modules=()
failed_modules=()

# Lua binary to use for running tests
lua_binary="${LUA_BINARY:-lua}"

# Check if the lua binary is available
if ! command -v "$lua_binary" &> /dev/null; then
    echo -e "${red}❌ Error: $lua_binary command not found.${nc}"
    exit 1
fi
echo "$($lua_binary -v)"
echo

# Get script directory
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Add repository root to Lua's package path
# This allows require() to find modules in the src/tests directories
lua_path="$script_dir/?.lua;$script_dir/?/init.lua;$script_dir/src/?.lua;$script_dir/src/?/init.lua;$LUA_PATH"

# Define noise vector files
vectors_dir="${NOISE_VECTORS_DIR:=vectors_sampled}"
vector_files=("cacophony.json" "snow.json" "snow_multi_psk.json")

# Parse command line arguments to determine which modules to run
default_modules=("utils_bit32" "utils_bit64" "utils_bytes" "poly1305" "chacha20" "chacha20_poly1305" "aes_gcm" "x25519" "x448" "sha256" "sha512" "blake2" "noise")
all_modules=("utils_bit32" "utils_bit64" "utils_bytes" "poly1305" "chacha20" "chacha20_poly1305" "aes_gcm" "x25519" "x448" "sha256" "sha512" "blake2" "noise" "noise_vectors")
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
            echo -e "${red}❌ Error: Unknown module '$module'${nc}"
            echo "Available modules: ${all_modules[*]}"
            exit 1
        fi
    done
fi

if [ ${#modules_to_run[@]} -eq 0 ]; then
    modules_to_run=("${default_modules[@]}")
    echo "Running default modules: ${modules_to_run[*]}"
elif [ "${modules_to_run[0]}" = "all" ]; then
    modules_to_run=("${all_modules[@]}")
    echo "Running all modules: ${modules_to_run[*]}"
else
    echo "Running specified modules: ${modules_to_run[*]}"
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

# Function to run a test and capture result
run_test() {
    local module_name="$1"
    local module_key="$2"
    local lua_command="$3"

    if ! should_run_module "$module_key"; then
        return
    fi

    echo "---------------------------------------------"
    echo -e "${blue}Testing $module_name...${nc}"
    echo "---------------------------------------------"

    if LUA_PATH="$lua_path" "$lua_binary" -e "$lua_command" 2>&1; then
        echo -e "${green}✅ $module_name: ALL TESTS PASSED${nc}"
        passed_modules+=("$module_name")
    else
        echo -e "${red}❌ $module_name: TESTS FAILED${nc}"
        failed_modules+=("$module_name")
    fi

    echo
}

run_selftest() {
  local module_name="$1"
  local module_key="$2"
  local lua_module="$3"
  run_test "$module_name" "$module_key" "
    local result = require('$lua_module').selftest()
    if not result then
        os.exit(1)
    end
  "
}

run_selftest "Utils - 32-bit operations" "utils_bit32" "noiseprotocol.utils.bit32"
run_selftest "Utils - 64-bit operations" "utils_bit64" "noiseprotocol.utils.bit64"
run_selftest "Utils - Byte operations" "utils_bytes" "noiseprotocol.utils.bytes"
run_selftest "Poly1305 MAC" "poly1305" "noiseprotocol.crypto.poly1305"
run_selftest "ChaCha20 Stream Cipher" "chacha20" "noiseprotocol.crypto.chacha20"
run_selftest "ChaCha20-Poly1305 AEAD" "chacha20_poly1305" "noiseprotocol.crypto.chacha20_poly1305"
run_selftest "AESGCM AEAD" "aes_gcm" "noiseprotocol.crypto.aes_gcm"
run_selftest "X25519 Curve25519 ECDH" "x25519" "noiseprotocol.crypto.x25519"
run_selftest "X448 Curve448 ECDH" "x448" "noiseprotocol.crypto.x448"
run_selftest "SHA-256 Cryptographic Hash" "sha256" "noiseprotocol.crypto.sha256"
run_selftest "SHA-512 Cryptographic Hash" "sha512" "noiseprotocol.crypto.sha512"
run_selftest "BLAKE2 Cryptographic Hash" "blake2" "noiseprotocol.crypto.blake2"
run_selftest "Noise Protocol" "noise" "noiseprotocol"

# Function to run noise vectors in parallel
run_noise_vectors_parallel() {
    set +e  # Disable exit on error for parallel execution

    echo "---------------------------------------------"
    echo -e "${blue}Testing Noise Vectors (Parallel)...${nc}"
    echo "---------------------------------------------"

    local repo_root="$script_dir"
    local temp_dir=$(mktemp -d)
    local all_passed=true
    local num_workers=${NOISE_VECTOR_WORKERS:-4}

    # Show vector file info
    echo "Analyzing vector files..."
    for vector_file in "${vector_files[@]}"; do
        local info=$(LUA_PATH="$lua_path" "$lua_binary" -e "
            local tv = require('tests.test_noise_vectors')
            local info = tv.get_vector_info('$repo_root/tests/$vectors_dir/$vector_file')
            print(string.format('%d total', info.total))
        " 2>&1) || { echo "Error getting info: $info"; exit 1; }
        echo "  $vector_file: $info"
    done

    echo
    echo "Running with $num_workers parallel workers..."

    # Process each vector file
    for vector_file in "${vector_files[@]}"; do
        echo
        echo "Processing $vector_file..."

        # Launch parallel workers
        local pids=()
        for ((i=0; i<num_workers; i++)); do
            (
                LUA_PATH="$lua_path" "$lua_binary" "$repo_root/tests/test_noise_vectors.lua" \
                    "$repo_root/tests/$vectors_dir/$vector_file" "$i" "$num_workers" \
                    > "$temp_dir/worker_$vector_file_$i.out" 2>&1
                echo $? > "$temp_dir/worker_$vector_file_$i.status"
            ) &
            pids+=($!)
        done

        # Wait for all workers to complete
        for pid in "${pids[@]}"; do
            wait $pid
        done

        # Collect results
        local total_passed=0
        local total_failed=0
        local worker_failed=false

        for ((i=0; i<num_workers; i++)); do
            local status_file="$temp_dir/worker_$vector_file_$i.status"
            local output_file="$temp_dir/worker_$vector_file_$i.out"

            if [ -f "$status_file" ]; then
                local status=$(cat "$status_file")
                if [ "$status" -ne 0 ]; then
                    worker_failed=true
                fi
            fi

            if [ -f "$output_file" ]; then
                # Parse results
                local results=$(grep "^RESULTS:" "$output_file" | head -1)
                if [ -n "$results" ]; then
                    local passed=$(echo "$results" | cut -d: -f2)
                    local failed=$(echo "$results" | cut -d: -f3)
                    total_passed=$((total_passed + passed))
                    total_failed=$((total_failed + failed))
                fi

                # Show errors if any
                grep "^ERROR:" "$output_file" | while read -r line; do
                    if [[ ! "$line" =~ ^RESULTS: ]]; then
                      echo "${line#ERROR:}";
                    fi
                done
            fi
        done

        echo "  Results: $total_passed passed, $total_failed failed"

        if [ $total_failed -gt 0 ] || [ "$worker_failed" = true ]; then
            all_passed=false
        fi
    done

    # Clean up
    rm -rf "$temp_dir"

    echo
    if [ "$all_passed" = true ]; then
        echo -e "${green}✅ Noise Vectors: ALL TESTS PASSED${nc}"
        passed_modules+=("Noise Vectors")
    else
        echo -e "${red}❌ Noise Vectors: TESTS FAILED${nc}"
        failed_modules+=("Noise Vectors")
    fi

    echo

    set -e  # Re-enable exit on error
}

# Function to run noise vectors sequentially
run_noise_vectors_sequential() {
    echo "---------------------------------------------"
    echo -e "${blue}Testing Noise Vectors (Sequential)...${nc}"
    echo "---------------------------------------------"

    local all_passed=true
    for vector_file in "${vector_files[@]}"; do
        echo "Processing $vector_file..."
        if ! LUA_PATH="$lua_path" "$lua_binary" -e "
            local tv = require('tests.test_noise_vectors')
            local success = tv.run_all_tests('$script_dir/tests/$vectors_dir/$vector_file')
            if not success then os.exit(1) end
        " 2>&1; then
            all_passed=false
        fi
    done

    if [ "$all_passed" = true ]; then
        echo -e "${green}✅ Noise Vectors: ALL TESTS PASSED${nc}"
        passed_modules+=("Noise Vectors")
    else
        echo -e "${red}❌ Noise Vectors: TESTS FAILED${nc}"
        failed_modules+=("Noise Vectors")
    fi
    echo
}

# Run noise vectors test
if should_run_module "noise_vectors"; then
    # Check if parallel execution is disabled
    if [ "${NOISE_VECTOR_WORKERS:-0}" -le 1 ]; then
        run_noise_vectors_sequential
    else
        # Run parallel version
        run_noise_vectors_parallel
    fi
fi

passed_count=${#passed_modules[@]}
failed_count=${#failed_modules[@]}
total_count=$((passed_count + failed_count))

# If only one module is run, no need to summarize
if [ $total_count -eq 1 ]; then
    exit 0
fi

# Summary
echo "============================================="
echo "📊 TEST SUMMARY"
echo "============================================="

if [ $passed_count -eq $total_count ]; then
    echo -e "${green}🎉 ALL MODULES PASSED: $passed_count/$total_count${nc}"
    echo
    echo "Passed modules:"
    for module in "${passed_modules[@]}"; do
        echo "• $module: ✅ PASS"
    done
    exit 0
else
    echo -e "${red}💥 SOME MODULES FAILED: $passed_count/$total_count passed${nc}"
    echo
    echo "Failed modules:"
    for module in "${failed_modules[@]}"; do
        echo "• $module: ❌ FAIL"
    done
    exit 1
fi
