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
# Available modules: utils, utils_bit32, utils_bit64, utils_bytes, poly1305, chacha20, chacha20_poly1305, aes_gcm, x25519, x448, sha256, sha512, blake2, noise, noise_vectors

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
# This allows require() to find modules in the repository root
export LUA_PATH="$SCRIPT_DIR/?.lua;$SCRIPT_DIR/?/init.lua;$SCRIPT_DIR/src/?.lua;$SCRIPT_DIR/src/?/init.lua;$LUA_PATH"
export SCRIPT_DIR

# Define noise vector files
NOISE_VECTORS_DIR="${NOISE_VECTORS_DIR:=vectors_sampled}"
NOISE_VECTOR_FILES=("cacophony.json" "snow.json" "snow_multi_psk.json")

# Parse command line arguments to determine which modules to run
DEFAULT_MODULES_TO_RUN=("utils_bit32" "utils_bit64" "utils_bytes" "poly1305" "chacha20" "chacha20_poly1305" "aes_gcm" "x25519" "x448" "sha256" "sha512" "blake2" "noise")
ALL_VALID_MODULES=("utils_bit32" "utils_bit64" "utils_bytes" "poly1305" "chacha20" "chacha20_poly1305" "aes_gcm" "x25519" "x448" "sha256" "sha512" "blake2" "noise" "noise_vectors")
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
            echo -e "${RED}❌ Error: Unknown module '$module'${NC}"
            echo "Available modules: ${ALL_VALID_MODULES[*]}"
            exit 1
        fi
    done
fi

if [ ${#MODULES_TO_RUN[@]} -eq 0 ]; then
    # No arguments provided, run all modules except noise_vectors
    MODULES_TO_RUN=("${DEFAULT_MODULES_TO_RUN[@]}")
    echo "Running default modules: ${MODULES_TO_RUN[*]}"
elif [ "${MODULES_TO_RUN[0]}" = "all" ]; then
    MODULES_TO_RUN=("${ALL_VALID_MODULES[@]}")
    echo "Running all modules: ${MODULES_TO_RUN[*]}"
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
        return
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

run_selftest() {
  local module_name="$1"
  local module_key="$2"
  local lua_module="$3"
  run_test "${module_name}" "${module_key}" "
    local result = require('${lua_module}').selftest()
    if not result then
        os.exit(1)
    end
  "
}

run_selftest "Utility Functions - 32-bit operations" "utils_bit32" "noiseprotocol.utils.bit32"
run_selftest "Utility Functions - 64-bit operations" "utils_bit64" "noiseprotocol.utils.bit64"
run_selftest "Utility Functions - Byte operations" "utils_bytes" "noiseprotocol.utils.bytes"
run_selftest "Poly1305 MAC" "poly1305" "noiseprotocol.crypto.poly1305"
run_selftest "ChaCha20 Stream Cipher" "chacha20" "noiseprotocol.crypto.chacha20"
run_selftest "ChaCha20-Poly1305 AEAD" "chacha20_poly1305" "noiseprotocol.crypto.chacha20_poly1305"
run_selftest "AESGCM AEAD" "aes_gcm" "noiseprotocol.crypto.aes_gcm"
run_selftest "X25519 Curve25519 ECDH" "x25519" "noiseprotocol.crypto.x25519"
run_selftest "X448 Curve448 ECDH" "x448" "noiseprotocol.crypto.x448"
run_selftest "SHA-256 Cryptographic Hash" "sha256" "noiseprotocol.crypto.sha256"
run_selftest "SHA-512 Cryptographic Hash" "sha512" "noiseprotocol.crypto.sha512"
run_selftest "BLAKE2s/BLAKE2b Cryptographic Hash" "blake2" "noiseprotocol.crypto.blake2"
run_selftest "Noise Protocol Framework" "noise" "noiseprotocol"

# Function to run noise vectors in parallel
run_noise_vectors_parallel() {
    set +e  # Disable exit on error for parallel execution

    echo -e "${BLUE}Testing Noise Vectors (Parallel)...${NC}"
    echo "----------------------------------------"

    TOTAL_MODULES=$((TOTAL_MODULES + 1))

    local repo_root="$SCRIPT_DIR"
    local temp_dir=$(mktemp -d)
    local all_passed=true
    local num_workers=${NOISE_VECTOR_WORKERS:-4}

    # Show vector file info
    echo "Analyzing vector files..."
    for vector_file in "${NOISE_VECTOR_FILES[@]}"; do
        local info=$("${LUA_BINARY}" -e "
            local tv = require('tests.test_noise_vectors')
            local info = tv.get_vector_info('$repo_root/tests/${NOISE_VECTORS_DIR}/$vector_file')
            print(string.format('%d total', info.total))
        " 2>&1) || { echo "Error getting info: $info"; exit 1; }
        echo "  $vector_file: $info"
    done

    echo
    echo "Running with $num_workers parallel workers..."

    # Process each vector file
    for vector_file in "${NOISE_VECTOR_FILES[@]}"; do
        echo
        echo "Processing $vector_file..."

        # Launch parallel workers
        local pids=()
        for ((i=0; i<num_workers; i++)); do
            (
                "${LUA_BINARY}" "$repo_root/tests/test_noise_vectors.lua" \
                    "$repo_root/tests/${NOISE_VECTORS_DIR}/$vector_file" "$i" "$num_workers" \
                    > "$temp_dir/worker_${vector_file}_${i}.out" 2>&1
                echo $? > "$temp_dir/worker_${vector_file}_${i}.status"
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
            local status_file="$temp_dir/worker_${vector_file}_${i}.status"
            local output_file="$temp_dir/worker_${vector_file}_${i}.out"

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
        echo -e "${GREEN}✅ Noise Vectors: ALL TESTS PASSED${NC}"
        PASSED_MODULES+=("Noise Vectors")
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "${RED}❌ Noise Vectors: TESTS FAILED${NC}"
        FAILED_MODULES+=("Noise Vectors")
    fi

    echo

    set -e  # Re-enable exit on error
}

# Function to run noise vectors sequentially
run_noise_vectors_sequential() {
    echo -e "${BLUE}Testing Noise Vectors (Sequential)...${NC}"
    echo "----------------------------------------"
    TOTAL_MODULES=$((TOTAL_MODULES + 1))

    local all_passed=true
    for vector_file in "${NOISE_VECTOR_FILES[@]}"; do
        echo "Processing $vector_file..."
        if ! "${LUA_BINARY}" -e "
            local tv = require('tests.test_noise_vectors')
            local repo_root = os.getenv('SCRIPT_DIR') or '.'
            local vectors_dir = os.getenv('NOISE_VECTORS_DIR') or 'vectors_sampled'
            local success = tv.run_all_tests(repo_root .. '/tests/' .. vectors_dir .. '/$vector_file')
            if not success then os.exit(1) end
        " 2>&1; then
            all_passed=false
        fi
    done

    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}✅ Noise Vectors: ALL TESTS PASSED${NC}"
        PASSED_MODULES+=("Noise Vectors")
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "${RED}❌ Noise Vectors: TESTS FAILED${NC}"
        FAILED_MODULES+=("Noise Vectors")
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
