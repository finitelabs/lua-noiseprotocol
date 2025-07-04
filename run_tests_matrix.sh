#!/bin/bash

# List of Lua versions to test
LUA_VERSIONS=("lua5.1" "lua5.2" "lua5.3" "lua5.4" "luajit")

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Track overall results
FAILED_VERSIONS=()

for lua_version in "${LUA_VERSIONS[@]}"; do
    echo "========================================="
    echo "Running tests with $lua_version"
    echo "========================================="

    # Check if the Lua version is available
    if ! command -v "$lua_version" &> /dev/null; then
        echo -e "${RED}❌ Error: '$lua_version' not found, skipping...${NC}"
        FAILED_VERSIONS+=("$lua_version (not installed)")
        continue
    fi

    # Export LUA_BINARY for run_tests.sh
    export LUA_BINARY="$lua_version"

    # Run the tests and pass all arguments
    if ! "$SCRIPT_DIR/run_tests.sh" "$@"; then
        FAILED_VERSIONS+=("$lua_version")
    fi

    echo
done

# Final summary
echo "========================================="
echo "📊 Matrix Test Summary"
echo "========================================="

if [ ${#FAILED_VERSIONS[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All LUA VERSIONS PASSED${NC}"
    exit 0
else
    echo -e "${RED}💥 SOME LUA VERSIONS FAILED:${NC}"
    printf '%s\n' "${FAILED_VERSIONS[@]}"
    exit 1
fi