#!/bin/bash

# List of luaenv versions to test
LUA_VERSIONS=("5.1.5" "5.2.4" "5.3.6" "5.4.8" "luajit-2.1-dev")

# Colors for output
green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0;31m'
nc='\033[0m' # No Color

luaenv_binary="${LUAENV_BINARY:-luaenv}"  # Use luaenv by default, can be overridden

# Get script directory
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! command -v "$luaenv_binary" &> /dev/null; then
    echo -e "${red}❌ Error: $luaenv_binary command not found.${nc}"
    exit 1
fi

if [ ! -d "$($luaenv_binary prefix)/../../plugins/luaenv-luarocks" ]; then
    echo -e "${red}❌ Error: luaenv-luarocks plugin not found. Please install it first.${nc}"
    exit 1
fi

# Track overall results
failed_versions=()
passed_versions=()

for lua_version in "${LUA_VERSIONS[@]}"; do
    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo -e "${yellow}Running tests with $lua_version${nc}"
    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo

    "$luaenv_binary" install -s $lua_version
    lua_prefix="$($luaenv_binary prefix $lua_version)"
    lua_binary="$lua_prefix/bin/lua"
    luarocks_binary="$lua_prefix/bin/luarocks"

    # Run the tests and pass all arguments
    if ! LUA_BINARY="$lua_binary" "$script_dir/run_tests.sh" "$@"; then
        failed_versions+=("$lua_version")
    else
        passed_versions+=("$lua_version")
    fi

    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo -e "${yellow}Running tests with $lua_version (OpenSSL)${nc}"
    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo

    "$luarocks_binary" install openssl 1>/dev/null

    if ! NOISE_USE_OPENSSL=1 LUA_BINARY="$lua_binary" "$script_dir/run_tests.sh" "$@"; then
        failed_versions+=("$lua_version (OpenSSL)")
    else
        passed_versions+=("$lua_version (OpenSSL)")
    fi
done

# Final summary
echo "============================================="
echo "📊 Matrix Test Summary"
echo "============================================="

if [ ${#failed_versions[@]} -eq 0 ]; then
    echo -e "${green}✅ All LUA VERSIONS PASSED:${nc}"
    printf '%s\n' "${passed_versions[@]}"
    exit 0
else
    echo -e "${red}💥 SOME LUA VERSIONS FAILED:${nc}"
    printf '%s\n' "${failed_versions[@]}"
    exit 1
fi