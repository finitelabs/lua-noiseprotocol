#!/usr/bin/env node

const luabundle = require("luabundle");
const fs = require("fs");
const path = require("path");

console.log("Building combined noiseprotocol.lua for multiple Lua versions...");

// Clean up any existing build
const buildDir = path.join(__dirname, "build");
if (fs.existsSync(buildDir)) {
  fs.rmSync(buildDir, { recursive: true });
}
fs.mkdirSync(buildDir, { recursive: true });

// Lua versions to build for (luabundle only supports up to 5.3)
const luaVersions = ["5.1", "5.2", "5.3", "LuaJIT"];

// Build for each version
for (const version of luaVersions) {
  console.log(`Building for Lua ${version}...`);

  const versionName = version === "LuaJIT" ? "LuaJIT" : `Lua${version}`;

  try {
    const result = luabundle.bundle("./src/noiseprotocol/init.lua", {
      luaVersion: version,
      isolate: true,
      excludes: [],
      paths: ["./src/?.lua", "./src/?/init.lua", "./?.lua", "./?/init.lua"],
    });

    const outputFile = path.join(
      buildDir,
      `noiseprotocol-${versionName.toLowerCase()}.lua`,
    );
    fs.writeFileSync(outputFile, result);

    const stats = fs.statSync(outputFile);
    console.log(`✅ Build successful for ${versionName}!`);
    console.log(`File size: ${stats.size} bytes`);
  } catch (error) {
    console.error(`❌ Build failed for ${versionName}:`, error.message);
    process.exit(1);
  }
}

// Also create a default build (5.1 compatible)
console.log("Creating default build (Lua 5.1 compatible)...");
fs.copyFileSync(
  path.join(buildDir, "noiseprotocol-lua5.1.lua"),
  path.join(buildDir, "noiseprotocol.lua"),
);

console.log("");
console.log("✅ All builds complete!");
console.log("Files created:");
const files = fs.readdirSync(buildDir).filter((f) => f.endsWith(".lua"));
for (const file of files) {
  const stats = fs.statSync(path.join(buildDir, file));
  console.log(`  ${file} (${stats.size} bytes)`);
}
