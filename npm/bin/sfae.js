#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const binaryPath = path.join(__dirname, "sfae");
const packageName = "@fundamental-research-labs/sfae";

if (!fs.existsSync(binaryPath)) {
  console.error(
    `sfae native binary is not installed. Reinstall the package or run \`npm rebuild ${packageName}\`.`
  );
  process.exit(1);
}

const env = {
  ...process.env,
  SFAE_INSTALL_METHOD: process.env.SFAE_INSTALL_METHOD || "npm",
  SFAE_NPM_PACKAGE: process.env.SFAE_NPM_PACKAGE || packageName
};

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env
});

child.on("error", (error) => {
  console.error(`failed to start sfae: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
