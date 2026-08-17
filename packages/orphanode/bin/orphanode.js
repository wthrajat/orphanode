#!/usr/bin/env node

"use strict";

const { LauncherError, run } = require("../lib/launcher.js");

try {
  const result = run(process.argv.slice(2));
  if (result.signal) {
    process.kill(process.pid, result.signal);
  } else {
    process.exitCode = result.status;
  }
} catch (error) {
  const message =
    error instanceof LauncherError
      ? error.message
      : `Unexpected launcher failure: ${error.message}`;
  process.stderr.write(`orphanode: ${message}\n`);
  process.exitCode = 1;
}
