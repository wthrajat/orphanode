#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const options = parseArguments(process.argv.slice(2));
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const fixturesRoot = path.join(repositoryRoot, "fixtures");
const outputDirectory = path.resolve(options.output);
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "orphanode-contract-"));

try {
  const fixtureEntries = await readdir(fixturesRoot, { withFileTypes: true });
  const fixtures = fixtureEntries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  await mkdir(outputDirectory, { recursive: true });

  let reportCount = 0;
  for (const fixture of fixtures) {
    const fixtureRoot = path.join(fixturesRoot, fixture);
    const manifestPath = path.join(fixtureRoot, "files.json");
    try {
      await readFile(manifestPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        continue;
      }
      throw error;
    }

    const output = runScan(options.binary, fixtureRoot, manifestPath);
    JSON.parse(output);
    await writeFile(path.join(outputDirectory, `${fixture}.json`), output);
    reportCount += 1;
  }

  assert(reportCount > 0, "no fixture reports were produced");
  await verifyManifestOrderDeterminism(options.binary, temporaryDirectory);
  console.log(`validated ${reportCount} fixture reports and manifest-order determinism`);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    values.set(argumentsList[index], argumentsList[index + 1]);
  }
  const binary = values.get("--binary");
  const output = values.get("--output");
  if (!binary || !output) {
    throw new Error("usage: contract.mjs --binary PATH --output DIRECTORY");
  }
  return { binary: path.resolve(binary), output };
}

function runScan(binary, root, manifestPath) {
  const result = spawnSync(
    binary,
    ["scan", "--root", root, "--files-from", manifestPath, "--format", "json"],
    { encoding: "utf8" },
  );
  if (![0, 1, 2].includes(result.status)) {
    throw new Error(
      `scan failed with status ${result.status}: ${result.stderr || result.error || "no details"}`,
    );
  }
  assert(result.stdout.trim().length > 0, "scan produced no JSON output");
  return result.stdout;
}

async function verifyManifestOrderDeterminism(binary, temporaryDirectory) {
  const fixtureRoot = path.join(fixturesRoot, "esm");
  const sourceManifest = JSON.parse(
    await readFile(path.join(fixtureRoot, "files.json"), "utf8"),
  );
  assert(sourceManifest.files.length > 1, "determinism fixture needs multiple files");

  let expectedOutput;
  for (let iteration = 0; iteration < 10; iteration += 1) {
    const offset = iteration % sourceManifest.files.length;
    const files = [
      ...sourceManifest.files.slice(offset),
      ...sourceManifest.files.slice(0, offset),
    ];
    if (iteration % 2 === 1) {
      files.reverse();
    }
    const manifestPath = path.join(temporaryDirectory, `files-${iteration}.json`);
    await writeFile(manifestPath, JSON.stringify({ ...sourceManifest, files }));
    const output = runScan(binary, fixtureRoot, manifestPath);
    JSON.parse(output);
    expectedOutput ??= output;
    assert.equal(output, expectedOutput, `JSON changed for manifest order ${iteration}`);
  }
}
