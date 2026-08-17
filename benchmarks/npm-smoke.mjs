#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const platformPackages = {
  "linux-x64-gnu": "@orphanode/linux-x64-gnu",
  "darwin-arm64": "@orphanode/darwin-arm64",
  "darwin-x64": "@orphanode/darwin-x64",
  "win32-x64-msvc": "@orphanode/win32-x64-msvc",
};
const platformTargets = {
  "linux-x64-gnu": "x86_64-unknown-linux-gnu",
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "win32-x64-msvc": "x86_64-pc-windows-msvc",
};
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const packagesRoot = path.join(repositoryRoot, "packages");
const npmCache = path.join(os.tmpdir(), "orphanode-npm-cache");
const command = process.argv[2];
const options = parseArguments(process.argv.slice(3));

switch (command) {
  case "smoke":
    await smokeNativePackage();
    break;
  case "pack-platform":
    await packPlatformPackage();
    break;
  case "pack-launcher":
    await packLauncherPackage();
    break;
  case "pack-worker":
    await packWorkerPackage();
    break;
  case "validate":
    await validateNpmMetadata();
    break;
  default:
    throw new Error(
      "usage: npm-smoke.mjs <smoke|pack-platform|pack-launcher|pack-worker|validate> [options]",
    );
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    values.set(argumentsList[index], argumentsList[index + 1]);
  }
  return Object.fromEntries(values);
}

async function smokeNativePackage() {
  requireOptions("--platform", "--binary", "--output");
  const workDirectory = await mkdtemp(path.join(os.tmpdir(), "orphanode-npm-smoke-"));
  try {
    const outputDirectory = path.resolve(options["--output"]);
    const platformTarball = await stageAndPackPlatform(
      options["--platform"],
      path.resolve(options["--binary"]),
      outputDirectory,
      options["--version"],
      workDirectory,
    );
    const launcherStage = path.join(workDirectory, "launcher");
    const launcherPackage = await stageLauncher(launcherStage, options["--version"]);
    const workerStage = path.join(workDirectory, "typescript-worker");
    const workerPackage = await stageWorker(workerStage, options["--version"]);
    const workerTarball = await npmPack(workerStage, workDirectory);
    launcherPackage.dependencies = {
      "@orphanode/typescript-worker": `file:${workerTarball}`,
    };
    const platformName = platformPackages[options["--platform"]];
    assert(platformName, `unsupported platform ${options["--platform"]}`);
    launcherPackage.optionalDependencies = {
      [platformName]: `file:${platformTarball}`,
    };
    await writeJson(path.join(launcherStage, "package.json"), launcherPackage);
    const launcherTarball = await npmPack(launcherStage, workDirectory);

    const installDirectory = path.join(workDirectory, "install");
    await mkdir(installDirectory);
    await writeJson(path.join(installDirectory, "package.json"), {
      private: true,
      dependencies: { orphanode: `file:${launcherTarball}` },
    });
    runNpm(
      ["install", "--ignore-scripts=false", "--no-audit", "--no-fund", "--no-package-lock"],
      installDirectory,
    );
    const executable = path.join(
      installDirectory,
      "node_modules",
      ".bin",
      process.platform === "win32" ? "orphanode.cmd" : "orphanode",
    );
    const result = spawnSync(executable, ["--version"], {
      cwd: installDirectory,
      encoding: "utf8",
      shell: process.platform === "win32",
    });
    assert.equal(
      result.status,
      0,
      `installed orphanode --version failed: ${result.stderr || result.error || "no details"}`,
    );
    assert(result.stdout.trim().length > 0, "installed orphanode --version was empty");
    console.log(result.stdout.trim());
  } finally {
    await rm(workDirectory, { recursive: true, force: true });
  }
}

async function packPlatformPackage() {
  requireOptions("--platform", "--binary", "--output", "--version");
  const workDirectory = await mkdtemp(path.join(os.tmpdir(), "orphanode-npm-pack-"));
  try {
    await stageAndPackPlatform(
      options["--platform"],
      path.resolve(options["--binary"]),
      path.resolve(options["--output"]),
      options["--version"],
      workDirectory,
    );
  } finally {
    await rm(workDirectory, { recursive: true, force: true });
  }
}

async function packLauncherPackage() {
  requireOptions("--output", "--version");
  const workDirectory = await mkdtemp(path.join(os.tmpdir(), "orphanode-npm-launcher-"));
  try {
    const launcherStage = path.join(workDirectory, "launcher");
    await stageLauncher(launcherStage, options["--version"]);
    const tarball = await npmPack(launcherStage, path.resolve(options["--output"]));
    await writeChecksum(tarball);
  } finally {
    await rm(workDirectory, { recursive: true, force: true });
  }
}

async function packWorkerPackage() {
  requireOptions("--output", "--version");
  const workDirectory = await mkdtemp(path.join(os.tmpdir(), "orphanode-npm-worker-"));
  try {
    const workerStage = path.join(workDirectory, "typescript-worker");
    await stageWorker(workerStage, options["--version"]);
    const tarball = await npmPack(workerStage, path.resolve(options["--output"]));
    await writeChecksum(tarball);
  } finally {
    await rm(workDirectory, { recursive: true, force: true });
  }
}

async function validateNpmMetadata() {
  requireOptions("--version");
  const expectedVersion = options["--version"];
  const launcherPackage = await readJson(path.join(packagesRoot, "orphanode", "package.json"));
  validateLauncherManifest(launcherPackage, expectedVersion);
  const workerPackage = await readJson(
    path.join(packagesRoot, "typescript-worker", "package.json"),
  );
  validateWorkerManifest(workerPackage, expectedVersion);

  for (const [platform, expectedName] of Object.entries(platformPackages)) {
    const packageJson = await readJson(
      path.join(packagesRoot, "platforms", platform, "package.json"),
    );
    assert.equal(packageJson.name, expectedName, `${platform} has the wrong package name`);
    verifyVersion(packageJson.version, expectedVersion, expectedName);
    nativeDistribution(packageJson, platform);
  }
  console.log(`validated all npm package metadata at ${expectedVersion}`);
}

async function stageAndPackPlatform(platform, binary, output, expectedVersion, work) {
  const expectedName = platformPackages[platform];
  assert(expectedName, `unsupported platform ${platform}`);
  const sourceDirectory = path.join(packagesRoot, "platforms", platform);
  const stageDirectory = path.join(work, platform);
  await copyPackage(sourceDirectory, stageDirectory);
  const packageJsonPath = path.join(stageDirectory, "package.json");
  const packageJson = await readJson(packageJsonPath);
  assert.equal(packageJson.name, expectedName, `${platform} has the wrong package name`);
  verifyVersion(packageJson.version, expectedVersion, expectedName);

  const distribution = nativeDistribution(packageJson, platform);
  const binaryRelativePath = distribution.binary;
  const binaryDestination = path.join(stageDirectory, binaryRelativePath);
  assert(
    isInside(stageDirectory, binaryDestination),
    `${expectedName} binary path escapes its package directory`,
  );
  await mkdir(path.dirname(binaryDestination), { recursive: true });
  await cp(binary, binaryDestination);
  if (process.platform !== "win32") {
    await chmod(binaryDestination, 0o755);
  }
  const binaryContents = await readFile(binaryDestination);
  const binaryDigest = createHash("sha256").update(binaryContents).digest("hex");
  const checksumDestination = path.join(stageDirectory, distribution.checksum);
  assert(
    isInside(stageDirectory, checksumDestination),
    `${expectedName} checksum path escapes its package directory`,
  );
  await mkdir(path.dirname(checksumDestination), { recursive: true });
  await writeFile(
    checksumDestination,
    `${binaryDigest}  ${path.basename(binaryDestination)}\n`,
  );
  const tarball = await npmPack(stageDirectory, output);
  await writeChecksum(tarball);
  return tarball;
}

async function stageLauncher(destination, expectedVersion) {
  const sourceDirectory = path.join(packagesRoot, "orphanode");
  await copyPackage(sourceDirectory, destination);
  const packageJson = await readJson(path.join(destination, "package.json"));
  validateLauncherManifest(packageJson, expectedVersion);
  return packageJson;
}

async function stageWorker(destination, expectedVersion) {
  const sourceDirectory = path.join(packagesRoot, "typescript-worker");
  await copyPackage(sourceDirectory, destination);
  const packageJson = await readJson(path.join(destination, "package.json"));
  validateWorkerManifest(packageJson, expectedVersion);
  return packageJson;
}

function validateLauncherManifest(packageJson, expectedVersion) {
  assert.equal(packageJson.name, "orphanode", "launcher package must be named orphanode");
  verifyVersion(packageJson.version, expectedVersion, "orphanode");
  assert.equal(typeof packageJson.bin, "object", "orphanode must declare a bin object");
  assert.equal(typeof packageJson.bin.orphanode, "string", "orphanode must expose bin.orphanode");
  assert.equal(
    packageJson.dependencies?.["@orphanode/typescript-worker"],
    packageJson.version,
    "orphanode must depend on its exact TypeScript worker version",
  );

  const optionalDependencies = packageJson.optionalDependencies;
  assert(optionalDependencies, "orphanode must declare platform optionalDependencies");
  for (const packageName of Object.values(platformPackages)) {
    assert.equal(
      optionalDependencies[packageName],
      packageJson.version,
      `orphanode must depend on exact ${packageName}@${packageJson.version}`,
    );
  }
}

function validateWorkerManifest(packageJson, expectedVersion) {
  assert.equal(
    packageJson.name,
    "@orphanode/typescript-worker",
    "worker package has the wrong name",
  );
  verifyVersion(packageJson.version, expectedVersion, packageJson.name);
  assert.equal(packageJson.private, false, "worker package must be publishable");
  assert.equal(
    packageJson.exports?.["./worker"],
    "./src/worker.mjs",
    "worker package must export its protocol entrypoint",
  );
}

function nativeDistribution(packageJson, platform) {
  const executableName = platform.startsWith("win32-") ? "orphanode.exe" : "orphanode";
  const distribution = packageJson.orphanode;
  assert.equal(
    distribution?.target,
    platformTargets[platform],
    `${packageJson.name} declares the wrong Rust target`,
  );
  assert.equal(
    typeof distribution.binary,
    "string",
    `${packageJson.name} must declare orphanode.binary`,
  );
  assert.equal(
    typeof distribution.checksum,
    "string",
    `${packageJson.name} must declare orphanode.checksum`,
  );
  const declaredCandidates = [];
  if (typeof packageJson.bin === "string") {
    declaredCandidates.push(packageJson.bin);
  } else if (packageJson.bin && typeof packageJson.bin.orphanode === "string") {
    declaredCandidates.push(packageJson.bin.orphanode);
  }
  if (typeof packageJson.main === "string") {
    declaredCandidates.push(packageJson.main);
  }
  declaredCandidates.push(distribution.binary);
  if (Array.isArray(packageJson.files)) {
    declaredCandidates.push(
      ...packageJson.files.filter(
        (candidate) => typeof candidate === "string" && path.basename(candidate) === executableName,
      ),
    );
  }
  const selected = declaredCandidates.find(
    (candidate) => path.basename(candidate) === executableName,
  );
  assert(
    selected,
    `${packageJson.name} must declare the packaged ${executableName} in bin, main, or files`,
  );
  assert(
    path.basename(distribution.checksum).startsWith(executableName),
    `${packageJson.name} checksum must describe ${executableName}`,
  );
  if (Array.isArray(packageJson.files)) {
    assert(
      packageJson.files.some(
        (candidate) =>
          candidate === selected ||
          selected.startsWith(`${candidate.replace(/\/$/, "")}/`) ||
          candidate === path.dirname(selected),
      ),
      `${packageJson.name} files must include ${selected}`,
    );
    assert(
      packageJson.files.some(
        (candidate) =>
          candidate === distribution.checksum ||
          distribution.checksum.startsWith(`${candidate.replace(/\/$/, "")}/`) ||
          candidate === path.dirname(distribution.checksum),
      ),
      `${packageJson.name} files must include ${distribution.checksum}`,
    );
  }
  assert.equal(selected, distribution.binary, `${packageJson.name} has conflicting binary paths`);
  return distribution;
}

async function copyPackage(source, destination) {
  try {
    await cp(source, destination, { recursive: true });
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new Error(`required npm package directory is missing: ${source}`);
    }
    throw error;
  }
}

async function npmPack(source, output) {
  await mkdir(output, { recursive: true });
  const result = runNpm(
    ["pack", source, "--json", "--pack-destination", output, "--ignore-scripts"],
    repositoryRoot,
  );
  let metadata;
  try {
    metadata = JSON.parse(result.stdout);
  } catch {
    throw new Error(`npm pack did not return JSON: ${result.stdout}`);
  }
  assert.equal(metadata.length, 1, "npm pack returned unexpected metadata");
  const tarball = path.resolve(output, metadata[0].filename);
  await readFile(tarball);
  return tarball;
}

function runNpm(argumentsList, cwd) {
  const executable = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(executable, argumentsList, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, npm_config_cache: npmCache },
    shell: process.platform === "win32",
  });
  if (result.status !== 0) {
    throw new Error(
      `npm ${argumentsList[0]} failed: ${result.stderr || result.stdout || result.error || "no details"}`,
    );
  }
  return result;
}

async function writeChecksum(file) {
  const contents = await readFile(file);
  const digest = createHash("sha256").update(contents).digest("hex");
  await writeFile(`${file}.sha256`, `${digest}  ${path.basename(file)}\n`);
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new Error(`required package metadata is missing: ${file}`);
    }
    throw error;
  }
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function requireOptions(...names) {
  for (const name of names) {
    assert(options[name], `missing required option ${name}`);
  }
}

function verifyVersion(actual, expected, packageName) {
  assert.match(actual, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, `${packageName} version is invalid`);
  if (expected) {
    assert.equal(actual, expected, `${packageName} version does not match the release tag`);
  }
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}
