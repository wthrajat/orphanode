"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const {
  appendFileSync,
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { selectTarget, targets } = require("../lib/launcher.js");

const packageRoot = path.resolve(__dirname, "..");
const platformsRoot = path.resolve(packageRoot, "..", "platforms");
const workerRoot = path.resolve(packageRoot, "..", "typescript-worker");
const expectedLauncherFiles = [
  "LICENSE-APACHE",
  "LICENSE-MIT",
  "README.md",
  "bin/orphanode.js",
  "lib/launcher.js",
  "package.json",
];
const expectedPlatformStaticFiles = [
  "LICENSE-APACHE",
  "LICENSE-MIT",
  "README.md",
  "package.json",
];

test("packs and installs every local npm tarball without a registry", (context) => {
  const temporaryDirectory = mkdtempSync(
    path.join(os.tmpdir(), "orphanode-distribution-test-"),
  );
  context.after(() => {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  });

  const tarballDirectory = path.join(temporaryDirectory, "tarballs");
  const stagingDirectory = path.join(temporaryDirectory, "staging");
  const cacheDirectory = path.join(temporaryDirectory, "npm-cache");
  mkdirSync(tarballDirectory, { recursive: true });
  mkdirSync(stagingDirectory, { recursive: true });

  const packageTarballs = new Map();
  const workerDryRun = npmPack(
    workerRoot,
    tarballDirectory,
    cacheDirectory,
    true,
  );
  assert.deepEqual(packageFileNames(workerDryRun), [
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "package.json",
    "src/protocol.mjs",
    "src/service.mjs",
    "src/typescript-oracle.mjs",
    "src/worker.mjs",
  ]);
  const workerPack = npmPack(
    workerRoot,
    tarballDirectory,
    cacheDirectory,
    false,
  );
  packageTarballs.set("@orphanode/typescript-worker", workerPack.tarballPath);
  const launcherDryRun = npmPack(
    packageRoot,
    tarballDirectory,
    cacheDirectory,
    true,
  );
  assert.deepEqual(packageFileNames(launcherDryRun), expectedLauncherFiles);
  const launcherPack = npmPack(
    packageRoot,
    tarballDirectory,
    cacheDirectory,
    false,
  );
  packageTarballs.set("orphanode", launcherPack.tarballPath);

  for (const target of uniqueTargets()) {
    const packageDirectory = stagePlatformPackage(
      stagingDirectory,
      target,
      currentTargetPackageName() === target.packageName,
    );
    const dryRun = npmPack(
      packageDirectory,
      tarballDirectory,
      cacheDirectory,
      true,
    );
    assert.deepEqual(packageFileNames(dryRun), [
      ...expectedPlatformStaticFiles,
      target.binary,
      target.checksum,
    ].sort());
    const packed = npmPack(
      packageDirectory,
      tarballDirectory,
      cacheDirectory,
      false,
    );
    packageTarballs.set(target.packageName, packed.tarballPath);
  }

  const consumerDirectory = path.join(temporaryDirectory, "consumer");
  mkdirSync(consumerDirectory, { recursive: true });
  const dependencies = Object.fromEntries(
    [...packageTarballs].map(([packageName, tarballPath]) => [
      packageName,
      `file:${tarballPath}`,
    ]),
  );
  writeFileSync(
    path.join(consumerDirectory, "package.json"),
    `${JSON.stringify({ name: "orphanode-local-consumer", private: true, dependencies }, null, 2)}\n`,
  );

  runNpm(
    [
      "install",
      "--force",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      "--offline",
    ],
    consumerDirectory,
    cacheDirectory,
  );

  for (const packageName of packageTarballs.keys()) {
    assert.equal(
      existsSync(path.join(consumerDirectory, "node_modules", packageName)),
      true,
      `${packageName} should be installed from its local tarball`,
    );
  }

  const selectedTarget = selectTarget();
  const commandPath = path.join(
    consumerDirectory,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "orphanode.cmd" : "orphanode",
  );
  const firstRun = spawnSync(commandPath, ["--version"], {
    cwd: consumerDirectory,
    encoding: "utf8",
    env: process.env,
    windowsHide: true,
  });
  assert.equal(firstRun.status, 0, firstRun.stderr);
  if (process.platform === "win32") {
    assert.match(firstRun.stdout, new RegExp(escapeRegex(process.version)));
  } else {
    assert.equal(firstRun.stdout, "fake orphanode: --version\n");
  }

  const installedBinaryPath = path.join(
    consumerDirectory,
    "node_modules",
    selectedTarget.packageName,
    selectedTarget.binary,
  );
  appendFileSync(installedBinaryPath, "damaged after install\n");
  const damagedRun = spawnSync(commandPath, ["--version"], {
    cwd: consumerDirectory,
    encoding: "utf8",
    env: process.env,
    windowsHide: true,
  });
  assert.equal(damagedRun.status, 1);
  assert.match(damagedRun.stderr, /SHA-256 mismatch/);
  assert.match(damagedRun.stderr, /was not executed/);
});

function uniqueTargets() {
  return [
    ...new Map(
      Object.values(targets).map((target) => [target.packageName, target]),
    ).values(),
  ];
}

function currentTargetPackageName() {
  try {
    return selectTarget().packageName;
  } catch {
    return undefined;
  }
}

function stagePlatformPackage(stagingRoot, target, shouldExecute) {
  const packageShortName = target.packageName.slice("@orphanode/".length);
  const sourceDirectory = path.join(platformsRoot, packageShortName);
  const packageDirectory = path.join(stagingRoot, packageShortName);
  cpSync(sourceDirectory, packageDirectory, { recursive: true });

  const binaryPath = path.join(packageDirectory, target.binary);
  mkdirSync(path.dirname(binaryPath), { recursive: true });
  if (process.platform === "win32" && shouldExecute) {
    copyFileSync(process.execPath, binaryPath);
  } else if (shouldExecute) {
    writeFileSync(
      binaryPath,
      "#!/usr/bin/env node\nprocess.stdout.write(`fake orphanode: ${process.argv.slice(2).join(\" \")}\\n`);\n",
    );
  } else {
    writeFileSync(binaryPath, `fake binary for ${target.rustTarget}\n`);
  }
  chmodSync(binaryPath, 0o755);

  const binary = readFileSync(binaryPath);
  const checksum = createHash("sha256").update(binary).digest("hex");
  const checksumPath = path.join(packageDirectory, target.checksum);
  writeFileSync(checksumPath, `${checksum}  ${path.basename(binaryPath)}\n`);
  return packageDirectory;
}

function npmPack(packageDirectory, tarballDirectory, cacheDirectory, dryRun) {
  const argumentsToNpm = ["pack", "--json", "--ignore-scripts"];
  if (dryRun) {
    argumentsToNpm.push("--dry-run");
  } else {
    argumentsToNpm.push("--pack-destination", tarballDirectory);
  }
  const output = runNpm(argumentsToNpm, packageDirectory, cacheDirectory);
  const entries = JSON.parse(output);
  assert.equal(entries.length, 1);
  const entry = entries[0];
  return {
    entry,
    tarballPath: dryRun
      ? undefined
      : path.join(tarballDirectory, entry.filename),
  };
}

function packageFileNames(packResult) {
  return packResult.entry.files.map((file) => file.path).sort();
}

function runNpm(argumentsToNpm, cwd, cacheDirectory) {
  assert.ok(process.env.npm_execpath, "run tests through npm so npm_execpath is set");
  const result = spawnSync(
    process.execPath,
    [process.env.npm_execpath, ...argumentsToNpm],
    {
      cwd,
      encoding: "utf8",
      env: {
        ...process.env,
        ...(cacheDirectory ? { npm_config_cache: cacheDirectory } : {}),
      },
      windowsHide: true,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
