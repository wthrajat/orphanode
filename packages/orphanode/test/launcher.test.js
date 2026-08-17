"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  LauncherError,
  detectLinuxLibc,
  resolveBinary,
  run,
  selectTarget,
  targets,
  workerEnvironment,
} = require("../lib/launcher.js");

const platformsRoot = path.resolve(__dirname, "..", "..", "platforms");
const temporaryDirectories = [];

test.after(() => {
  for (const temporaryDirectory of temporaryDirectories) {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("selects every published native target explicitly", () => {
  assert.equal(
    selectTarget({ platform: "linux", arch: "x64", libc: "glibc" }).packageName,
    "@orphanode/linux-x64-gnu",
  );
  assert.equal(
    selectTarget({ platform: "darwin", arch: "arm64" }).packageName,
    "@orphanode/darwin-arm64",
  );
  assert.equal(
    selectTarget({ platform: "darwin", arch: "x64" }).packageName,
    "@orphanode/darwin-x64",
  );
  assert.equal(
    selectTarget({ platform: "win32", arch: "x64" }).packageName,
    "@orphanode/win32-x64-msvc",
  );
});

test("keeps launcher and platform package versions and paths aligned", () => {
  const launcherManifest = JSON.parse(
    readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8"),
  );
  const publishedTargets = [
    ...new Map(
      Object.values(targets).map((target) => [target.packageName, target]),
    ).values(),
  ];

  assert.deepEqual(
    Object.keys(launcherManifest.optionalDependencies).sort(),
    publishedTargets.map((target) => target.packageName).sort(),
  );
  for (const target of publishedTargets) {
    assert.equal(
      launcherManifest.optionalDependencies[target.packageName],
      launcherManifest.version,
    );
    const manifestPath = path.join(
      platformsRoot,
      target.packageName.slice("@orphanode/".length),
      "package.json",
    );
    const platformManifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    assert.equal(platformManifest.version, launcherManifest.version);
    assert.deepEqual(platformManifest.orphanode, {
      target: target.rustTarget,
      binary: target.binary,
      checksum: target.checksum,
    });
  }
});

test("rejects unsupported architectures and Linux libc variants", () => {
  for (const runtime of [
    { platform: "linux", arch: "arm64", libc: "glibc" },
    { platform: "linux", arch: "x64", libc: "musl" },
    { platform: "freebsd", arch: "x64" },
  ]) {
    assert.throws(
      () => selectTarget(runtime),
      (error) =>
        error instanceof LauncherError &&
        error.code === "ORPHANODE_UNSUPPORTED_PLATFORM" &&
        error.message.includes(`platform=${runtime.platform}`),
    );
  }
});

test("detects glibc and musl from Node diagnostic reports", () => {
  assert.equal(
    detectLinuxLibc(() => ({ header: { glibcVersionRuntime: "2.39" } })),
    "glibc",
  );
  assert.equal(
    detectLinuxLibc(() => ({ sharedObjects: ["/lib/ld-musl-x86_64.so.1"] })),
    "musl",
  );
  assert.equal(detectLinuxLibc(() => ({})), "unknown");
  assert.equal(
    detectLinuxLibc(() => {
      throw new Error("reports disabled");
    }),
    "unknown",
  );
});

test("reports a missing optional native package", () => {
  const target = selectTarget({ platform: "darwin", arch: "arm64" });
  assert.throws(
    () =>
      resolveBinary({
        target,
        resolvePackageJson() {
          throw new Error("not found");
        },
      }),
    (error) =>
      error.code === "ORPHANODE_PLATFORM_PACKAGE_MISSING" &&
      error.message.includes(target.packageName) &&
      error.message.includes("--omit=optional"),
  );
});

test("verifies a fake packaged binary before forwarding arguments", () => {
  const fixture = createPlatformFixture(
    selectTarget({ platform: "darwin", arch: "x64" }),
  );
  let spawnCall;

  const result = run(["scan", "--root", "fixture"], {
    resolvePackageJson: fixture.resolvePackageJson,
    spawnSync(binaryPath, argumentsToForward, options) {
      spawnCall = { argumentsToForward, binaryPath, options };
      return { signal: null, status: 7 };
    },
    target: fixture.target,
  });

  assert.equal(result.status, 7);
  assert.equal(spawnCall.binaryPath, fixture.binaryPath);
  assert.deepEqual(spawnCall.argumentsToForward, ["scan", "--root", "fixture"]);
  assert.equal(spawnCall.options.stdio, "inherit");
});

test("refuses a fake binary whose contents no longer match its checksum", () => {
  const fixture = createPlatformFixture(
    selectTarget({ platform: "win32", arch: "x64" }),
  );
  writeFileSync(fixture.binaryPath, "changed after packaging\n");

  assert.throws(
    () =>
      resolveBinary({
        resolvePackageJson: fixture.resolvePackageJson,
        target: fixture.target,
      }),
    (error) =>
      error.code === "ORPHANODE_BINARY_DAMAGED" &&
      error.message.includes("SHA-256 mismatch") &&
      error.message.includes("was not executed"),
  );
});

test("refuses a native package with a mismatched version", () => {
  const fixture = createPlatformFixture(
    selectTarget({ platform: "darwin", arch: "arm64" }),
  );
  const manifest = JSON.parse(readFileSync(fixture.packageJsonPath, "utf8"));
  manifest.version = "9.9.9";
  writeFileSync(fixture.packageJsonPath, `${JSON.stringify(manifest, null, 2)}\n`);

  assert.throws(
    () =>
      resolveBinary({
        resolvePackageJson: fixture.resolvePackageJson,
        target: fixture.target,
      }),
    (error) =>
      error.code === "ORPHANODE_BINARY_DAMAGED" &&
      error.message.includes("does not match launcher version 0.1.0"),
  );
});

test("turns native process start failures into a launcher error", () => {
  const fixture = createPlatformFixture(
    selectTarget({ platform: "darwin", arch: "x64" }),
  );

  assert.throws(
    () =>
      run([], {
        resolvePackageJson: fixture.resolvePackageJson,
        spawnSync() {
          return { error: new Error("permission denied"), signal: null, status: null };
        },
        target: fixture.target,
      }),
    (error) =>
      error.code === "ORPHANODE_BINARY_START_FAILED" &&
      error.message.includes("permission denied"),
  );
});

test("passes the installed deep worker to the native process", () => {
  const environment = workerEnvironment(
    { SAFE: "yes" },
    (specifier) => {
      assert.equal(specifier, "@orphanode/typescript-worker/worker");
      return "/installed/orphanode-worker.mjs";
    },
  );

  assert.deepEqual(environment, {
    SAFE: "yes",
    ORPHANODE_TYPESCRIPT_WORKER: "/installed/orphanode-worker.mjs",
  });
});

function createPlatformFixture(target) {
  const temporaryDirectory = mkdtempSync(
    path.join(os.tmpdir(), "orphanode-launcher-test-"),
  );
  temporaryDirectories.push(temporaryDirectory);

  const sourceDirectory = path.join(
    platformsRoot,
    target.packageName.slice("@orphanode/".length),
  );
  const packageDirectory = path.join(temporaryDirectory, "platform-package");
  cpSync(sourceDirectory, packageDirectory, { recursive: true });

  const binaryPath = path.join(packageDirectory, target.binary);
  const checksumPath = path.join(packageDirectory, target.checksum);
  mkdirSync(path.dirname(binaryPath), { recursive: true });
  const fakeBinary = Buffer.from("fake packaged OrphaNode binary\n");
  writeFileSync(binaryPath, fakeBinary);
  chmodSync(binaryPath, 0o755);
  const checksum = createHash("sha256").update(fakeBinary).digest("hex");
  writeFileSync(checksumPath, `${checksum}  ${path.basename(binaryPath)}\n`);

  const packageJsonPath = path.join(packageDirectory, "package.json");
  return {
    binaryPath,
    packageJsonPath,
    resolvePackageJson(specifier) {
      assert.equal(specifier, `${target.packageName}/package.json`);
      return packageJsonPath;
    },
    target,
  };
}
