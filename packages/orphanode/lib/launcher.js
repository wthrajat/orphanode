"use strict";

const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const {
  accessSync,
  constants,
  lstatSync,
  readFileSync,
} = require("node:fs");
const path = require("node:path");

const launcherManifest = require("../package.json");

const targets = Object.freeze({
  "darwin:arm64": Object.freeze({
    binary: "bin/orphanode",
    checksum: "bin/orphanode.sha256",
    nodeArch: "arm64",
    nodePlatform: "darwin",
    packageName: "@orphanode/darwin-arm64",
    rustTarget: "aarch64-apple-darwin",
  }),
  "darwin:x64": Object.freeze({
    binary: "bin/orphanode",
    checksum: "bin/orphanode.sha256",
    nodeArch: "x64",
    nodePlatform: "darwin",
    packageName: "@orphanode/darwin-x64",
    rustTarget: "x86_64-apple-darwin",
  }),
  "linux:x64:glibc": Object.freeze({
    binary: "bin/orphanode",
    checksum: "bin/orphanode.sha256",
    libc: "glibc",
    nodeArch: "x64",
    nodePlatform: "linux",
    packageName: "@orphanode/linux-x64-gnu",
    rustTarget: "x86_64-unknown-linux-gnu",
  }),
  "win32:x64": Object.freeze({
    binary: "bin/orphanode.exe",
    checksum: "bin/orphanode.exe.sha256",
    nodeArch: "x64",
    nodePlatform: "win32",
    packageName: "@orphanode/win32-x64-msvc",
    rustTarget: "x86_64-pc-windows-msvc",
  }),
});

const supportedTargets = Object.freeze(
  Object.values(targets).map((target) => target.rustTarget),
);

class LauncherError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = "LauncherError";
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

function detectLinuxLibc(reportProvider = defaultReportProvider) {
  let report;
  try {
    report = reportProvider();
  } catch {
    return "unknown";
  }

  if (report?.header?.glibcVersionRuntime) {
    return "glibc";
  }

  const sharedObjects = Array.isArray(report?.sharedObjects)
    ? report.sharedObjects
    : [];
  if (sharedObjects.some((entry) => /(?:^|[/\\])(?:ld-)?musl/i.test(entry))) {
    return "musl";
  }

  return "unknown";
}

function defaultReportProvider() {
  if (!process.report || typeof process.report.getReport !== "function") {
    return undefined;
  }
  return process.report.getReport();
}

function selectTarget(runtime = {}) {
  const nodePlatform = runtime.platform ?? process.platform;
  const nodeArch = runtime.arch ?? process.arch;
  const libc =
    nodePlatform === "linux"
      ? runtime.libc ?? detectLinuxLibc(runtime.reportProvider)
      : undefined;
  const key =
    nodePlatform === "linux"
      ? `${nodePlatform}:${nodeArch}:${libc}`
      : `${nodePlatform}:${nodeArch}`;
  const target = targets[key];

  if (!target) {
    const libcDetail = nodePlatform === "linux" ? `, libc=${libc}` : "";
    throw new LauncherError(
      "ORPHANODE_UNSUPPORTED_PLATFORM",
      `No OrphaNode native binary is published for platform=${nodePlatform}, ` +
        `arch=${nodeArch}${libcDetail}. Supported targets: ` +
        `${supportedTargets.join(", ")}.`,
    );
  }

  return target;
}

function resolveBinary(options = {}) {
  const target = options.target ?? selectTarget(options.runtime);
  const resolvePackageJson = options.resolvePackageJson ?? require.resolve;
  const packageJsonSpecifier = `${target.packageName}/package.json`;
  let packageJsonPath;

  try {
    packageJsonPath = resolvePackageJson(packageJsonSpecifier);
  } catch (cause) {
    throw new LauncherError(
      "ORPHANODE_PLATFORM_PACKAGE_MISSING",
      `The required native package ${target.packageName}@${launcherManifest.version} ` +
        "is not installed. Reinstall orphanode with optional dependencies enabled " +
        "and do not use --omit=optional.",
      cause,
    );
  }

  const platformManifest = readPlatformManifest(packageJsonPath, target);
  validatePlatformManifest(platformManifest, target);

  const packageRoot = path.dirname(packageJsonPath);
  const binaryPath = resolvePackageFile(packageRoot, target.binary, target);
  const checksumPath = resolvePackageFile(packageRoot, target.checksum, target);
  verifyBinary(binaryPath, checksumPath, target);

  return binaryPath;
}

function readPlatformManifest(packageJsonPath, target) {
  try {
    return JSON.parse(readFileSync(packageJsonPath, "utf8"));
  } catch (cause) {
    throw damagedPackageError(
      target,
      `cannot read its package manifest at ${packageJsonPath}`,
      cause,
    );
  }
}

function validatePlatformManifest(manifest, target) {
  if (manifest.name !== target.packageName) {
    throw damagedPackageError(target, "its package name does not match");
  }
  if (manifest.version !== launcherManifest.version) {
    throw damagedPackageError(
      target,
      `version ${manifest.version ?? "unknown"} does not match launcher version ` +
        launcherManifest.version,
    );
  }

  const distribution = manifest.orphanode;
  if (
    distribution?.target !== target.rustTarget ||
    distribution?.binary !== target.binary ||
    distribution?.checksum !== target.checksum
  ) {
    throw damagedPackageError(target, "its binary metadata does not match");
  }
}

function resolvePackageFile(packageRoot, relativePath, target) {
  const resolvedPath = path.resolve(packageRoot, relativePath);
  const pathFromRoot = path.relative(packageRoot, resolvedPath);
  if (
    pathFromRoot === ".." ||
    pathFromRoot.startsWith(`..${path.sep}`) ||
    path.isAbsolute(pathFromRoot)
  ) {
    throw damagedPackageError(target, "its binary metadata escapes the package");
  }
  return resolvedPath;
}

function verifyBinary(binaryPath, checksumPath, target) {
  assertRegularFile(binaryPath, "binary", target);
  assertRegularFile(checksumPath, "checksum", target);

  let checksumSource;
  let binary;
  try {
    checksumSource = readFileSync(checksumPath, "utf8");
    binary = readFileSync(binaryPath);
  } catch (cause) {
    throw damagedPackageError(target, "its binary or checksum cannot be read", cause);
  }

  const expectedChecksum = parseChecksum(
    checksumSource,
    path.basename(binaryPath),
    target,
  );
  const actualChecksum = createHash("sha256").update(binary).digest("hex");
  if (actualChecksum !== expectedChecksum) {
    throw damagedPackageError(
      target,
      `SHA-256 mismatch for ${path.basename(binaryPath)}`,
    );
  }

  if (target.nodePlatform !== "win32") {
    try {
      accessSync(binaryPath, constants.X_OK);
    } catch (cause) {
      throw damagedPackageError(target, "its native binary is not executable", cause);
    }
  }
}

function assertRegularFile(filePath, label, target) {
  try {
    if (!lstatSync(filePath).isFile()) {
      throw new Error("not a regular file");
    }
  } catch (cause) {
    throw damagedPackageError(
      target,
      `its ${label} file is missing or is not a regular file`,
      cause,
    );
  }
}

function parseChecksum(source, expectedFileName, target) {
  const lines = source.trim().split(/\r?\n/);
  const match =
    lines.length === 1
      ? /^([a-fA-F0-9]{64})(?:[ \t]+\*?(.+?))?$/.exec(lines[0])
      : null;
  if (!match) {
    throw damagedPackageError(target, "its SHA-256 file has an invalid format");
  }

  const checksumFileName = match[2];
  if (checksumFileName && checksumFileName !== expectedFileName) {
    throw damagedPackageError(
      target,
      `its SHA-256 file names ${checksumFileName}, expected ${expectedFileName}`,
    );
  }

  return match[1].toLowerCase();
}

function damagedPackageError(target, detail, cause) {
  return new LauncherError(
    "ORPHANODE_BINARY_DAMAGED",
    `The installed ${target.packageName} package is damaged: ${detail}. ` +
      "Remove and reinstall orphanode; the binary was not executed.",
    cause,
  );
}

function run(argumentsToForward, options = {}) {
  const binaryPath = resolveBinary(options);
  const spawn = options.spawnSync ?? spawnSync;
  const environment = workerEnvironment(options.env ?? process.env, options.resolveModule);
  const result = spawn(binaryPath, argumentsToForward, {
    cwd: options.cwd,
    encoding: options.encoding,
    env: environment,
    stdio: options.stdio ?? "inherit",
    windowsHide: true,
  });

  if (result.error) {
    throw new LauncherError(
      "ORPHANODE_BINARY_START_FAILED",
      `The verified native binary could not be started: ${result.error.message}`,
      result.error,
    );
  }
  if (result.status === null && !result.signal) {
    throw new LauncherError(
      "ORPHANODE_BINARY_START_FAILED",
      "The verified native binary stopped without an exit status or signal.",
    );
  }

  return result;
}

function workerEnvironment(environment, resolveModule = require.resolve) {
  if (environment.ORPHANODE_TYPESCRIPT_WORKER) {
    return environment;
  }
  try {
    return {
      ...environment,
      ORPHANODE_TYPESCRIPT_WORKER: resolveModule(
        "@orphanode/typescript-worker/worker",
      ),
    };
  } catch {
    return environment;
  }
}

module.exports = {
  LauncherError,
  detectLinuxLibc,
  resolveBinary,
  run,
  selectTarget,
  targets,
  verifyBinary,
  workerEnvironment,
};
