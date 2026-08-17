#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { spawnSync } from "node:child_process";

const MAX_CAPTURED_OUTPUT_BYTES = 64 * 1024 * 1024;

const options = parseArguments(process.argv.slice(2));
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const budget = JSON.parse(
  await readFile(path.join(repositoryRoot, "benchmarks", "budget.json"), "utf8"),
);
const runner =
  process.env.ORPHANODE_BENCHMARK_RUNNER ?? `${process.platform}-${process.arch}`;
validateBudget(budget, runner);

const corpusRoot = await mkdtemp(path.join(os.tmpdir(), "orphanode-benchmark-"));

try {
  const corpus = await createCorpus(corpusRoot, budget.corpus);
  const environment = inspectEnvironment(corpusRoot, runner);
  const cacheRoot = path.join(corpusRoot, ".orphanode", "cache");
  const samples = { cold: [], warm: [], incremental: [] };

  for (let index = 0; index < budget.sampleCounts.cold; index += 1) {
    await rm(cacheRoot, { recursive: true, force: true });
    samples.cold.push(measureScan(`cold-${index}`, "cold"));
  }

  for (let index = 0; index < budget.sampleCounts.warm; index += 1) {
    samples.warm.push(measureScan(`warm-${index}`, "warm"));
  }

  const changedPath = path.join(corpusRoot, budget.corpus.incrementalFile);
  for (let index = 0; index < budget.sampleCounts.incremental; index += 1) {
    await writeFile(
      changedPath,
      sourceForFile(budget.corpus.fileCount - 1, budget.corpus, index + 1),
    );
    samples.incremental.push(
      measureScan(`incremental-${index}`, "incremental"),
    );
  }

  const measurements = Object.fromEntries(
    Object.entries(samples).map(([phase, phaseSamples]) => [
      phase,
      summarizeSamples(phaseSamples, corpus.lineCount),
    ]),
  );
  const measuredPeakRssMiB = peakRss(samples);
  const regression = normalizedRegression(measurements, budget);
  const gates = evaluateGates(measurements, measuredPeakRssMiB, regression, budget);
  const tool = inspectTool(options.binary);
  if (process.env.CI) {
    assert.notEqual(environment.filesystem, "unavailable");
    assert.notEqual(tool.revision, "unavailable");
  }
  const result = {
    schemaVersion: 2,
    environment,
    tool,
    corpus,
    measurements,
    peakRssMiB: measuredPeakRssMiB,
    budgets: budget.absoluteBudgets,
    normalizedRegression: regression,
    gates,
  };

  await mkdir(path.dirname(path.resolve(options.output)), { recursive: true });
  await writeFile(
    path.resolve(options.output),
    `${JSON.stringify(result, null, 2)}\n`,
  );
  console.log(JSON.stringify(result, null, 2));
  enforceGates(gates, measurements, measuredPeakRssMiB, regression, budget);

  function measureScan(label, phase) {
    const rssPath = path.join(corpusRoot, `.peak-rss-${label}.txt`);
    const measureMemory =
      process.platform === "linux" && existsSync("/usr/bin/time");
    const scanArguments = [
      "scan",
      "--root",
      corpusRoot,
      "--target",
      "node",
      "--format",
      "json",
    ];
    const command = measureMemory ? "/usr/bin/time" : options.binary;
    const commandArguments = measureMemory
      ? ["-f", "%M", "-o", rssPath, options.binary, ...scanArguments]
      : scanArguments;
    const startedAt = performance.now();
    const scan = spawnSync(command, commandArguments, {
      encoding: "utf8",
      maxBuffer: MAX_CAPTURED_OUTPUT_BYTES,
    });
    const wallTimeMs = performance.now() - startedAt;

    if (scan.error) {
      throw scan.error;
    }
    assert.equal(
      scan.status,
      budget.expectations.exitCode,
      `benchmark ${phase} scan exited ${scan.status}: ${scan.stderr || "no details"}`,
    );
    assert(scan.stdout.trim().length > 0, `${phase} scan produced no JSON report`);
    const report = JSON.parse(scan.stdout);
    validateReport(report, phase, budget);

    let peakRssMiB = null;
    if (measureMemory) {
      const peakRssKiB = Number.parseInt(readFileSync(rssPath, "utf8").trim(), 10);
      unlinkSync(rssPath);
      assert(Number.isFinite(peakRssKiB), "GNU time did not report peak RSS");
      peakRssMiB = peakRssKiB / 1024;
    }

    return {
      label,
      wallTimeMs,
      peakRssMiB,
      filesPerSecond: perSecond(corpus.fileCount, wallTimeMs),
      linesPerSecond: perSecond(corpus.lineCount, wallTimeMs),
      cache: {
        status: report.cache.status,
        hits: report.cache.hits,
        misses: report.cache.misses,
        generationWritten: report.cache.generationWritten,
      },
    };
  }
} finally {
  await rm(corpusRoot, { recursive: true, force: true });
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    values.set(argumentsList[index], argumentsList[index + 1]);
  }
  const binary = values.get("--binary");
  const output = values.get("--output");
  if (!binary || !output) {
    throw new Error("usage: benchmark.mjs --binary PATH --output FILE");
  }
  return { binary: path.resolve(binary), output };
}

function validateBudget(configuration, runner) {
  assert.equal(configuration.schemaVersion, 2, "unknown benchmark budget schema");
  assert.equal(
    configuration.corpus.lineCount,
    configuration.corpus.fileCount * configuration.corpus.linesPerFile,
    "corpus dimensions must produce exactly the declared line count",
  );
  assert.equal(
    configuration.corpus.lineCount,
    1_000_000,
    "the release benchmark must contain exactly 1,000,000 source lines",
  );
  for (const [phase, count] of Object.entries(configuration.sampleCounts)) {
    assert(
      Number.isInteger(count) && count >= 3 && count % 2 === 1,
      `${phase} must use an odd sample count of at least three`,
    );
  }
  assert.equal(configuration.expectations.exitCode, 0);
  assert.equal(configuration.expectations.findings, 0);
  assert(configuration.absoluteBudgets.coldMedianMs <= 5_000);
  assert(configuration.absoluteBudgets.warmMedianMs <= 500);
  assert(configuration.absoluteBudgets.incrementalMedianMs > 0);
  assert(configuration.absoluteBudgets.peakRssMiBExclusive <= 750);
  assert(configuration.normalizedRegression.maximumPercent <= 10);
  for (const phase of ["cold", "warm", "incremental"]) {
    const reference =
      configuration.normalizedRegression.referenceMedianMsPerMillionLines[phase];
    const regressionLimit =
      reference * (1 + configuration.normalizedRegression.maximumPercent / 100);
    const absoluteLimit = configuration.absoluteBudgets[`${phase}MedianMs`];
    assert(
      regressionLimit <= absoluteLimit,
      `${phase} regression limit must not exceed its absolute budget`,
    );
  }
  if (process.env.CI) {
    assert.equal(runner, configuration.runner, "benchmark runner is not pinned");
    assert.equal(
      process.version,
      `v${configuration.node}`,
      "Node.js does not match the pinned benchmark version",
    );
    assert.equal(process.platform, "linux", "performance budgets require Linux");
    assert.equal(process.arch, "x64", "performance budgets require x64");
  }
}

async function createCorpus(root, corpus) {
  assert.equal(corpus.version, "synthetic-million-line-chain-v2");
  assert.equal(
    corpus.incrementalFile,
    sourcePath(corpus.fileCount - 1),
    "incremental file must be the final leaf in the import chain",
  );
  const sourceRoot = path.join(root, "src");
  await mkdir(sourceRoot, { recursive: true });
  const hash = createHash("sha256");
  let lineCount = 0;

  const packageManifest = {
    name: "@orphanode/benchmark-million-lines",
    private: true,
    type: "module",
    packageManager: "npm@11.5.1",
    scripts: { start: `node ${sourcePath(0)}` },
  };
  const packageText = `${JSON.stringify(packageManifest, null, 2)}\n`;
  await writeFile(path.join(root, "package.json"), packageText);
  hash.update("package.json\0").update(packageText);

  const writeBatchSize = 32;
  for (let start = 0; start < corpus.fileCount; start += writeBatchSize) {
    const writes = [];
    const end = Math.min(start + writeBatchSize, corpus.fileCount);
    for (let index = start; index < end; index += 1) {
      const relativePath = sourcePath(index);
      const source = sourceForFile(index, corpus, 0);
      const sourceLines = countNewlines(source);
      assert.equal(sourceLines, corpus.linesPerFile);
      lineCount += sourceLines;
      hash.update(relativePath).update("\0").update(source);
      writes.push(writeFile(path.join(root, relativePath), source));
    }
    await Promise.all(writes);
  }

  assert.equal(lineCount, corpus.lineCount);
  const corpusSha256 = hash.digest("hex");
  assert.equal(
    corpusSha256,
    corpus.sha256,
    "generated corpus does not match its pinned SHA-256",
  );
  return {
    ...corpus,
    entry: sourcePath(0),
    reachableFiles: corpus.fileCount,
    resolvedImports: corpus.fileCount - 1,
    sha256: corpusSha256,
  };
}

function sourceForFile(index, corpus, mutation) {
  const isLeaf = index + 1 === corpus.fileCount;
  const firstLine = isLeaf
    ? `void ${mutation};`
    : `import "./${path.basename(sourcePath(index + 1))}";`;
  return `${firstLine}\n${"void 0;\n".repeat(corpus.linesPerFile - 1)}`;
}

function sourcePath(index) {
  return `src/reachable-${String(index).padStart(4, "0")}.js`;
}

function validateReport(report, phase, configuration) {
  const { corpus, expectations } = configuration;
  assert.equal(report.schemaVersion, expectations.reportSchemaVersion);
  assert.equal(report.status, "complete", `${phase} analysis must be complete`);
  assert.deepEqual(report.entries, [sourcePath(0)]);
  assert.deepEqual(report.summary, {
    files: corpus.fileCount,
    reachableFiles: corpus.fileCount,
    unreachableFiles: 0,
    incompleteFiles: 0,
    diagnostics: 0,
  });
  assert.equal(report.files.length, corpus.fileCount);
  assert.equal(report.findings.length, expectations.findings);
  assert.equal(report.diagnostics.length, 0);
  assert.equal(report.project?.mode, "balanced");
  assert.deepEqual(report.project?.targetProfiles, ["node"]);
  for (const [index, file] of report.files.entries()) {
    assert.equal(file.path, sourcePath(index));
    assert.equal(file.status, "reachable");
    assert.equal(file.sourceKind, "java_script");
    assert.equal(file.moduleKind, "esm");
    assert.equal(file.lineCount, corpus.linesPerFile);
    if (index + 1 === corpus.fileCount) {
      assert.equal(file.imports.length, 0);
    } else {
      assert.equal(file.imports.length, 1);
      assert.equal(file.imports[0].status, "resolved");
      assert.equal(file.imports[0].target, sourcePath(index + 1));
    }
  }
  assert.equal(
    report.files.reduce((total, file) => total + file.lineCount, 0),
    corpus.lineCount,
  );
  assert(report.cache, `${phase} report must expose persistent-cache evidence`);

  const expectedCache = {
    cold: {
      status: "empty",
      hits: 0,
      misses: corpus.fileCount,
      generationWritten: true,
    },
    warm: {
      status: "active",
      hits: corpus.fileCount,
      misses: 0,
      generationWritten: false,
    },
    incremental: {
      status: "active",
      hits: corpus.fileCount - 1,
      misses: 1,
      generationWritten: true,
    },
  }[phase];
  assert.deepEqual(report.cache, expectedCache);
}

function summarizeSamples(samples, lineCount) {
  const wallTimes = samples.map((sample) => sample.wallTimeMs);
  const medianWallTimeMs = median(wallTimes);
  return {
    sampleCount: samples.length,
    medianWallTimeMs,
    medianAbsoluteDeviationMs: medianAbsoluteDeviation(wallTimes),
    medianFilesPerSecond: median(
      samples.map((sample) => sample.filesPerSecond),
    ),
    medianLinesPerSecond: median(
      samples.map((sample) => sample.linesPerSecond),
    ),
    normalizedMedianMsPerMillionLines:
      medianWallTimeMs * (1_000_000 / lineCount),
    samples,
  };
}

function normalizedRegression(measurements, configuration) {
  const baseline = configuration.normalizedRegression;
  const phases = {};
  for (const phase of ["cold", "warm", "incremental"]) {
    const measured = measurements[phase].normalizedMedianMsPerMillionLines;
    const reference = baseline.referenceMedianMsPerMillionLines[phase];
    const percent = ((measured - reference) / reference) * 100;
    phases[phase] = {
      measuredMsPerMillionLines: measured,
      referenceMsPerMillionLines: reference,
      percent,
      maximumPercent: baseline.maximumPercent,
      passed: percent <= baseline.maximumPercent,
    };
  }
  return {
    reference: baseline.reference,
    normalization: "median wall time scaled to 1,000,000 source lines",
    phases,
  };
}

function evaluateGates(measurements, measuredPeakRssMiB, regression, configuration) {
  const budgets = configuration.absoluteBudgets;
  return {
    coldMedian: measurements.cold.medianWallTimeMs <= budgets.coldMedianMs,
    warmMedian: measurements.warm.medianWallTimeMs <= budgets.warmMedianMs,
    incrementalMedian:
      measurements.incremental.medianWallTimeMs <= budgets.incrementalMedianMs,
    peakRss:
      measuredPeakRssMiB === null
        ? null
        : measuredPeakRssMiB < budgets.peakRssMiBExclusive,
    normalizedRegression: Object.values(regression.phases).every(
      (phase) => phase.passed,
    ),
  };
}

function enforceGates(
  gates,
  measurements,
  measuredPeakRssMiB,
  regression,
  configuration,
) {
  const budgets = configuration.absoluteBudgets;
  assert(
    gates.coldMedian,
    `cold median ${measurements.cold.medianWallTimeMs}ms exceeded ${budgets.coldMedianMs}ms`,
  );
  assert(
    gates.warmMedian,
    `warm median ${measurements.warm.medianWallTimeMs}ms exceeded ${budgets.warmMedianMs}ms`,
  );
  assert(
    gates.incrementalMedian,
    `incremental median ${measurements.incremental.medianWallTimeMs}ms exceeded ${budgets.incrementalMedianMs}ms`,
  );
  if (process.env.CI) {
    assert.notEqual(measuredPeakRssMiB, null, "CI must measure peak RSS");
  }
  if (measuredPeakRssMiB !== null) {
    assert(
      gates.peakRss,
      `peak RSS ${measuredPeakRssMiB}MiB must remain below ${budgets.peakRssMiBExclusive}MiB`,
    );
  }
  for (const [phase, result] of Object.entries(regression.phases)) {
    assert(
      result.passed,
      `${phase} normalized regression ${result.percent}% exceeded ${result.maximumPercent}%`,
    );
  }
}

function inspectEnvironment(root, runner) {
  const cpus = os.cpus();
  return {
    runner,
    ci: Boolean(process.env.CI),
    node: process.version,
    os: {
      platform: process.platform,
      release: os.release(),
      version: os.version(),
      architecture: process.arch,
    },
    hardware: {
      cpuModel: cpus[0]?.model ?? "unavailable",
      logicalCpuCount: cpus.length,
      totalMemoryMiB: Math.round(os.totalmem() / 1024 / 1024),
    },
    filesystem: filesystemType(root),
  };
}

function inspectTool(binary) {
  const version = spawnSync(binary, ["--version"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(version.status, 0, `cannot read tool version: ${version.stderr}`);
  const binaryContents = readFileSync(binary);
  return {
    version: version.stdout.trim(),
    revision:
      process.env.ORPHANODE_BENCHMARK_TOOL_REVISION ??
      process.env.GITHUB_SHA ??
      gitRevision() ??
      "unavailable",
    binarySha256: createHash("sha256").update(binaryContents).digest("hex"),
    binaryBytes: binaryContents.byteLength,
  };
}

function gitRevision() {
  const revision = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  return revision.status === 0 ? revision.stdout.trim() : null;
}

function filesystemType(root) {
  if (process.platform === "linux") {
    const result = spawnSync("stat", ["-f", "-c", "%T", root], {
      encoding: "utf8",
    });
    if (result.status === 0) {
      return result.stdout.trim();
    }
  }
  if (process.platform === "darwin") {
    const disk = spawnSync("df", ["-P", root], { encoding: "utf8" });
    const device = disk.stdout.trim().split("\n").at(-1)?.split(/\s+/)[0];
    const mounts = spawnSync("mount", [], { encoding: "utf8" });
    const mountLine = mounts.stdout
      .split("\n")
      .find((line) => device && line.startsWith(`${device} on `));
    const filesystem = mountLine?.match(/\(([^,\s]+)/)?.[1];
    if (filesystem) {
      return filesystem;
    }
  }
  return "unavailable";
}

function peakRss(sampleGroups) {
  const measurements = Object.values(sampleGroups)
    .flat()
    .map((sample) => sample.peakRssMiB)
    .filter((value) => value !== null);
  return measurements.length === 0 ? null : Math.max(...measurements);
}

function countNewlines(value) {
  let count = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) === 10) {
      count += 1;
    }
  }
  return count;
}

function perSecond(count, wallTimeMs) {
  return count / (wallTimeMs / 1000);
}

function medianAbsoluteDeviation(values) {
  const center = median(values);
  return median(values.map((value) => Math.abs(value - center)));
}

function median(values) {
  assert(values.length > 0, "cannot take the median of an empty sample");
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}
