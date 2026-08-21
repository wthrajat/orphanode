#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { cp, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const options = parseArguments(process.argv.slice(2));
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const temporaryDirectory = await realpath(
  await mkdtemp(path.join(os.tmpdir(), "orphanode-resolver-")),
);
let fixtureCopyIndex = 0;

try {
  await compareEsmResolution();
  await compareCommonJsResolution();
  await compareReviewedNodeCorpus();
  await compareTypeScriptResolution();
  await compareTypeScriptUnicodeResolution();
  console.log("OrphaNode resolver results match Node.js and TypeScript for the fixture corpus");
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    values.set(argumentsList[index], argumentsList[index + 1]);
  }
  const binary = values.get("--binary");
  const typescript = values.get("--typescript");
  if (!binary || !typescript) {
    throw new Error(
      "usage: resolver-differential.mjs --binary PATH --typescript TYPESCRIPT_JS",
    );
  }
  return { binary: path.resolve(binary), typescript: path.resolve(typescript) };
}

async function copiedFixture(name) {
  const source = path.join(repositoryRoot, "fixtures", name);
  const destination = path.join(temporaryDirectory, `${name}-${fixtureCopyIndex}`);
  fixtureCopyIndex += 1;
  await cp(source, destination, { recursive: true, verbatimSymlinks: true });
  return destination;
}

function scan(root) {
  const result = spawnSync(
    options.binary,
    ["scan", "--root", root, "--files-from", "files.json", "--format", "json"],
    { encoding: "utf8" },
  );
  if (![0, 1, 2].includes(result.status)) {
    throw new Error(`scan failed: ${result.stderr || result.error || result.status}`);
  }
  return JSON.parse(result.stdout);
}

function orphanodeTarget(report, sourcePath, specifier) {
  const file = report.files.find((candidate) => candidate.path === sourcePath);
  assert(file, `report omitted ${sourcePath}`);
  const imported = file.imports.find((candidate) => candidate.specifier === specifier);
  assert(imported, `report omitted ${specifier} from ${sourcePath}`);
  assert.equal(imported.status, "resolved", `${specifier} was not resolved`);
  assert(imported.target, `${specifier} has no target`);
  return imported.target;
}

function projectRelative(root, absolutePath) {
  return path.relative(root, absolutePath).split(path.sep).join("/");
}

async function compareEsmResolution() {
  const root = await copiedFixture("esm");
  const resolverPath = path.join(root, "src", ".orphanode-resolver.mjs");
  await writeFile(
    resolverPath,
    "process.stdout.write(import.meta.resolve('./message.js'));\n",
  );
  const nodeResult = spawnSync(process.execPath, [resolverPath], { encoding: "utf8" });
  assert.equal(nodeResult.status, 0, nodeResult.stderr);
  const expected = projectRelative(root, fileURLToPath(nodeResult.stdout.trim()));
  const actual = orphanodeTarget(scan(root), "src/index.js", "./message.js");
  assert.equal(actual, expected, "ESM resolution differs from Node.js");
}

async function compareCommonJsResolution() {
  const root = await copiedFixture("commonjs");
  const importer = path.join(root, "src", "index.cjs");
  const expected = projectRelative(
    root,
    createRequire(pathToFileURL(importer)).resolve("./message.cjs"),
  );
  const actual = orphanodeTarget(scan(root), "src/index.cjs", "./message.cjs");
  assert.equal(actual, expected, "CommonJS resolution differs from Node.js");
}

async function compareReviewedNodeCorpus() {
  const expected = JSON.parse(
    await readFile(
      path.join(repositoryRoot, "fixtures", "reference", "node-resolution.expected.json"),
      "utf8",
    ),
  );
  const fixtureRoots = {
    "resolver-package-maps": await copiedFixture("resolver-package-maps"),
    "resolver-path-identity": await copiedFixture("resolver-path-identity"),
  };
  const reports = Object.fromEntries(
    Object.entries(fixtureRoots).map(([name, root]) => [name, scan(root)]),
  );
  const cases = {
    "case-preserving-relative-import": [
      "resolver-path-identity",
      "src/index.mjs",
      "./ExactCase.mjs",
    ],
    "package-imports-import-condition": [
      "resolver-package-maps",
      "src/consumer.mjs",
      "#internal",
    ],
    "package-imports-require-condition": [
      "resolver-package-maps",
      "src/consumer.cjs",
      "#internal",
    ],
    "self-reference-import-condition": [
      "resolver-package-maps",
      "src/consumer.mjs",
      "fixture-resolver/feature",
    ],
    "self-reference-require-condition": [
      "resolver-package-maps",
      "src/consumer.cjs",
      "fixture-resolver/feature",
    ],
    "symlink-default-realpath": [
      "resolver-path-identity",
      "src/index.mjs",
      "./linked.mjs",
    ],
    "unicode-relative-import": [
      "resolver-path-identity",
      "src/index.mjs",
      "./café.mjs",
    ],
  };

  for (const referenceCase of expected.cases) {
    const mapping = cases[referenceCase.id];
    if (!mapping) {
      continue;
    }
    const [fixture, source, specifier] = mapping;
    const expectedPrefix = `${fixture}/`;
    assert(
      referenceCase.resolved?.startsWith(expectedPrefix),
      `Node reference ${referenceCase.id} is not an in-fixture path`,
    );
    const expectedTarget = referenceCase.resolved.slice(expectedPrefix.length);
    const actualTarget = orphanodeTarget(reports[fixture], source, specifier);
    assert.equal(actualTarget, expectedTarget, `${referenceCase.id} differs from Node.js`);
  }
}

async function compareTypeScriptResolution() {
  const root = await copiedFixture("ts-path-alias");
  const typescriptModule = await import(pathToFileURL(options.typescript));
  const typescript = typescriptModule.default ?? typescriptModule;
  const configPath = path.join(root, "tsconfig.json");
  const config = typescript.readConfigFile(configPath, typescript.sys.readFile);
  assert.equal(config.error, undefined, "TypeScript could not read the fixture config");
  const parsed = typescript.parseJsonConfigFileContent(
    config.config,
    typescript.sys,
    root,
    undefined,
    configPath,
  );
  assert.equal(parsed.errors.length, 0, "TypeScript rejected the fixture config");
  const importer = path.join(root, "src", "index.ts");
  const resolution = typescript.resolveModuleName(
    "@/message",
    importer,
    parsed.options,
    typescript.sys,
  ).resolvedModule;
  assert(resolution, "TypeScript did not resolve the path alias");
  const expected = projectRelative(root, resolution.resolvedFileName);
  const actual = orphanodeTarget(scan(root), "src/index.ts", "@/message");
  assert.equal(actual, expected, "path-alias resolution differs from TypeScript");
}

async function compareTypeScriptUnicodeResolution() {
  const root = await copiedFixture("resolver-path-identity");
  const typescriptModule = await import(pathToFileURL(options.typescript));
  const typescript = typescriptModule.default ?? typescriptModule;
  const configPath = path.join(root, "tsconfig.json");
  const config = typescript.readConfigFile(configPath, typescript.sys.readFile);
  assert.equal(config.error, undefined, "TypeScript could not read the path fixture config");
  const parsed = typescript.parseJsonConfigFileContent(
    config.config,
    typescript.sys,
    root,
    undefined,
    configPath,
  );
  assert.equal(parsed.errors.length, 0, "TypeScript rejected the path fixture config");
  const importer = path.join(root, "src", "types.ts");
  const resolution = typescript.resolveModuleName(
    "./café.js",
    importer,
    parsed.options,
    typescript.sys,
  ).resolvedModule;
  assert(resolution, "TypeScript did not resolve Unicode extension substitution");
  const expected = projectRelative(root, resolution.resolvedFileName);
  const actual = orphanodeTarget(scan(root), "src/types.ts", "./café.js");
  assert.equal(actual, expected, "Unicode extension substitution differs from TypeScript");
}
