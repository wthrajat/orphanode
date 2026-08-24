import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  JsonLineDecoder,
  MAX_BATCH_QUERIES,
  PROTOCOL_NAME,
  PROTOCOL_VERSION,
  ProtocolError,
  parseRequestLine,
  protocolDescriptor,
  withRequestTimeout,
} from "../src/protocol.mjs";
import { createWorkerService, dispatchRequest } from "../src/service.mjs";
import { initializeTypeScriptOracle } from "../src/typescript-oracle.mjs";

test("JSON-lines decoder preserves fragmented and coalesced messages", () => {
  const decoder = new JsonLineDecoder(128);

  assert.deepEqual(decoder.push('{"one":'), []);
  const lines = decoder.push('1}\n{"two":2}\r\n');

  assert.deepEqual(
    lines.map((line) => line.toString("utf8")),
    ['{"one":1}', '{"two":2}'],
  );
});

test("JSON-lines decoder rejects an unterminated oversized message", () => {
  const decoder = new JsonLineDecoder(8);

  assert.throws(
    () => decoder.push("123456789"),
    (error) =>
      error instanceof ProtocolError && error.code === "message_too_large",
  );
});

test("request parser enforces the protocol version and timeout ceiling", () => {
  assert.throws(
    () =>
      parseRequestLine(
        Buffer.from(
          JSON.stringify({
            protocol: PROTOCOL_NAME,
            protocolVersion: PROTOCOL_VERSION + 1,
            id: "version",
            method: "capabilities",
          }),
        ),
      ),
    (error) =>
      error instanceof ProtocolError &&
      error.code === "unsupported_protocol_version" &&
      error.requestId === "version",
  );

  assert.throws(
    () =>
      parseRequestLine(
        Buffer.from(
          JSON.stringify({
            protocol: PROTOCOL_NAME,
            protocolVersion: PROTOCOL_VERSION,
            id: "timeout",
            method: "capabilities",
            timeoutMs: 30_001,
          }),
        ),
      ),
    (error) =>
      error instanceof ProtocolError && error.code === "invalid_timeout",
  );
});

test("timeout wrapper reports the cooperative deadline contract", async () => {
  await assert.rejects(
    withRequestTimeout(5, async () => {
      await new Promise((resolve) => setTimeout(resolve, 25));
      return "late";
    }),
    (error) =>
      error instanceof ProtocolError && error.code === "request_timeout",
  );
  assert.equal(
    protocolDescriptor().timeoutContract.hardTimeoutEnforcement,
    "host-must-terminate-worker-process",
  );
});

test("unavailable TypeScript is a capability result, not a worker failure", async () => {
  const service = createWorkerService();
  const initialized = await service.handle(
    request("initialize", { allowProjectTypeScript: false }),
    context(),
  );
  const queried = await service.handle(
    request("query", { queries: [] }),
    context(),
  );

  assert.equal(initialized.status, "unavailable");
  assert.equal(initialized.reason, "project_typescript_not_authorized");
  assert.deepEqual(queried.results, []);
  assert.equal(queried.status, "unavailable");
});

test("ready service returns only injected oracle facts and bounds batches", async () => {
  const oracle = {
    queryBatch(queries) {
      return queries.map((query) => ({
        queryId: query.id,
        status: "resolved",
        receiverCandidates: [],
      }));
    },
  };
  const service = createWorkerService({
    async initializeOracle() {
      return {
        status: "ready",
        typescriptVersion: "test",
        typescriptIdentity: "identity-test",
        configPath: "tsconfig.json",
        oracle,
      };
    },
  });
  const initialized = await service.handle(
    request("initialize", {}),
    context(),
  );
  assert.equal(initialized.typescriptIdentity, "identity-test");

  const result = await service.handle(
    request("query", {
      queries: [{ id: "receiver", kind: "receiverCandidates" }],
    }),
    context(),
  );
  assert.deepEqual(result, {
    status: "resolved",
    results: [
      {
        queryId: "receiver",
        status: "resolved",
        receiverCandidates: [],
      },
    ],
  });

  await assert.rejects(
    service.handle(
      request("query", {
        queries: Array.from({ length: MAX_BATCH_QUERIES + 1 }, (_, id) => ({ id })),
      }),
      context(),
    ),
    (error) => error instanceof ProtocolError && error.code === "batch_too_large",
  );
});

test("deep analysis resolves TypeScript from the configuration owner", async () => {
  const workspaceRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "orphanode-typescript-worker-"),
  );
  try {
    const packageRoot = path.join(workspaceRoot, "packages", "application");
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, "tsconfig.json"), "{}\n");
    writeFakeTypeScript(workspaceRoot, "root-version");
    writeFakeTypeScript(packageRoot, "package-version");

    const initialized = await initializeTypeScriptOracle({
      allowProjectTypeScript: true,
      workspaceRoot,
      typescriptResolutionRoot: packageRoot,
      tsconfigPath: path.join(packageRoot, "tsconfig.json"),
    });

    assert.equal(initialized.status, "ready");
    assert.equal(initialized.typescriptVersion, "package-version");
    assert.match(initialized.typescriptIdentity, /^[a-f0-9]{64}$/u);
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
});

test("deep analysis rejects a TypeScript resolution root outside the workspace", async () => {
  const workspaceRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "orphanode-typescript-workspace-"),
  );
  const outsideRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "orphanode-typescript-outside-"),
  );
  try {
    const initialized = await initializeTypeScriptOracle({
      allowProjectTypeScript: true,
      workspaceRoot,
      typescriptResolutionRoot: outsideRoot,
    });

    assert.equal(initialized.status, "unavailable");
    assert.equal(
      initialized.reason,
      "typescript_resolution_root_outside_workspace",
    );
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
    fs.rmSync(outsideRoot, { recursive: true, force: true });
  }
});

test("dispatch applies the request timeout", async () => {
  const slowService = {
    async handle() {
      await new Promise((resolve) => setTimeout(resolve, 25));
      return { status: "late" };
    },
  };

  await assert.rejects(
    dispatchRequest(slowService, { ...request("capabilities"), timeoutMs: 5 }),
    (error) =>
      error instanceof ProtocolError && error.code === "request_timeout",
  );
});

test("worker process speaks ordered JSON-lines and shuts down cleanly", async () => {
  const workerPath = fileURLToPath(new URL("../src/worker.mjs", import.meta.url));
  const child = spawn(process.execPath, [workerPath], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  child.stdin.end(
    [
      request("capabilities", {}, "capabilities"),
      request(
        "initialize",
        { allowProjectTypeScript: false },
        "initialize",
      ),
      request("shutdown", {}, "shutdown"),
    ]
      .map((message) => JSON.stringify(message))
      .join("\n") + "\n",
  );
  const [exitCode] = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (...args) => resolve(args));
  });
  const responses = stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  assert.equal(exitCode, 0);
  assert.equal(stderr, "");
  assert.deepEqual(
    responses.map((response) => response.id),
    ["capabilities", "initialize", "shutdown"],
  );
  assert.equal(responses[0].result.framing, "json-lines");
  assert.equal(responses[1].result.status, "unavailable");
  assert.equal(responses[2].result.shutdown, true);
});

function request(method, params = {}, id = method) {
  return {
    protocol: PROTOCOL_NAME,
    protocolVersion: PROTOCOL_VERSION,
    id,
    method,
    params,
    timeoutMs: 5_000,
  };
}

function context() {
  return {
    signal: new AbortController().signal,
    deadlineMs: Date.now() + 5_000,
  };
}

function writeFakeTypeScript(packageRoot, version) {
  const typescriptRoot = path.join(packageRoot, "node_modules", "typescript");
  fs.mkdirSync(typescriptRoot, { recursive: true });
  fs.writeFileSync(
    path.join(typescriptRoot, "package.json"),
    `${JSON.stringify({ name: "typescript", version, main: "index.cjs" })}\n`,
  );
  fs.writeFileSync(
    path.join(typescriptRoot, "index.cjs"),
    [
      `module.exports.version = ${JSON.stringify(version)};`,
      "module.exports.sys = { readFile() { return '{}'; } };",
      "module.exports.readConfigFile = () => ({ config: {} });",
      "module.exports.parseJsonConfigFileContent = () => ({",
      "  errors: [], fileNames: [], options: {}, projectReferences: [],",
      "});",
      "module.exports.createProgram = () => ({ getTypeChecker() { return {}; } });",
      "module.exports.flattenDiagnosticMessageText = (message) => String(message);",
      "",
    ].join("\n"),
  );
}
