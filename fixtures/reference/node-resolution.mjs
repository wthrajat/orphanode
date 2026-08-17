import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const fixturesRoot = fileURLToPath(new URL("../", import.meta.url));
const expectedPath = fileURLToPath(
  new URL("./node-resolution.expected.json", import.meta.url),
);

const cases = [
  {
    id: "case-preserving-relative-import",
    mode: "import",
    from: "resolver-path-identity/src/index.mjs",
    specifier: "./ExactCase.mjs",
  },
  {
    id: "package-imports-import-condition",
    mode: "import",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "#internal",
  },
  {
    id: "package-imports-require-condition",
    mode: "require",
    from: "resolver-package-maps/src/consumer.cjs",
    specifier: "#internal",
  },
  {
    id: "self-reference-import-condition",
    mode: "import",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "fixture-resolver/feature",
  },
  {
    id: "self-reference-require-condition",
    mode: "require",
    from: "resolver-package-maps/src/consumer.cjs",
    specifier: "fixture-resolver/feature",
  },
  {
    id: "symlink-default-realpath",
    mode: "import",
    from: "resolver-path-identity/src/index.mjs",
    specifier: "./linked.mjs",
  },
  {
    id: "unicode-relative-import",
    mode: "import",
    from: "resolver-path-identity/src/index.mjs",
    specifier: "./café.mjs",
  },
  {
    id: "unexported-self-subpath",
    mode: "import",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "fixture-resolver/private",
  },
];

const importProbe = String.raw`
try {
  process.stdout.write(JSON.stringify({ resolved: import.meta.resolve(process.argv[1]) }));
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.code ?? error.name }));
}
`;

function normalizeResolved(resolved) {
  if (!resolved.startsWith("file:")) {
    return resolved;
  }

  const absolutePath = fileURLToPath(resolved);
  return relative(fixturesRoot, absolutePath).split(sep).join("/");
}

function resolveImport(testCase) {
  const containingFile = resolve(fixturesRoot, testCase.from);
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", importProbe, testCase.specifier],
    {
      cwd: dirname(containingFile),
      encoding: "utf8",
    },
  );

  if (result.status !== 0) {
    throw new Error(result.stderr || `Node import probe exited ${result.status}`);
  }

  return JSON.parse(result.stdout);
}

function resolveRequire(testCase) {
  const containingUrl = pathToFileURL(resolve(fixturesRoot, testCase.from));
  const fixtureRequire = createRequire(containingUrl);

  try {
    return { resolved: pathToFileURL(fixtureRequire.resolve(testCase.specifier)).href };
  } catch (error) {
    return { error: error.code ?? error.name };
  }
}

export function collectNodeResolutionReference() {
  return {
    engine: "node",
    cases: cases.map((testCase) => {
      const outcome =
        testCase.mode === "import"
          ? resolveImport(testCase)
          : resolveRequire(testCase);

      return outcome.resolved
        ? { id: testCase.id, resolved: normalizeResolved(outcome.resolved) }
        : { id: testCase.id, error: outcome.error };
    }),
  };
}

const actual = collectNodeResolutionReference();

if (process.argv.includes("--check")) {
  const expected = JSON.parse(await readFile(expectedPath, "utf8"));
  assert.deepEqual(actual, expected);
  console.log("Node resolution reference matches reviewed expectations.");
} else {
  process.stdout.write(`${JSON.stringify(actual, null, 2)}\n`);
}
