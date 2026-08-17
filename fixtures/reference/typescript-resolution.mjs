import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const fixturesRoot = fileURLToPath(new URL("../", import.meta.url));
const expectedPath = fileURLToPath(
  new URL("./typescript-resolution.expected.json", import.meta.url),
);
const require = createRequire(import.meta.url);

const cases = [
  {
    id: "declaration-import",
    config: "declaration-type-only/tsconfig.json",
    from: "declaration-type-only/types/public.d.ts",
    specifier: "../src/contracts.js",
  },
  {
    id: "declaration-target",
    config: "declaration-type-only/tsconfig.json",
    from: "declaration-type-only/src/index.ts",
    specifier: "../types/public.js",
  },
  {
    id: "package-imports-types-condition",
    config: "resolver-package-maps/tsconfig.json",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "#internal",
  },
  {
    id: "path-alias",
    config: "ts-path-alias/tsconfig.json",
    from: "ts-path-alias/src/index.ts",
    specifier: "@/message",
  },
  {
    id: "self-reference-types-condition",
    config: "resolver-package-maps/tsconfig.json",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "fixture-resolver/feature",
  },
  {
    id: "unicode-extension-substitution",
    config: "resolver-path-identity/tsconfig.json",
    from: "resolver-path-identity/src/types.ts",
    specifier: "./café.js",
  },
  {
    id: "unexported-self-subpath",
    config: "resolver-package-maps/tsconfig.json",
    from: "resolver-package-maps/src/consumer.mjs",
    specifier: "fixture-resolver/private",
  },
];

function loadTypeScript() {
  const modulePath = process.env.TYPESCRIPT_PATH ?? "typescript";

  try {
    return require(modulePath);
  } catch (error) {
    throw new Error(
      "Install the pinned fixtures/reference dependency or set TYPESCRIPT_PATH " +
        "to a TypeScript 5.9.3 package directory.",
      { cause: error },
    );
  }
}

function compilerOptionsFor(ts, relativeConfigPath) {
  const configPath = resolve(fixturesRoot, relativeConfigPath);
  const loaded = ts.readConfigFile(configPath, ts.sys.readFile);

  if (loaded.error) {
    throw new Error(
      ts.formatDiagnostic(loaded.error, {
        getCanonicalFileName: (fileName) => fileName,
        getCurrentDirectory: () => fixturesRoot,
        getNewLine: () => "\n",
      }),
    );
  }

  const parsed = ts.parseJsonConfigFileContent(
    loaded.config,
    ts.sys,
    dirname(configPath),
  );

  if (parsed.errors.length > 0) {
    throw new Error(
      ts.formatDiagnostics(parsed.errors, {
        getCanonicalFileName: (fileName) => fileName,
        getCurrentDirectory: () => fixturesRoot,
        getNewLine: () => "\n",
      }),
    );
  }

  return parsed.options;
}

function normalizeResolved(resolvedFileName) {
  return relative(fixturesRoot, resolvedFileName).split(sep).join("/");
}

export function collectTypeScriptResolutionReference() {
  const ts = loadTypeScript();

  if (ts.version !== "5.9.3") {
    throw new Error(`Expected TypeScript 5.9.3, received ${ts.version}.`);
  }

  const optionsByConfig = new Map();
  const results = cases.map((testCase) => {
    let options = optionsByConfig.get(testCase.config);

    if (!options) {
      options = compilerOptionsFor(ts, testCase.config);
      optionsByConfig.set(testCase.config, options);
    }

    const containingFile = resolve(fixturesRoot, testCase.from);
    const resolution = ts.resolveModuleName(
      testCase.specifier,
      containingFile,
      options,
      ts.sys,
    ).resolvedModule;

    return {
      id: testCase.id,
      resolved: resolution
        ? normalizeResolved(resolution.resolvedFileName)
        : null,
    };
  });

  return {
    engine: "typescript",
    version: ts.version,
    cases: results,
  };
}

const actual = collectTypeScriptResolutionReference();

if (process.argv.includes("--check")) {
  const expected = JSON.parse(await readFile(expectedPath, "utf8"));
  assert.deepEqual(actual, expected);
  console.log("TypeScript resolution reference matches reviewed expectations.");
} else {
  process.stdout.write(`${JSON.stringify(actual, null, 2)}\n`);
}
