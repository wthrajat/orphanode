import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const checks = [
  "node-resolution.mjs",
  "typescript-resolution.mjs",
];

for (const check of checks) {
  const checkPath = fileURLToPath(new URL(check, import.meta.url));
  const result = spawnSync(process.execPath, [checkPath, "--check"], {
    encoding: "utf8",
    env: process.env,
  });

  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);

  if (result.status !== 0) {
    process.exitCode = result.status ?? 1;
    break;
  }
}
