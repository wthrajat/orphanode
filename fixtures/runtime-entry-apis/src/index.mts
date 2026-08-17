import { fork } from "node:child_process";
import { register } from "node:module";
import { Worker } from "node:worker_threads";

new Worker(new URL("./worker.mts", import.meta.url));
fork(new URL("./child.cjs", import.meta.url));
register("./loader.mjs", import.meta.url);
