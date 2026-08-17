import { parentPort } from "node:worker_threads";

parentPort?.postMessage("worker ready");
