import assert from "node:assert/strict";
import { serverName } from "../src/server.mjs";

assert.equal(serverName, "fixture server");
