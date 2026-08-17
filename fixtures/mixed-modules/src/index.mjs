import { legacyValue, loadEsm } from "./bridge.cjs";

console.log(legacyValue, await loadEsm());
