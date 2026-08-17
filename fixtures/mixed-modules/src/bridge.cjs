const legacyValue = require("./legacy.cjs");

exports.legacyValue = legacyValue;
exports.loadEsm = () => import("./esm-helper.js");
