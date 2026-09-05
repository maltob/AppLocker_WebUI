import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = await readFile(new URL("../wdac.js", import.meta.url), "utf8");
const page = await readFile(new URL("../wdac-ui.html", import.meta.url), "utf8");
const fixture = await readFile(new URL("fixtures/wdac-minimal.xml", import.meta.url), "utf8");

assert.match(source, /urn:schemas-microsoft-com:sipolicy/);
assert.match(source, /WDAC_SIGNER_ECC_UNSUPPORTED/);
assert.match(source, /WDAC_KERNEL_PATH_UNSUPPORTED/);
assert.match(source, /FileAttrib/);
assert.match(source, /function parseXml/);
assert.match(source, /function serialize/);
assert.match(page, /href="index\.html">AppLocker/);
assert.match(page, /data-wdac-workspace/);
assert.match(page, /data-library-engine="wdac"/);

console.log("WDAC smoke checks passed");
