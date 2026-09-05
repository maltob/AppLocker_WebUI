import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = await readFile(new URL("../wdac.js", import.meta.url), "utf8");
const page = await readFile(new URL("../index.html", import.meta.url), "utf8");
const fixture = await readFile(new URL("fixtures/wdac-minimal.xml", import.meta.url), "utf8");

assert.match(source, /urn:schemas-microsoft-com:sipolicy/);
assert.match(source, /WDAC_SIGNER_ECC_UNSUPPORTED/);
assert.match(source, /WDAC_KERNEL_PATH_UNSUPPORTED/);
assert.match(source, /FileAttrib/);
assert.match(source, /function parseXml/);
assert.match(source, /function serialize/);
assert.match(page, /<script src="wdac\.js"><\/script>/);

console.log("WDAC smoke checks passed");
