import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const required = [
  "index.html",
  "styles.css",
  "app.js",
  "wdac.js",
  "compatibility.js",
  "wdac-page.js",
  "rule-compatibility.js",
  "wdac-ui.html",
  ".github/workflows/pages.yml",
  "analysis-worker.js",
  "sw.js",
  "manifest.webmanifest",
  "README.md",
  "plan.md",
  "tests/e2e-harness.html",
  "tests/e2e-harness.js",
  "tests/fixtures/roundtrip-policy.xml",
  "tests/fixtures/unsupported-policy.xml",
  "tests/fixtures/msi-summary-fixture.js",
  "tests/fixtures/dll-analysis.json",
  "tests/fixtures/sample.ps1",
  "tests/fixtures/compatibility-matrix.json",
  "tests/fixtures/truncated-pe.json",
  "tests/fixtures/appx-fixture.js"
];
for (const file of required) await access(join(root, file));

const [index, app, wdac, worker, manifest, harness, roundtripFixture, msiFixture, dllFixture, scriptFixture, compatibilityFixture, truncatedFixture, appxFixture] = await Promise.all([
  readFile(join(root, "index.html"), "utf8"),
  readFile(join(root, "app.js"), "utf8"),
  readFile(join(root, "wdac.js"), "utf8"),
  readFile(join(root, "analysis-worker.js"), "utf8"),
  readFile(join(root, "manifest.webmanifest"), "utf8"),
  readFile(join(root, "tests/e2e-harness.js"), "utf8"),
  readFile(join(root, "tests/fixtures/roundtrip-policy.xml"), "utf8"),
  readFile(join(root, "tests/fixtures/msi-summary-fixture.js"), "utf8"),
  readFile(join(root, "tests/fixtures/dll-analysis.json"), "utf8"),
  readFile(join(root, "tests/fixtures/sample.ps1"), "utf8"),
  readFile(join(root, "tests/fixtures/compatibility-matrix.json"), "utf8"),
  readFile(join(root, "tests/fixtures/truncated-pe.json"), "utf8"),
  readFile(join(root, "tests/fixtures/appx-fixture.js"), "utf8")
]);

assert.match(index, /styles\.css/);
assert.match(index, /app\.js/);
assert.match(index, /manifest\.webmanifest/);
assert.match(index, /Content-Security-Policy/);
assert.match(index, /connect-src 'none'/);
assert.doesNotMatch(index, /(?:src|href)=["']https?:\/\//i);
assert.match(app, /parseXmlFidelity/);
assert.doesNotMatch(index, /<script src="wdac\.js"><\/script>/);
assert.match(index, /href="wdac-ui\.html">WDAC/);
assert.match(wdac, /WDAC_SIGNER_ECC_UNSUPPORTED/);
assert.match(wdac, /WDAC_KERNEL_PATH_UNSUPPORTED/);
assert.match(wdac, /localStorage/);
assert.match(app, /serializePolicyFidelity/);
assert.match(app, /openReviewFidelity/);
assert.match(app, /RuleCollectionExtensions/);
assert.match(app, /readExceptions/);
assert.match(app, /defaultRulesButton/);
assert.match(app, /policy-studio-test-result/);
assert.match(app, /__policyStudioTest/);
assert.match(app, /parseMsiMetadata/);
assert.match(app, /isMsiFile/);
assert.match(app, /classifyFileName/);
assert.match(app, /detectPeFileType/);
assert.match(app, /isDll/);
assert.match(app, /hashWholeFile/);
assert.match(worker, /crypto\.subtle\.digest/);
assert.match(app, /buildValidationReport/);
assert.match(harness, /Validation report is versioned and structured/);
assert.match(harness, /AppX manifest metadata parsed/);
assert.match(index, /downloadReportButton/);
assert.doesNotMatch(app, /windows-helper|localhost:\d+|fetch\(["']https?:/i);
assert.deepEqual(JSON.parse(manifest).display, "standalone");
assert.match(harness, /importXml/);
assert.match(harness, /serializeXml/);
assert.match(roundtripFixture, /<Exceptions>/);
assert.match(roundtripFixture, /<RuleCollectionExtensions>/);
assert.match(msiFixture, /__msiSummaryFixture/);
assert.match(harness, /MSI SummaryInformation metadata parsed/);
assert.deepEqual(JSON.parse(dllFixture).expectedTargetCollection, "Dll");
assert.match(scriptFixture, /#requires/);
assert.match(harness, /PowerShell script metadata parsed/);
assert.equal(JSON.parse(compatibilityFixture).entries.every(entry => entry.status === "pending-windows-golden"), true);
assert.equal(JSON.parse(truncatedFixture).expectedHash, null);
assert.match(appxFixture, /__appxFixture/);
assert.match(app, /parseAppxPackage/);
assert.match(await readFile(join(root, "rule-compatibility.js"), "utf8"), /PolicyRuleCompatibility/);

await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ["--check", join(root, "app.js")], { stdio: "inherit" });
  child.on("error", reject);
  child.on("exit", code => code === 0 ? resolve() : reject(new Error(`app.js syntax check failed with code ${code}`)));
});

console.log(`Static smoke checks passed (${required.length} required files).`);
