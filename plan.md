# AppLocker Policy Builder — Implementation Plan

## 1. Goal

Build a local-first web UI for creating, importing, editing, validating, and exporting Microsoft AppLocker XML policies. The application should help administrators author safe policies without hand-editing XML and should be able to derive useful rule data from files the user explicitly selects, including Windows PE executables.

The tool is an authoring and analysis utility. It does not apply policies to Windows, change Group Policy, start services, or silently scan a device.

## 2. Product principles

- **Local by default:** policy drafts, selected-file metadata, hashes, and signature data stay on the device unless the user deliberately exports or shares them.
- **Safe rollout:** new rule collections default to `AuditOnly`; changing to `Enabled` requires a clear warning and confirmation in the export review.
- **No hidden filesystem access:** the browser only reads files or directories that the user selects. Remembered handles are optional and revocable.
- **Standards-based output:** exported XML follows the Microsoft AppLocker policy schema and round-trips through Windows tooling.
- **Explain every rule:** the UI shows what a rule matches, whom it applies to, and the operational risk of broad paths, deny rules, DLL enforcement, or missing default rules.
- **Deterministic output:** stable ordering and formatting make policies easy to diff and review.
- **Browser-only architecture:** all product capabilities run in the browser. There is no native helper, local service, browser extension, or installed agent.

## 3. Scope

### MVP

- Create and edit AppLocker policies with `Exe`, `Msi`, `Script`, `Dll`, and `Appx` rule collections.
- Configure each collection as `AuditOnly`, `Enabled`, or absent. Do not encourage `NotConfigured`, because its merge behavior is easy to misunderstand.
- Create Allow and Deny rules using:
  - file path conditions;
  - file hash conditions;
  - publisher conditions when publisher attributes are available.
- Set rule name, description, stable GUID, action, and user/group SID.
- Support condition exceptions appropriate to the rule type.
- Add Microsoft-style default rules through an explicit wizard.
- Import an existing AppLocker XML policy and show validation errors without discarding the original file.
- Export formatted AppLocker XML and a machine-readable validation report.
- Select individual files or a directory from the browser.
- Parse PE files locally to obtain architecture, file size, version-resource fields, certificate-table presence, an ordinary checksum, and an AppLocker-compatible Authenticode hash.
- Derive a proposed hash rule from a selected file only after the browser-computed AppLocker hash passes the compatibility gate for that file category.
- Derive a proposed publisher rule only when the required signed-file attributes can be extracted with sufficient confidence; otherwise explain why it is unavailable and offer a hash rule.
- Store drafts and preferences in IndexedDB, with import/export backup.
- Provide a policy review screen with warnings, counts, generated XML, and a change summary.

### Post-MVP

- Appx/MSIX manifest and package-signature inspection.
- Bulk directory analysis, duplicate-rule consolidation, and publisher-rule optimization.
- Policy simulation against a selected inventory.
- CSP/Intune `RuleCollection` payload export in addition to complete AppLocker XML.
- Policy templates and reusable organizational rule sets.
- Event-log import to propose rules from audited AppLocker events.
- Accessible policy change history and side-by-side XML diff.

### Explicitly out of scope for the first release

- Applying or deploying a policy.
- Editing live Local Security Policy or Group Policy Objects.
- Remote filesystem scanning.
- Uploading executables to a server.
- Claiming that a browser-parsed certificate is currently trusted by Windows.
- Installing or communicating with a native helper, local service, browser extension, or agent.
- Replacing WDAC/App Control for Business policy authoring.

## 4. Recommended architecture

Use a TypeScript monorepo even though the product is browser-only. This keeps schema/domain logic independent of the UI and allows workers and test tooling to reuse the same packages.

```text
apps/
  web/                    React UI, PWA shell, browser capability adapters
packages/
  applocker-model/        Canonical typed policy model and invariants
  applocker-xml/          Secure parser, serializer, XSD-derived validation
  file-analysis/          Hashing, PE parsing, signature metadata extraction
  policy-analysis/        Lints, overlap checks, risk warnings, summaries
  test-fixtures/          XML and synthetic/non-sensitive file fixtures
docs/
  security.md
  compatibility.md
```

Suggested browser stack:

- React + TypeScript + Vite.
- A lightweight router for wizard/editor/review routes.
- IndexedDB through a small repository abstraction (Dexie is reasonable, but keep it behind an interface).
- Web Workers for hashing, PE parsing, XML validation, and inventory analysis.
- A vetted incremental SHA-256 implementation in a worker, plus an AppLocker-compatible Authenticode hashing implementation for PE files. Web Crypto can be used only where a full-file digest is actually the required algorithm and buffering limits permit it.
- Zod or an equivalent runtime validator at persistence and worker boundaries.
- Vitest, Testing Library, Playwright, and `fast-check` (or an equivalent property-testing library).

Do not bind the domain model directly to React state or XML DOM nodes. UI state should edit a canonical policy object, and the XML adapter should be the only component that understands AppLocker element ordering and serialization details.

## 5. Browser capability boundary

### Browser-only mode

The browser can safely support:

- user-mediated file selection with `<input type="file">`, drag/drop, and the File System Access API where available;
- user-mediated directory selection where supported;
- streaming or chunked file reads;
- ordinary SHA-256 checksums and, for verified file categories, AppLocker-compatible Authenticode hashes;
- PE/COFF header parsing;
- version-resource extraction;
- parsing the PE certificate table and embedded PKCS#7 certificate metadata;
- generation of path and hash rules;
- generation of publisher-rule suggestions based on extracted signed attributes, clearly labeled as browser-parsed rather than Windows trust-verified;
- IndexedDB/OPFS draft persistence and explicit file download.

Browser constraints must be visible in the product:

- browsers cannot silently enumerate arbitrary local paths;
- a web app cannot reliably determine the original absolute path of a selected file;
- a certificate's presence does not prove that Windows currently trusts it;
- browser certificate libraries do not reproduce every Windows trust-chain, revocation, catalog-signing, or policy decision;
- File System Access API support and persisted-handle behavior differ by browser, so file-input and download fallbacks are mandatory.

For path-rule creation, ask the user to enter or confirm the deployment path. Never fabricate it from a selected browser file name.

The application will not offer runtime SID lookup, effective-policy inspection, Windows trust verification, catalog-signature resolution, or direct validation by installed Windows AppLocker components. Users enter SIDs directly or choose documented well-known SID presets. The app must explain these limitations at the point where they matter.

Compatibility with Windows remains a development and release-testing concern: maintainers compare browser results and generated XML with golden outputs created on disposable Windows test machines. This tooling is not shipped with, invoked by, or required by the web application.

## 6. Canonical domain model

Model the policy independently of XML:

```ts
type CollectionType = "Exe" | "Msi" | "Script" | "Dll" | "Appx";
type EnforcementMode = "AuditOnly" | "Enabled";
type RuleAction = "Allow" | "Deny";

interface Policy {
  version: "1";
  collections: Partial<Record<CollectionType, RuleCollection>>;
  extensions?: PolicyExtensions;
  importMetadata?: ImportMetadata;
}

interface RuleCollection {
  type: CollectionType;
  enforcementMode: EnforcementMode;
  rules: Rule[];
  extensions?: RuleCollectionExtensions;
}

interface RuleBase {
  id: string;
  name: string;
  description: string;
  userOrGroupSid: string;
  action: RuleAction;
}

type Rule = PathRule | HashRule | PublisherRule;
```

The concrete rule types should use discriminated unions and preserve all schema-relevant fields:

- `PathRule`: one path condition plus zero or more path exceptions.
- `HashRule`: one or more file hash records, including algorithm, digest, source file name, and source file length, plus hash exceptions if permitted by the schema.
- `PublisherRule`: publisher, product, binary, version range, plus publisher exceptions.

Important invariants:

- rule IDs are GUIDs and unique across the whole policy;
- there is at most one collection of each type;
- each rule contains the condition form corresponding to its XML rule element;
- exported collections always use an explicit enforcement mode;
- hash data has a normalized `0x`-prefixed uppercase hexadecimal representation if Windows fixtures confirm that convention;
- file lengths are serialized without floating-point loss;
- `Appx` rules accept only publisher conditions;
- empty or unsupported rules cannot reach serialization;
- imported unknown extensions are either safely preserved in an explicit opaque-extension field or block lossy export until the user acknowledges removal.

Treat schema confirmation against real Windows-exported fixtures as a release gate; do not rely solely on hand-written TypeScript types.

## 7. AppLocker XML layer

### Import

1. Enforce configurable file-size and node-count limits before parsing.
2. Reject DTDs, processing instructions, and unexpected document roots.
3. Parse in a worker and never render XML as raw HTML.
4. Validate the root `AppLockerPolicy`, version, collections, rules, condition cardinality, attribute enums, GUIDs, SIDs, hash encodings, and element ordering.
5. Convert valid portions into the canonical model while collecting errors and warnings with source locations where possible.
6. Detect duplicate rule IDs and duplicate collection types.
7. Identify extensions and elements the current UI cannot faithfully edit.
8. Keep the original text separately until the import is accepted.

### Export

1. Validate the canonical model.
2. Run semantic policy linting.
3. Serialize via DOM/XML APIs or a small escaping serializer; never concatenate unescaped user strings.
4. Emit UTF-8 XML with deterministic indentation, collection order, rule order, attribute order, and line endings.
5. Reparse the generated XML and compare it to the canonical model.
6. Offer `policy.xml` plus an optional JSON validation report.

### Round-trip policy

- For fully supported XML, import -> export -> import must be semantically identical.
- Preserve rule IDs and user-authored order by default.
- Clearly mark any normalized formatting.
- If an imported construct cannot be represented, use a read-only/raw preservation path or stop export with a clear lossy-conversion warning. Never silently drop it.

### Schema coverage

Implement and test:

- `AppLockerPolicy Version="1"`;
- `RuleCollection` types `Exe`, `Msi`, `Script`, `Dll`, and `Appx`;
- collection enforcement modes used by Windows XML;
- `FilePathRule`, `FileHashRule`, and `FilePublisherRule`;
- `Conditions`, `Exceptions`, `FilePathCondition`, `FileHashCondition`, `FileHash`, `FilePublisherCondition`, and `BinaryVersionRange`;
- EXE/DLL rule collection extensions, including the requirement that related extension blocks are emitted together;
- unknown future extensions without silent data loss.

## 8. PE and executable analysis

Run all file analysis in a worker. Never execute, load, shell-open, or dynamically import a selected file.

### Parsing pipeline

1. Check size limits and DOS `MZ` signature.
2. Validate the `e_lfanew` offset before reading the PE signature.
3. Parse COFF and optional headers with bounds checks on every offset and length.
4. Record machine architecture, image type, linker timestamp (labeled as untrusted metadata), subsystem, and section summary.
5. Walk the resource directory safely to extract `VS_VERSION_INFO`, `StringFileInfo`, and fixed version data.
6. Locate the Attribute Certificate Table, parse PKCS#7/CMS metadata with a vetted library, and extract signer certificate subjects and relevant signed attributes.
7. Calculate an ordinary SHA-256 checksum plus the AppLocker-compatible Authenticode hash incrementally, with progress and cancellation. Keep the two values distinctly named and displayed.
8. Normalize extracted fields into an `AnalyzedFile` record.
9. Generate rule proposals, never rules that are automatically added without review.

### AppLocker-relevant output

```ts
interface AnalyzedFile {
  displayName: string;
  size: bigint;
  wholeFileSha256: string;
  appLockerHash?: {
    type: "SHA256" | "SHA256Flat";
    data: string;
    compatibility: "golden-verified" | "unverified";
  };
  pe?: {
    machine: string;
    productName?: string;
    fileDescription?: string;
    originalFilename?: string;
    fileVersion?: string;
    productVersion?: string;
  };
  signature?: {
    present: boolean;
    parseStatus: "parsed" | "malformed" | "unsupported";
    publisherName?: string;
    digestAlgorithm?: string;
    windowsTrustStatus: "not-checked";
    source: "browser";
  };
  warnings: AnalysisWarning[];
}
```

### Important technical validation spike

Before committing publisher-rule generation to MVP, compare browser-extracted publisher, product, binary, and version values against golden `Get-AppLockerFileInformation` results for a fixture corpus of signed Windows and third-party binaries. If normalized values do not consistently match Windows, ship browser publisher inspection as informational and omit automatic publisher-rule proposals. Users can still enter publisher fields manually or create an AppLocker-compatible hash rule.

Hash rules need their own compatibility gate. AppLocker uses a system-computed Authenticode hash, which is not always the same as an ordinary whole-file SHA-256 digest. Implement the correct hashing procedure per supported file type, label any ordinary checksum separately, and do not generate a `FileHashRule` until its value matches Windows golden results.

### Performance and resilience

- Default maximum individual file size: 2 GiB, configurable downward based on browser testing.
- Never allocate a buffer equal to a large file's full size solely to hash it.
- Limit parallel analyzers (for example, two workers) and queue the rest.
- Provide cancellation and remove references to `File` objects when an analysis is cleared.
- Cache analysis by a local fingerprint only after the user opts in; the ordinary whole-file SHA-256 plus size is preferred once calculated.
- Do not retain executable bytes in IndexedDB or OPFS by default.

## 9. Local storage and file access

### Persistence model

Use IndexedDB stores such as:

```text
drafts           id, name, policy, createdAt, updatedAt, schemaVersion
analysisCache    sha256, size, normalized metadata, analyzedAt, parserVersion
fileHandles      id, serialized handle where supported, permission state
preferences      key, value
```

Rules:

- Autosave only canonical policy data and lightweight file metadata.
- File handles are remembered only after an explicit “remember this location” action.
- On startup, check handle permission; do not trigger a permission prompt until a user gesture.
- Provide “Delete all local data” and per-draft deletion.
- Provide JSON backup/restore with versioned migrations.
- Keep an in-memory fallback when IndexedDB is unavailable.
- Do not put policy XML or analyzed metadata in `localStorage`; use it only for non-sensitive UI preferences, or avoid it entirely.

### Privacy messaging

State plainly in the file picker and settings screens:

- files are analyzed locally;
- selected file bytes are not uploaded;
- only metadata/digests are stored, unless a future feature explicitly says otherwise;
- drafts can contain sensitive paths, SIDs, publisher names, and software inventory details.

## 10. User experience

### Main flow

```text
Start / Import
      |
      v
Policy overview -----> Collection editor
      |                       |
      |                       +--> Manual rule form
      |                       +--> Analyze file(s) -> proposal -> review
      |                       +--> Default-rule wizard
      v
Validation and risk review
      |
      +--> Fix blocking errors
      +--> Acknowledge warnings
      v
XML preview and export
```

### Screens

1. **Home:** new policy, import XML, resume local draft, privacy summary.
2. **Policy overview:** cards for all five collections, mode, allow/deny counts, warnings, and add/configure actions.
3. **Collection editor:** filterable rule table, duplicate action, reorder, enable/disable collection, and default-rule wizard.
4. **Rule editor:** condition-specific form, SID presets (`Everyone` as `S-1-1-0`), expert fields, match explanation, and inline errors.
5. **File analyzer:** explicit picker/drop zone, progress, extracted identity, confidence/source labels, and proposed-rule chooser.
6. **Import report:** parsed collections/rules, blocking errors, unsupported constructs, and whether export would be lossless.
7. **Review:** errors, warnings, broad-match analysis, default-rule coverage, deny precedence warning, DLL/performance warning, and audit-first guidance.
8. **XML preview/export:** escaped syntax view, copy/download, deterministic file name, and validation summary.
9. **Settings/data:** privacy controls, cached analyses, remembered handles, backup/restore, and clear-data controls.

### Accessibility

- Meet WCAG 2.2 AA for keyboard navigation, focus order, contrast, labels, and error association.
- Do not encode Allow/Deny or validation severity by color alone.
- Make tables usable on narrow screens with a card/list fallback.
- Announce analysis progress and validation results through appropriate live regions without excessive chatter.

## 11. Policy analysis and guardrails

Validation has three levels:

### Blocking schema errors

- duplicate collection type or rule GUID;
- malformed GUID, SID, hash, version, or required attribute;
- condition incompatible with the collection;
- more than one primary condition where the schema permits only one;
- invalid XML characters;
- unsupported construct that would be lost on export.

### High-risk warnings

- switching a collection directly to enforcement without an audit stage;
- an Allow collection with no rules, which can block all files in that collection;
- a Deny rule, because explicit deny takes precedence over allow;
- writable-user-location path allow rules;
- broad wildcards or environment variables with surprising expansion;
- DLL rule collection enabled, because of coverage and performance impact;
- service enforcement without the corresponding system-app protection extension;
- rules targeting unresolved or unusual SIDs;
- missing standard Windows/Program Files/administrator defaults where applicable;
- unsigned files represented only by brittle hash rules;
- imported `NotConfigured` mode.

### Informational findings

- overlapping rules;
- exact duplicates;
- publisher rule could replace multiple hashes;
- stale analysis based on parser version;
- path shown is user-entered and was not obtained from the browser.

Every finding needs a stable code, severity, affected rule/collection IDs, short explanation, and suggested remediation. That makes validation usable in the UI, tests, and exported reports.

## 12. Security model

Document a threat model before shipping file import.

Threats and mitigations:

- **Malicious XML:** strict size/node/depth limits, no DTD/entity expansion, schema allowlist, worker isolation, escaped display.
- **Malformed PE/resource/certificate:** bounds-checked parser, worker termination on timeout, fuzz/property tests, no native execution.
- **Memory exhaustion:** chunked hashing, bounded concurrency, file-size caps, parser budgets.
- **Stored XSS:** treat all imported names, descriptions, paths, and certificate strings as data; React text rendering only; strong Content Security Policy.
- **Supply-chain compromise:** lockfile, dependency review, automated vulnerability/license checks, reproducible release build, Subresource Integrity if external assets are ever used (prefer bundling).
- **Local data leakage:** no analytics containing policy or file metadata; no network requests from the analyzer; easy deletion; sanitized error telemetry only with explicit opt-in.

Consider shipping the PWA with a CSP similar to `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, adjusted only for actual build needs.

## 13. Testing strategy

### Unit tests

- Domain invariants and migrations.
- XML escaping, ordering, and all rule/condition variants.
- GUID/SID/hash/version validators.
- PE offset and bounds checks.
- Version-resource decoding and Unicode cases.
- Hashing across empty, tiny, chunk-boundary, and large sparse/generated inputs.
- Every lint rule and remediation link.

### Fixture and compatibility tests

- Policies exported by Local Security Policy and AppLocker PowerShell on supported Windows versions.
- Full policy, single-collection policy, empty policy, default rules, exceptions, and extensions.
- Signed, unsigned, malformed, truncated, 32-bit, 64-bit, ARM64, managed, and native PE fixtures that are licensed for repository use or generated during tests.
- Browser analysis output compared with Windows `Get-AppLockerFileInformation` golden results.
- Generated XML imported by `Set-AppLockerPolicy`/AppLocker tooling on an isolated disposable Windows VM; validation must not modify a production policy.

### Property/fuzz tests

- Serialize/parse semantic round trips for generated valid policies.
- Arbitrary strings cannot break XML structure.
- Random/truncated PE byte sequences never cause out-of-bounds reads or hangs.
- Imported XML respects time, memory, depth, and node budgets.

### End-to-end tests

- Create each rule type, autosave, reload, review, and export.
- Import a valid policy and export it losslessly.
- Import a partially unsupported policy and verify export is blocked or explicitly acknowledged.
- Analyze a file, cancel analysis, retry, and add a hash proposal.
- Permission denial and unsupported File System Access API fallback.
- Clear all local data.
- Keyboard-only and screen-reader smoke flows.

### Release gates

- No blocking accessibility violations on primary flows.
- Generated policies pass canonical-model validation and reparse checks.
- Golden XML passes validation on the supported Windows test VM matrix.
- Browser parsing never claims Windows trust status; it reports certificate/signature structure only.
- AppLocker hash-rule output matches Windows golden results and is never substituted with a generic whole-file checksum.
- No executable bytes or policy contents leave the browser in network inspection tests.

## 14. Delivery phases

### Phase 0 — schema and feasibility spikes

- Capture the current Microsoft XSD and representative Windows-exported XML as attributed test references.
- Export fixture policies from Windows for every collection, rule, exception, and extension.
- Prove XML round-trip behavior.
- Prove chunked SHA-256 calculation in target browsers.
- Prototype PE version-resource and PKCS#7 parsing.
- Compare publisher fields against golden `Get-AppLockerFileInformation` results and make the MVP go/no-go decision for browser publisher-rule proposals.
- Compare browser-computed AppLocker/Authenticode hashes against Windows golden results for every supported file category; keep hash-rule generation disabled for categories that do not match.

Exit criteria: written compatibility matrix, canonical model approved, fixture corpus available, publisher-rule decision recorded.

### Phase 1 — policy engine and XML CLI harness

- Implement canonical model, runtime validation, lint result format, XML import/export, and deterministic formatting.
- Add a small developer-only CLI/test harness for converting fixtures and printing diagnostics.
- Build round-trip, golden, and property tests before UI integration.

Exit criteria: supported fixture policies round-trip and validate on Windows.

### Phase 2 — core web editor

- Create application shell, navigation, policy overview, collection editor, all manual rule forms, default-rule wizard, validation panel, XML preview, and download.
- Add accessible keyboard behavior and responsive layout from the start.

Exit criteria: a user can build and export a complete policy without file analysis.

### Phase 3 — local persistence and import

- Add IndexedDB repository, schema migrations, autosave status, draft management, backup/restore, XML import report, and clear-data controls.
- Implement preservation/blocking behavior for unsupported XML.

Exit criteria: drafts survive reloads and supported imports are lossless.

### Phase 4 — file analysis

- Add worker protocol, picker/drop flows, incremental hashing, PE parsing, progress/cancel behavior, analysis result UI, caching controls, and hash-rule proposals.
- Enable browser publisher proposals only if Phase 0 compatibility criteria were met.

Exit criteria: malicious/truncated fixtures are safely rejected; valid fixture identity matches golden data; no selected bytes are persisted or transmitted by default.

### Phase 5 — hardening and release

- Complete threat model, CSP, dependency audit, performance testing, browser matrix, accessibility audit, offline/PWA behavior, user documentation, and Windows compatibility run.
- Add a sample audit-only policy walkthrough and operational deployment warnings.

Exit criteria: all release gates pass and limitations are documented in-product.

## 15. Initial backlog order

1. Record architectural decisions for browser-only operation, unsupported XML preservation, and browser capability limitations.
2. Add repository tooling, TypeScript strict mode, formatting/linting, test runner, and CI.
3. Add Microsoft XSD/reference fixtures and license/provenance notes.
4. Implement canonical model and validators.
5. Implement XML importer and diagnostic locations.
6. Implement deterministic serializer and semantic round-trip tests.
7. Implement policy lint engine.
8. Build policy overview and collection editor.
9. Build path, hash, and publisher rule editors.
10. Build import report and export review.
11. Add IndexedDB drafts and migrations.
12. Add worker infrastructure and incremental hashing.
13. Add PE/resource parser and fuzz corpus.
14. Add signature metadata parser and Windows comparison spike.
15. Add file-analysis UI and reviewed rule proposals.
16. Complete end-to-end, accessibility, privacy, performance, and Windows compatibility gates.

## 16. Decisions to record early

- Target browsers and whether Chromium-only directory handles are an acceptable enhancement.
- Deployment form: static PWA, internally hosted site, or packaged web view.
- Whether browser-derived publisher-rule proposals meet the Windows golden-fixture compatibility threshold; otherwise keep publisher inspection informational and allow manual entry only.
- How unsupported imported XML is preserved and when export is blocked.
- Maximum file/directory size and file-count budgets.
- Supported policy extensions in v1.
- Whether policy drafts are considered sensitive organizational data under the intended deployment environment.
- Whether CSP/Intune fragment export belongs in the first release.
- Supported Windows versions for compatibility testing.

## 17. Documentation deliverables

- Getting started and sample audit-only workflow.
- Rule types and tradeoffs: publisher vs path vs hash.
- Browser file-access/privacy behavior.
- Import/export compatibility and known limitations.
- Safe deployment checklist: test on a reference machine, start in audit mode, collect events, confirm Application Identity service configuration, keep recovery access, then enforce.
- Contributor notes for updating the schema and golden fixtures.

## 18. Success metrics

- A first-time administrator can create a valid audit-only policy without editing XML.
- All supported imported policies round-trip without semantic changes.
- All exported fixtures are accepted by Windows AppLocker tooling.
- Every generated rule has a human-readable match explanation.
- File analysis never uploads or executes the selected file.
- Hashing and metadata extraction remain responsive and cancellable on large files.
- Unsupported or risky constructs are visible before export and are never silently discarded.
- The app can be used offline after initial installation/load.

## 19. Primary references

- [Microsoft: Working with AppLocker rules](https://learn.microsoft.com/en-us/windows/security/application-security/app-control-for-business/applocker/working-with-applocker-rules)
- [Microsoft: AppLocker CSP and policy XSD](https://learn.microsoft.com/en-us/windows/client-management/mdm/applocker-csp)
- [Microsoft: AppLocker rule collection extensions](https://learn.microsoft.com/en-us/windows/security/application-security/app-control-for-business/applocker/rule-collection-extensions)
- [Microsoft: Requirements to use AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/app-control-for-business/applocker/requirements-to-use-applocker)
- [Microsoft: Configure the Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/app-control-for-business/applocker/configure-the-application-identity-service)
- [Microsoft: New-AppLockerPolicy](https://learn.microsoft.com/en-us/powershell/module/applocker/new-applockerpolicy)

These references should be pinned by retrieval date in project documentation and rechecked before a compatibility release. The Microsoft-published XSD and XML produced by actual Windows tooling are the source of truth when examples or secondary libraries disagree.
