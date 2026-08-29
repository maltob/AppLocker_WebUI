# Policy Studio

Policy Studio is a browser-only AppLocker XML authoring tool. It has no backend, does not upload selected files, and stores drafts in the browser's local storage.

## Run locally

Serve this directory from a local HTTP server, then open the printed URL:

```text
python -m http.server 4173
```

Use HTTPS in deployed environments. Secure contexts enable Web Crypto and the File System Access API; the ordinary file picker remains available as a fallback.

Run the dependency-free static checks with:

```text
npm test
```

Run the browser end-to-end fixture harness by serving the directory and opening:

```text
python -m http.server 4173
http://127.0.0.1:4173/tests/e2e-harness.html
```

The harness runs the real app parser and serializer against XML fixtures, then
imports the exported XML again to verify that rules, exceptions, and extension
blocks survive the round trip. It also verifies that unsupported XML is surfaced
as an import issue instead of being silently discarded.

The fixture manifest at `tests/fixtures/compatibility-matrix.json` tracks the
Windows golden-result work needed before file-derived hashes or publisher data
can be considered verified. Until those entries are populated from disposable
Windows machines, generated MSI and script hashes remain explicitly unverified.

## Deploy

The directory is a static site and can be deployed directly to GitHub Pages, Cloudflare Pages, or another static HTTPS host. No build step or server-side environment variables are required.

## Workflow differentiators

The editor is designed as a policy review layer that complements the Windows AppLocker service and endpoint automation tools:

- **What-if analysis** tests a path, hash, publisher, product, version, and SID against the current collections without executing a file.
- **Semantic comparison** compares another XML policy by collections, enforcement modes, rule identities, and conditions while leaving the current draft untouched.
- **Evidence provenance** distinguishes manual, imported, and local-analysis rules. File-derived rules retain their hash basis, signer, and verification status in the validation report.
- **App Control review** provides an advisory migration-readiness score and calls out path dependence, hash maintenance, missing publisher coverage, unsupported XML, and unverified evidence before a WDAC/App Control design review.

These checks are intentionally advisory. The browser does not enforce policy, verify Windows trust/revocation, or compile a WDAC/App Control policy. Validate final hashes, signer trust, and behavior on a disposable Windows reference machine.

## Browser-only limitations

- A browser can inspect only files the user explicitly selects.
- It cannot discover or guarantee the original Windows path of a selected file.
- Certificate extraction reports embedded PKCS#7/X.509 data, not Windows trust, revocation, or catalog-signature status.
- Publisher rules are proposals for review. Product, binary, and version values come from PE version resources when available.
- AppX/MSIX analysis reads the ZIP package manifest locally and can propose publisher rules from the package identity; package trust and catalog signatures are not verified.
- AppLocker-compatible hashes must be validated against Windows-generated fixtures before production enforcement.
- File analysis uses a dedicated browser worker for whole-file SHA-256 work when workers are available; it falls back to Web Crypto if a worker cannot start.
- The policy review dialog can download a versioned JSON validation report alongside the XML export.

## Safety checklist

1. Start collections in Audit only mode.
2. Review broad paths, deny rules, empty collections, and writable locations.
3. Export and test on an isolated reference machine.
4. Confirm the generated XML with Windows AppLocker tooling before deployment.
5. Use **Review policy** to catch missing Windows/SystemRoot, Program Files, Windows Installer, script, DLL, and packaged-app coverage before enabling enforcement.
