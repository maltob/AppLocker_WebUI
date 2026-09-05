# WDAC Policy Authoring Implementation Plan

## Goal

Add browser-only WDAC/App Control policy authoring alongside the existing AppLocker editor. Preserve AppLocker behavior and keep the site deployable as a static GitHub Pages or Cloudflare Pages application.

## Scope

Initial support creates, imports, validates, and exports unsigned WDAC XML base policies in Audit mode. It supports Hash, FileName/file-attribute, FilePublisher, SignedVersion, RSA Leaf/PCA certificate, and user-mode FilePath rules. It includes user-mode and kernel-mode signing scenarios.

The browser does not compile CIP/P7B binaries, sign policies, deploy policies, resolve online trust or revocation, or collect EVTX events. Windows ConfigCI tooling remains the validation authority.

## Architecture

Keep AppLocker and WDAC as separate policy engines over shared evidence:

PolicyDocument
  engine: applocker | wdac
  evidence[]
  model: AppLockerPolicyModel | WdacPolicyModel
  findings[]

Add separate evidence, WDAC model, WDAC XML, validation, and UI modules. Do not represent WDAC as AppLocker collections: WDAC is device-wide and has explicit user-mode/kernel signing scenarios.

## Evidence and file attributes

Expose OriginalFileName, InternalName, FileDescription, ProductName, file version, file type, kernel-driver indicators, Authenticode hash and state, every embedded signature, certificate public-key algorithm/OID, RSA key size or ECC curve, certificate-chain level, timestamp, and confidence.

Model FileAttrib records explicitly. FileName, FilePublisher, and SignedVersion rules retain the selected attribute and version range. Missing or inconsistent metadata blocks automatic attribute-rule generation and offers a hash alternative.

## Mandatory safety checks

### ECC certificates

WDAC signer rules require supported RSA. ECC/ECDSA-only evidence disables signer choices, emits WDAC_SIGNER_ECC_UNSUPPORTED, blocks export, and recommends a verified hash or file-attribute rule. A compatible RSA signature may be selected explicitly from a dual-signed file. RSA keys above 4096 bits are blocked.

### Kernel paths

FilePath rules are user-mode only. Disable FilePath for kernel-only policies and .sys evidence, emit WDAC_KERNEL_PATH_UNSUPPORTED, and block kernel signing scenarios from referencing FilePath. Mixed policies keep paths in the user-mode scenario and show the limitation. Warn about writable paths, macros, wildcards, and target OS compatibility.

Also warn when AppLocker SID/user/group scope, exceptions, deny semantics, or collection modes have no direct WDAC equivalent. WDAC must not expose misleading per-user SID controls.

## XML behavior

Import and export the urn:schemas-microsoft-com:sipolicy SiPolicy document. Parse metadata, options, FileRules/FileAttrib, Signers, SigningScenarios, and references. Validate IDs and cross-references, preserve unknown XML where safe, use deterministic ordering and stable IDs, and block export when semantics cannot be preserved. Export XML only and include Windows conversion guidance.

## UI

Add a persistent engine selector and WDAC settings for scope, Audit/Enforced mode, target Windows capability profile, base-policy metadata, and rule type. Disabled rule choices remain visible with textual reasons. Findings are keyboard accessible, announced through live regions, and receive focus after blocked export.

## Testing

Add fixtures for minimal audit policies, valid user/kernel scenarios, RSA, ECC-only, dual-signed, oversized RSA, unsigned EXE/DLL/SYS, user-mode and invalid kernel paths, file attributes with missing or malformed versions, unknown XML extensions, and dangling references.

Automate certificate and file-attribute classification, ECC and kernel-path blocking, WDAC XML semantic round trips, AppLocker regression tests, and accessible UI smoke checks.

On Windows, add a non-deploying golden check that parses generated XML and converts it with ConvertFrom-CIPolicy in a temporary directory. Never activate generated policies in CI.

## Delivery order

1. Repair the existing SID/newline baseline and capture AppLocker golden tests.
2. Extract shared evidence and AppLocker adapters.
3. Add certificate algorithm and file-attribute evidence.
4. Implement the WDAC model and compatibility findings.
5. Implement SiPolicy import/export.
6. Add WDAC UI and engine selection.
7. Add browser and Windows golden validation.
8. Update documentation and deployment guidance.

## Definition of done

AppLocker behavior remains semantically unchanged. WDAC XML can be created, imported, edited, exported, and re-imported client-side. File attributes are first-class rules. ECC-only signer rules and kernel FilePath rules cannot be exported. Mixed-scope paths are user-mode-only and visibly warned. Generated XML has valid references and passes Windows conversion validation. The production build remains a static site.
