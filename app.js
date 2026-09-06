(() => {
  "use strict";

  const COLLECTIONS = [
    { key: "Exe", label: "Executable files", symbol: "EXE", description: "Control which .exe and .com files can run." },
    { key: "Msi", label: "Windows Installer", symbol: "MSI", description: "Control Windows Installer packages and patches." },
    { key: "Script", label: "Scripts", symbol: "SCR", description: "Control PowerShell, batch, VBScript, and JavaScript." },
    { key: "Dll", label: "DLL files", symbol: "DLL", description: "Control which dynamic-link libraries can load." },
    { key: "Appx", label: "Packaged apps", symbol: "APP", description: "Control signed Microsoft Store and MSIX apps." }
  ];
  // Script files are inspected as text. PowerShell's Authenticode signature is
  // embedded in a commented PKCS#7 block; the browser can decode its X.509
  // certificates, but it cannot reproduce Windows trust, revocation, or
  // catalog-signature decisions.
  const SCRIPT_TYPES = {
    ".ps1": "PowerShell script", ".psm1": "PowerShell module", ".psd1": "PowerShell data/manifest",
    ".bat": "Windows batch script", ".cmd": "Windows command script",
    ".vbs": "VBScript", ".vbe": "Encoded VBScript", ".js": "JScript", ".jse": "Encoded JScript",
    ".wsf": "Windows Script File", ".wsh": "Windows Script Host settings"
  };
  const DEFAULT_SID = "S-1-1-0";  const WELL_KNOWN_SIDS = { "S-1-1-0": { name: "Everyone", hint: "applies to all users and groups" }, "S-1-5-11": { name: "Authenticated Users", hint: "applies to users who have signed in" }, "S-1-5-32-544": { name: "Administrators", hint: "local Administrators group only" }, "S-1-5-32-545": { name: "Users", hint: "local Users group; excludes service identities" }, "S-1-5-18": { name: "Local System", hint: "Windows LocalSystem service identity" }, "S-1-5-19": { name: "Local Service", hint: "Windows LocalService service identity" }, "S-1-5-20": { name: "Network Service", hint: "Windows NetworkService service identity" } };
  const STORAGE_KEY = "applocker-policy-studio-fallback";
  const $ = (id) => document.getElementById(id);
  let activeModal = null;
 let editingRuleId = null;
  let pendingRuleProvenance = null;
  let toastTimer;
  let state = newPolicy();
  window.__policyStudioGetState = () => state;

  function newPolicy() {
    return { name: "Untitled policy", version: "1", selectedCollection: "Exe", collections: { Exe: { mode: "AuditOnly", rules: [], extensionsXml: "" } }, importIssues: [], policyExtensionsXml: "" };
  }

  function uid() { return crypto.randomUUID ? crypto.randomUUID() : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); }); }
  function esc(value) { return String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c])); }
  function normalizeMode(value) { return value === "Enabled" ? "Enabled" : "AuditOnly"; }
  function collectionDef(key) { return COLLECTIONS.find(c => c.key === key) || COLLECTIONS[0]; }  function sidLabel(value) { const sid = String(value || DEFAULT_SID).trim(); const known = WELL_KNOWN_SIDS[sid]; return known ? known.name + " (" + sid + ")" : sid; }

  const dbPromise = "indexedDB" in window ? new Promise(resolve => {
    const request = indexedDB.open("applocker-policy-studio", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("drafts", { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
  }) : Promise.resolve(null);

  async function saveDraft() {
    const payload = { ...state, updatedAt: new Date().toISOString() };
    try {
      const db = await dbPromise;
      if (db) await new Promise((resolve, reject) => { const tx = db.transaction("drafts", "readwrite"); tx.objectStore("drafts").put({ id: "current", payload }); tx.oncomplete = resolve; tx.onerror = reject; });
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
      $("saveState").textContent = "Saved locally";
    } catch { $("saveState").textContent = "Saved in this browser"; }
  }
  async function loadDraft() {
    try {
      const db = await dbPromise;
      let saved = null;
      if (db) saved = await new Promise(resolve => { const req = db.transaction("drafts").objectStore("drafts").get("current"); req.onsuccess = () => resolve(req.result?.payload || null); req.onerror = () => resolve(null); });
      if (!saved) saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
      if (saved?.collections) { state = { ...newPolicy(), ...saved, selectedCollection: saved.selectedCollection || Object.keys(saved.collections)[0] || "Exe" }; render(); }
    } catch { /* The empty policy remains usable when storage is unavailable. */ }
  }

  function markDirty() { $("saveState").textContent = "Saving…"; clearTimeout(markDirty.timer); markDirty.timer = setTimeout(saveDraft, 350); }
  function currentCollection() { return state.collections[state.selectedCollection] || (state.collections[state.selectedCollection] = { mode: "AuditOnly", rules: [] }); }

  function render() {
    const current = currentCollection();
    const def = collectionDef(state.selectedCollection);
    $("policyTitle").textContent = state.name;
    $("collectionTitle").textContent = def.label;
    $("collectionType").textContent = def.symbol;
    $("collectionDescription").textContent = def.description;
    $("enforcementMode").value = current.mode;
    const allRules = Object.values(state.collections).reduce((n, c) => n + (c.rules?.length || 0), 0);
    $("ruleCount").textContent = allRules;
    $("collectionCount").textContent = Object.keys(state.collections).length;
    const baselineWarnings = (state.importIssues?.length || 0) + (current.mode === "Enabled" ? 1 : 0) + (!allRules ? 1 : 0); $("warningCount").textContent = String(baselineWarnings);
    $("visibleRuleCount").textContent = `${current.rules.length} ${current.rules.length === 1 ? "rule" : "rules"}`;
    $("appliesTo").textContent = current.rules[0]?.sid === "S-1-5-32-544" ? "Administrators" : "Everyone";
    renderCollections(); renderRules(); window.dispatchEvent(new CustomEvent("policy-studio:policy-change"));
    $("reviewText").textContent = allRules ? `${allRules} rule${allRules === 1 ? "" : "s"} across ${Object.keys(state.collections).length} collection${Object.keys(state.collections).length === 1 ? "" : "s"}.` : "Add a rule to start building this collection.";
    $("auditNotice").hidden = current.mode === "Enabled" || sessionStorage.getItem("auditNoticeDismissed") === "true";
  }

  function renderCollections() {
    $("collectionList").innerHTML = COLLECTIONS.map(def => {
      const present = state.collections[def.key]; const count = present?.rules?.length || 0;
      return `<button class="collection-item ${state.selectedCollection === def.key ? "active" : ""}" type="button" data-collection="${def.key}" aria-current="${state.selectedCollection === def.key ? "page" : "false"}"><span class="collection-symbol" aria-hidden="true">${def.symbol}</span><span class="collection-item-copy"><strong>${def.label}</strong><span>${present ? (present.mode === "Enabled" ? "Enforced" : "Audit only") : "Not configured"}</span></span><span class="collection-item-count">${count || "—"}</span></button>`;
    }).join("");
    document.querySelectorAll("[data-collection]").forEach(button => button.addEventListener("click", () => { state.selectedCollection = button.dataset.collection; if (!state.collections[state.selectedCollection]) state.collections[state.selectedCollection] = { mode: "AuditOnly", rules: [] }; markDirty(); render(); }));
  }

  function ruleConditionLabel(rule) {
    if (rule.kind === "path") return rule.condition.path || "No path";
    if (rule.kind === "hash") return rule.condition.data ? `${rule.condition.data.slice(0, 18)}…` : "No hash";
    return [rule.condition.publisher, rule.condition.product, rule.condition.binary].filter(Boolean).join(" / ") || "No publisher";
  }
  function ruleConditionKey(rule) { return [rule.kind, rule.action, rule.sid || DEFAULT_SID, JSON.stringify(rule.condition || {}), JSON.stringify(rule.exceptions || [])].join("|"); }
  function provenanceLabel(rule) {
    const source = rule.provenance?.source || "manual";
    return source === "local-analysis" ? "Local evidence" : source === "import" ? "Imported" : "Manual";
  }
  function renderRules() {
    const rules = currentCollection().rules || [];
    if (!rules.length) { $("ruleRegion").innerHTML = `<div class="empty-state"><div class="empty-mark" aria-hidden="true">＋</div><h3>No rules in this collection</h3><p>Start with a path, hash, or publisher rule—or inspect a local file to make a suggestion.</p><button class="button button-secondary" id="emptyAddRule" type="button">Add first rule</button></div>`; $("emptyAddRule").addEventListener("click", () => openRuleModal()); return; }
    $("ruleRegion").innerHTML = `<table class="rule-table"><caption class="visually-hidden">Rules in ${esc(collectionDef(state.selectedCollection).label)}</caption><thead><tr><th scope="col">Rule</th><th scope="col">Condition</th><th scope="col">Action</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead><tbody>${rules.map(rule => `<tr><td><span class="rule-name">${esc(rule.name)}</span><span class="rule-meta">${rule.kind === "path" ? "File path" : rule.kind === "hash" ? "File hash" : "Publisher"} · ${esc(rule.sid || DEFAULT_SID)}</span></td><td><span class="condition-value" title="${esc(ruleConditionLabel(rule))}">${esc(ruleConditionLabel(rule))}</span></td><td><span class="action-pill ${rule.action === "Deny" ? "action-deny" : "action-allow"}">${rule.action}</span></td><td class="row-actions"><button type="button" data-edit-rule="${rule.id}" aria-label="Edit ${esc(rule.name)}">Edit</button><button type="button" data-delete-rule="${rule.id}" aria-label="Delete ${esc(rule.name)}">Delete</button></td></tr>`).join("")}</tbody></table>`;
    document.querySelectorAll("[data-edit-rule]").forEach(b => b.addEventListener("click", () => openRuleModal(b.dataset.editRule)));
   document.querySelectorAll("[data-delete-rule]").forEach(b => b.addEventListener("click", () => { const rule = rules.find(r => r.id === b.dataset.deleteRule); if (rule && confirm(`Delete “${rule.name}”?`)) { currentCollection().rules = rules.filter(r => r.id !== rule.id); markDirty(); render(); showToast("Rule deleted"); } }));
    document.querySelectorAll(".rule-meta").forEach((meta, index) => { const rule = rules[index]; if (rule) meta.textContent += " · " + provenanceLabel(rule); });
  }

  function modalFocusables(modal) { return [...modal.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(node => !node.hidden && node.getAttribute("aria-hidden") !== "true"); }
  function openModal(id) { const modal = $(id); modal.dataset.returnFocusId = document.activeElement?.id || ""; modal.hidden = false; activeModal = modal; document.body.classList.add("modal-open"); (modalFocusables(modal)[0] || modal.querySelector(".modal"))?.focus(); }
  function closeModal(modal = activeModal) { if (!modal) return; const returnTarget = modal.dataset.returnFocusId && $(modal.dataset.returnFocusId); modal.hidden = true; activeModal = null; editingRuleId = null; document.body.classList.remove("modal-open"); returnTarget?.focus(); }
  function openRuleModal(ruleId = null, preset = null) {
   editingRuleId = ruleId; const rule = ruleId ? currentCollection().rules.find(r => r.id === ruleId) : null;
    pendingRuleProvenance = preset?.provenance || null;
    $("ruleModalTitle").textContent = rule ? "Edit rule" : "Add a rule";
    $("ruleName").value = rule?.name || preset?.name || ""; $("ruleDescription").value = rule?.description || preset?.description || ""; $("ruleAction").value = rule?.action || "Allow"; $("ruleSid").value = rule?.sid || DEFAULT_SID; $("ruleKind").value = rule?.kind || preset?.kind || "path";
    renderConditionFields({ ...(rule?.condition || preset?.condition), exceptions: rule?.exceptions || preset?.exceptions || [] }); openModal("ruleModal");
  }
  function renderConditionFields(values = {}) {
    const kind = $("ruleKind").value; const fields = $("conditionFields");
    const exceptions = (values.exceptions || []).filter(exception => exception.kind === kind);
    if (kind === "path") { $("conditionLegend").textContent = "Path condition"; fields.innerHTML = `<div class="field"><label for="conditionPath">Path or pattern <span aria-hidden="true">*</span></label><input id="conditionPath" required placeholder="%PROGRAMFILES%\\Contoso\\*" value="${esc(values.path || "")}" /><small class="muted">Use Windows paths and wildcards. Confirm the path on the target device.</small></div><div class="field"><label for="conditionExceptions">Path exceptions <span class="optional">optional</span></label><textarea id="conditionExceptions" rows="2" placeholder="One path per line">${esc(exceptions.map(exception => exception.path || "").join("\n"))}</textarea></div>`; }
    if (kind === "hash") { $("conditionLegend").textContent = "File hash condition"; fields.innerHTML = `<div class="field"><label for="conditionData">AppLocker hash <span aria-hidden="true">*</span></label><input id="conditionData" required placeholder="0x…" value="${esc(values.data || "")}" /><small class="muted">Use the Authenticode-compatible hash, not a generic checksum.</small></div><div class="form-grid two-up"><div class="field"><label for="conditionFile">Source file name</label><input id="conditionFile" value="${esc(values.file || "")}" placeholder="Contoso.exe" /></div><div class="field"><label for="conditionLength">Source file length</label><input id="conditionLength" type="number" min="0" value="${esc(values.length || "")}" placeholder="1048576" /></div></div><div class="field"><label for="conditionExceptions">Hash exceptions <span class="optional">optional</span></label><textarea id="conditionExceptions" rows="2" placeholder="0xHASH | file.exe | 1048576">${esc(exceptions.map(exception => [exception.data || "", exception.file || "", exception.length || ""].join(" | ")).join("\n"))}</textarea><small class="muted">One exception per line: hash, source file name, file length.</small></div>`; }
    if (kind === "publisher") { $("conditionLegend").textContent = "Publisher condition"; fields.innerHTML = `<div class="field"><label for="conditionPublisher">Publisher name <span aria-hidden="true">*</span></label><input id="conditionPublisher" required value="${esc(values.publisher || "")}" placeholder="CN=Contoso Ltd" /></div><div class="form-grid two-up"><div class="field"><label for="conditionProduct">Product name</label><input id="conditionProduct" value="${esc(values.product || "*")}" placeholder="*" /></div><div class="field"><label for="conditionBinary">Binary name</label><input id="conditionBinary" value="${esc(values.binary || "*")}" placeholder="*" /></div></div><div class="field"><label for="conditionVersion">Minimum version</label><input id="conditionVersion" value="${esc(values.lowVersion || "0.0.0.0")}" placeholder="0.0.0.0" /></div><div class="field"><label for="conditionExceptions">Publisher exceptions <span class="optional">optional</span></label><textarea id="conditionExceptions" rows="2" placeholder="Publisher | Product | Binary | Min version | Max version">${esc(exceptions.map(exception => [exception.publisher || "", exception.product || "*", exception.binary || "*", exception.lowVersion || "0.0.0.0", exception.highVersion || "*"].join(" | ")).join("\n"))}</textarea><small class="muted">One exception per line. Leave fields broad with * when needed.</small></div>`; }
  }

  function updateSidHint() { const input = $("ruleSid"); const hint = $("sidHint"); if (!input || !hint) return; const sid = input.value.trim(); const known = WELL_KNOWN_SIDS[sid]; hint.textContent = known ? known.name + " · " + known.hint + "." : sid ? "Custom or domain SID · verify the identity on the target device." : "Enter a SID or choose a well-known identity."; }
  function readCondition() { const kind = $("ruleKind").value; if (kind === "path") return { path: $("conditionPath").value.trim() }; if (kind === "hash") return { data: $("conditionData").value.trim().toUpperCase(), file: $("conditionFile").value.trim(), length: $("conditionLength").value.trim() }; return { publisher: $("conditionPublisher").value.trim(), product: $("conditionProduct").value.trim() || "*", binary: $("conditionBinary").value.trim() || "*", lowVersion: $("conditionVersion").value.trim() || "0.0.0.0", highVersion: "*" }; }
  function readExceptions() { const kind = $("ruleKind").value; const raw = $("conditionExceptions")?.value || ""; return raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => { if (kind === "path") return { kind, path: line }; if (kind === "hash") { const [data = "", file = "", length = ""] = line.split("|").map(part => part.trim()); return { kind, data: data.toUpperCase(), file, length }; } const [publisher = "", product = "*", binary = "*", lowVersion = "0.0.0.0", highVersion = "*"] = line.split("|").map(part => part.trim()); return { kind, publisher, product: product || "*", binary: binary || "*", lowVersion: lowVersion || "0.0.0.0", highVersion: highVersion || "*" }; }); }
  function targetCollectionForFile(result) {
    const type = result.collection || result.fileType || (result.msi ? "Msi" : (result.script ? "Script" : "Exe"));
    return COLLECTIONS.some(collection => collection.key === type) ? type : "Exe";
  }
  function ensureCollection(type) { if (!state.collections[type]) state.collections[type] = { mode: "AuditOnly", rules: [], extensionsXml: "" }; state.selectedCollection = type; return state.collections[type]; }
  function addRuleFromFile(result) {
    if (!result.appLockerHash) return showToast("No AppLocker-compatible hash is available");
    const type = targetCollectionForFile(result); const collection = ensureCollection(type);
    const hashLabel = result.script ? "browser-computed whole-file SHA-256 candidate" : "browser-computed Authenticode hash candidate";
    const rule = { id: uid(), ...(window.PolicyRuleCompatibility?.shared(result, "hash") || {}), name: `Allow ${result.name}`, description: `Hash rule proposed from local analysis of ${result.name} (${hashLabel}).`, action: "Allow", sid: DEFAULT_SID, kind: "hash", compatibility: result.compatibility || "unverified", provenance: { source: "local-analysis", fileName: result.name, hashBasis: result.hashBasis || hashLabel, compatibility: result.compatibility || "unverified", signer: result.signature?.certificates?.[0]?.subject || null }, condition: { data: result.appLockerHash, file: result.name, length: result.size }, exceptions: [] };
    if (window.PolicyRuleCompatibility) Object.assign(rule, window.PolicyRuleCompatibility.shared(result, "hash"));
    collection.rules.push(rule); markDirty(); render(); closeModal($("analysisModal")); showToast(`Hash rule added to ${collectionDef(type).label}`);
  }
  function addPublisherRuleFromFile(result) {
    const certificates = result.signature?.certificates || []; const issuers = new Set(certificates.map(c => c.issuer)); const signer = certificates.find(c => !issuers.has(c.subject)) || certificates[0]; const publisher = result.appx?.publisher || signer?.subject; if (!publisher) return showToast("No signing publisher is available");
   const version = result.pe || {}; const appx = result.appx || {}; const type = targetCollectionForFile(result); ensureCollection(type); closeModal($("analysisModal"));
    pendingRuleProvenance = { ...((window.PolicyRuleCompatibility?.shared(result, "publisher")) || {}), source: "local-analysis", fileName: result.name, hashBasis: "publisher metadata", compatibility: result.compatibility || "unverified", signer: publisher };
    openRuleModal(null, { kind: "publisher", name: `Allow ${result.name} publisher`, description: `Publisher rule proposed from browser-parsed metadata for ${result.name}.`, condition: { publisher, product: appx.name || appx.displayName || version.ProductName || "*", binary: appx.name ? "*" : (version.OriginalFilename || result.name), lowVersion: appx.version || (version.FileVersion ? normalizeVersion(version.FileVersion) : "0.0.0.0"), highVersion: "*" } });
  }

  function parseXml(text) {
    const doc = new DOMParser().parseFromString(text, "application/xml"); if (doc.querySelector("parsererror") || doc.documentElement?.nodeName !== "AppLockerPolicy") throw new Error("This does not look like an AppLocker policy XML file.");
    const next = newPolicy(); next.name = "Imported policy"; next.collections = {};
    [...doc.documentElement.children].filter(node => node.tagName === "RuleCollection").forEach(collectionNode => { const type = collectionNode.getAttribute("Type"); if (!COLLECTIONS.some(c => c.key === type)) return; const rules = []; [...collectionNode.children].forEach(ruleNode => { if (!["FilePathRule", "FileHashRule", "FilePublisherRule"].includes(ruleNode.tagName)) return; const conditionParent = [...ruleNode.children].find(child => child.tagName === "Conditions"); const condition = conditionParent?.firstElementChild; if (!condition) return; let kind = ruleNode.tagName === "FilePathRule" ? "path" : ruleNode.tagName === "FileHashRule" ? "hash" : "publisher"; let values = {}; if (kind === "path") values.path = condition.getAttribute("Path") || ""; if (kind === "hash") { const hash = [...condition.children].find(child => child.tagName === "FileHash"); values = { data: hash?.getAttribute("Data") || "", file: hash?.getAttribute("SourceFileName") || "", length: hash?.getAttribute("SourceFileLength") || "" }; } if (kind === "publisher") { const pub = [...condition.children].find(child => child.tagName === "FilePublisherCondition"); const version = pub ? [...pub.children].find(child => child.tagName === "BinaryVersionRange") : null; values = { publisher: pub?.getAttribute("PublisherName") || "", product: pub?.getAttribute("ProductName") || "*", binary: pub?.getAttribute("BinaryName") || "*", lowVersion: version?.getAttribute("LowSection") || "0.0.0.0", highVersion: version?.getAttribute("HighSection") || "*" }; } rules.push({ id: ruleNode.getAttribute("Id") || uid(), name: ruleNode.getAttribute("Name") || "Imported rule", description: ruleNode.getAttribute("Description") || "", action: ruleNode.getAttribute("Action") === "Deny" ? "Deny" : "Allow", sid: ruleNode.getAttribute("UserOrGroupSid") || DEFAULT_SID, kind, condition: values }); }); next.collections[type] = { mode: normalizeMode(collectionNode.getAttribute("EnforcementMode")), rules }; }); if (!Object.keys(next.collections).length) throw new Error("No supported rule collections were found in this policy."); next.selectedCollection = Object.keys(next.collections)[0]; state = next; markDirty(); render(); showToast("Policy imported and ready for review"); }

  function parseConditionNode(condition) {
    if (!condition) return null;
    if (condition.tagName === "FilePathCondition") return { kind: "path", path: condition.getAttribute("Path") || "" };
    if (condition.tagName === "FileHashCondition") { const hash = [...condition.children].find(child => child.tagName === "FileHash"); return hash ? { kind: "hash", data: hash.getAttribute("Data") || "", file: hash.getAttribute("SourceFileName") || "", length: hash.getAttribute("SourceFileLength") || "" } : null; }
    if (condition.tagName === "FilePublisherCondition") { const version = [...condition.children].find(child => child.tagName === "BinaryVersionRange"); return { kind: "publisher", publisher: condition.getAttribute("PublisherName") || "", product: condition.getAttribute("ProductName") || "*", binary: condition.getAttribute("BinaryName") || "*", lowVersion: version?.getAttribute("LowSection") || "0.0.0.0", highVersion: version?.getAttribute("HighSection") || "*" }; }
    return null;
  }
  function defaultRuleTemplates(type) {
    const base = (name, description, sid, condition, kind = "path") => ({ name, description, sid, action: "Allow", kind, condition });
    if (type === "Appx") return [base("(Default Rule) All signed packaged apps", "Allows Everyone to run packaged apps that are signed.", DEFAULT_SID, { publisher: "*", product: "*", binary: "*", lowVersion: "0.0.0.0", highVersion: "*" }, "publisher")];
    const label = collectionDef(type).label.toLowerCase(); return [base(`(Default Rule) All ${label} in Windows`, `Allows Everyone to run ${label} located in the Windows folder.`, DEFAULT_SID, { path: "%WINDIR%\\*" }), base(`(Default Rule) All ${label} in Program Files`, `Allows Everyone to run ${label} located in Program Files.`, DEFAULT_SID, { path: "%PROGRAMFILES%\\*" }), base(`(Default Rule) All ${label} for administrators`, `Allows local Administrators to run all ${label}.`, "S-1-5-32-544", { path: "*" })];
  }
  function openDefaults() { const templates = defaultRuleTemplates(state.selectedCollection); $("defaultsDescription").textContent = `Choose standard ${collectionDef(state.selectedCollection).label.toLowerCase()} rules to add in Audit only mode.`; $("defaultRuleOptions").innerHTML = templates.map((template, index) => `<label class="default-option"><input type="checkbox" data-default-index="${index}" checked /><span><strong>${esc(template.name)}</strong><small>${esc(template.description)}</small></span></label>`).join(""); openModal("defaultsModal"); }
  function addDefaults() { const templates = defaultRuleTemplates(state.selectedCollection); const selected = [...document.querySelectorAll("[data-default-index]:checked")].map(input => templates[Number(input.dataset.defaultIndex)]).filter(Boolean); const collection = currentCollection(); let added = 0; selected.forEach(template => { const duplicate = collection.rules.some(rule => rule.kind === template.kind && ruleConditionLabel(rule) === ruleConditionLabel(template)); if (!duplicate) { collection.rules.push({ ...template, id: uid(), exceptions: [] }); added++; } }); markDirty(); render(); closeModal($("defaultsModal")); showToast(added ? `${added} default rule${added === 1 ? "" : "s"} added` : "Selected defaults already exist"); }
  function parseXmlFidelity(text) {
    if (text.length > 10 * 1024 * 1024) throw new Error("This XML file is larger than the 10 MB safety limit.");
    const doc = new DOMParser().parseFromString(text, "application/xml"); if (doc.querySelector("parsererror") || doc.documentElement?.nodeName !== "AppLockerPolicy") throw new Error("This does not look like an AppLocker policy XML file.");
    const serializer = new XMLSerializer(); const next = newPolicy(); next.name = "Imported policy"; next.collections = {}; next.importIssues = [];
    [...doc.documentElement.children].forEach(node => {
      if (node.tagName !== "RuleCollection" && node.tagName !== "PolicyExtensions") next.importIssues.push(`Unsupported policy element <${node.tagName}> was not edited.`);
      if (node.tagName === "PolicyExtensions") next.policyExtensionsXml = serializer.serializeToString(node);
    });
    [...doc.documentElement.children].filter(node => node.tagName === "RuleCollection").forEach(collectionNode => {
      const type = collectionNode.getAttribute("Type"); if (!COLLECTIONS.some(c => c.key === type)) { next.importIssues.push(`Unsupported rule collection type “${type || "(missing)"}”.`); return; }
      const collection = { mode: normalizeMode(collectionNode.getAttribute("EnforcementMode")), rules: [], extensionsXml: "" };
      [...collectionNode.children].forEach(ruleNode => {
        if (ruleNode.tagName === "RuleCollectionExtensions") { collection.extensionsXml = serializer.serializeToString(ruleNode); return; }
        if (!["FilePathRule", "FileHashRule", "FilePublisherRule"].includes(ruleNode.tagName)) { next.importIssues.push(`Unsupported element <${ruleNode.tagName}> in the ${type} collection.`); return; }
        [...ruleNode.children].filter(child => !["Conditions", "Exceptions"].includes(child.tagName)).forEach(child => next.importIssues.push(`Unsupported element <${child.tagName}> in rule “${ruleNode.getAttribute("Name") || "unnamed"}”.`)); const conditions = [...ruleNode.children].find(child => child.tagName === "Conditions"); const primaryNodes = conditions ? [...conditions.children] : []; const condition = parseConditionNode(primaryNodes[0]);
        if (!condition) { next.importIssues.push(`Rule “${ruleNode.getAttribute("Name") || ruleNode.getAttribute("Id") || "unnamed"}” has an unsupported or missing condition.`); return; }
        if (primaryNodes.length > 1) next.importIssues.push(`Rule “${ruleNode.getAttribute("Name") || ruleNode.getAttribute("Id") || "unnamed"}” contains multiple primary conditions.`);
        const exceptionsNode = [...ruleNode.children].find(child => child.tagName === "Exceptions"); const exceptions = []; if (exceptionsNode) [...exceptionsNode.children].forEach(exceptionCondition => { const parsed = parseConditionNode(exceptionCondition); if (parsed) exceptions.push(parsed); else next.importIssues.push(`Rule “${ruleNode.getAttribute("Name") || "unnamed"}” contains an unsupported exception.`); });
        collection.rules.push({ id: ruleNode.getAttribute("Id") || uid(), name: ruleNode.getAttribute("Name") || "Imported rule", description: ruleNode.getAttribute("Description") || "", action: ruleNode.getAttribute("Action") === "Deny" ? "Deny" : "Allow", sid: ruleNode.getAttribute("UserOrGroupSid") || DEFAULT_SID, kind: condition.kind, condition, exceptions });
      }); next.collections[type] = collection;
    });
   if (!Object.keys(next.collections).length) throw new Error("No supported rule collections were found in this policy."); next.selectedCollection = Object.keys(next.collections)[0]; state = next; markDirty(); render(); showToast(next.importIssues.length ? "Imported with review issues" : "Policy imported and ready for review");
    Object.values(next.collections).forEach(collection => collection.rules.forEach(rule => { rule.provenance = { source: "import" }; }));
  }
  function serializeCondition(condition, indent) { if (condition.kind === "path") return `${indent}<FilePathCondition Path="${esc(condition.path)}" />\n`; if (condition.kind === "hash") return `${indent}<FileHashCondition>\n${indent}  <FileHash Type="SHA256" Data="${esc(condition.data)}" SourceFileName="${esc(condition.file)}" SourceFileLength="${esc(condition.length)}" />\n${indent}</FileHashCondition>\n`; return `${indent}<FilePublisherCondition PublisherName="${esc(condition.publisher)}" ProductName="${esc(condition.product || "*")}" BinaryName="${esc(condition.binary || "*")}">\n${indent}  <BinaryVersionRange LowSection="${esc(condition.lowVersion || "0.0.0.0")}" HighSection="${esc(condition.highVersion || "*")}" />\n${indent}</FilePublisherCondition>\n`; }
  function serializePolicyFidelity() {
    const order = ["Exe", "Msi", "Script", "Dll", "Appx"]; let xml = '<?xml version="1.0" encoding="utf-8"?>\n<AppLockerPolicy Version="1">\n';
    order.filter(type => state.collections[type]).forEach(type => { const collection = state.collections[type]; xml += `  <RuleCollection Type="${type}" EnforcementMode="${collection.mode}">\n`; collection.rules.forEach(rule => { const element = rule.kind === "path" ? "FilePathRule" : rule.kind === "hash" ? "FileHashRule" : "FilePublisherRule"; xml += `    <${element} Id="${esc(rule.id)}" Name="${esc(rule.name)}" Description="${esc(rule.description)}" UserOrGroupSid="${esc(rule.sid || DEFAULT_SID)}" Action="${rule.action}">\n      <Conditions>\n${serializeCondition({ ...rule.condition, kind: rule.kind }, "        ")}      </Conditions>\n`; if (rule.exceptions?.length) { xml += "      <Exceptions>\n"; rule.exceptions.forEach(exception => { xml += serializeCondition(exception, "        "); }); xml += "      </Exceptions>\n"; } xml += `    </${element}>\n`; }); if (collection.extensionsXml) xml += `    ${collection.extensionsXml}\n`; xml += "  </RuleCollection>\n"; }); if (state.policyExtensionsXml) xml += `  ${state.policyExtensionsXml}\n`; return `${xml}</AppLockerPolicy>\n`; }

  function serializePolicy() {
    const order = ["Exe", "Msi", "Script", "Dll", "Appx"]; let xml = '<?xml version="1.0" encoding="utf-8"?>\n<AppLockerPolicy Version="1">\n';
    order.filter(type => state.collections[type]).forEach(type => { const collection = state.collections[type]; xml += `  <RuleCollection Type="${type}" EnforcementMode="${collection.mode}">\n`; collection.rules.forEach(rule => { const element = rule.kind === "path" ? "FilePathRule" : rule.kind === "hash" ? "FileHashRule" : "FilePublisherRule"; xml += `    <${element} Id="${esc(rule.id)}" Name="${esc(rule.name)}" Description="${esc(rule.description)}" UserOrGroupSid="${esc(rule.sid || DEFAULT_SID)}" Action="${rule.action}">\n      <Conditions>\n`; if (rule.kind === "path") xml += `        <FilePathCondition Path="${esc(rule.condition.path)}" />\n`; if (rule.kind === "hash") xml += `        <FileHashCondition>\n          <FileHash Type="SHA256" Data="${esc(rule.condition.data)}" SourceFileName="${esc(rule.condition.file)}" SourceFileLength="${esc(rule.condition.length)}" />\n        </FileHashCondition>\n`; if (rule.kind === "publisher") xml += `        <FilePublisherCondition PublisherName="${esc(rule.condition.publisher)}" ProductName="${esc(rule.condition.product || "*")}" BinaryName="${esc(rule.condition.binary || "*")}">\n          <BinaryVersionRange LowSection="${esc(rule.condition.lowVersion || "0.0.0.0")}" HighSection="${esc(rule.condition.highVersion || "*")}" />\n        </FilePublisherCondition>\n`; xml += `      </Conditions>\n    </${element}>\n`; }); xml += "  </RuleCollection>\n"; }); return `${xml}</AppLockerPolicy>\n`; }

  function openReview() { const collections = Object.entries(state.collections); const allRules = collections.reduce((n, [, c]) => n + c.rules.length, 0); const findings = []; if (!allRules) findings.push(["warning", "No rules yet", "Add at least one rule before exporting this policy."]); collections.forEach(([type, c]) => { if (c.mode === "Enabled") findings.push(["warning", `${collectionDef(type).label} is enforced`, "Consider testing this collection in Audit only first."]); if (!c.rules.length) findings.push(["warning", `${collectionDef(type).label} is empty`, "An empty allow collection can block all files of this type."]); }); if (allRules && !findings.length) findings.push(["good", "Looks good", `${allRules} rule${allRules === 1 ? "" : "s"} ${allRules === 1 ? "is" : "are"} ready for XML export.`]); $("reviewResults").innerHTML = findings.map(([kind, title, text]) => `<div class="finding ${kind}"><span class="finding-icon">${kind === "good" ? "✓" : "!"}</span><div><strong>${title}</strong><p>${text}</p></div></div>`).join(""); openModal("reviewModal"); }
  function openReviewFidelity() { const findings = []; const collections = Object.entries(state.collections); const allRules = collections.reduce((n, [, c]) => n + c.rules.length, 0); (state.importIssues || []).forEach(issue => findings.push(["warning", "Import needs review", issue + " Export is blocked until this is resolved."])); if (!allRules) findings.push(["warning", "No rules yet", "Add at least one rule before exporting this policy."]); const seen = new Map(); collections.forEach(([type, collection]) => { if (collection.mode === "Enabled") findings.push(["warning", `${collectionDef(type).label} is enforced`, "Consider testing this collection in Audit only first."]); if (!collection.rules.length) findings.push(["warning", `${collectionDef(type).label} is empty`, "An empty allow collection can block all files of this type."]); collection.rules.forEach(rule => { const key = `${rule.kind}|${rule.action}|${rule.sid}|${ruleConditionLabel(rule)}`; if (seen.has(key)) findings.push(["warning", "Duplicate rule", `“${rule.name}” matches the same condition as “${seen.get(key)}”.`]); else seen.set(key, rule.name); if (rule.action === "Deny") findings.push(["warning", `Deny rule: ${rule.name}`, "Explicit deny rules take precedence over allows for the same user or group."]); if (rule.kind === "path" && (/^\*$/i.test(rule.condition.path || "") || /%USERPROFILE%|%APPDATA%|%TEMP%|\\Users\\[^*]+\\AppData/i.test(rule.condition.path || ""))) findings.push(["warning", `Writable path: ${rule.name}`, "Review whether a standard user can write to this location before allowing it."]); if (rule.kind === "path" && (rule.condition.path || "").endsWith("\\*")) findings.push(["good", `Broad path reviewed: ${rule.name}`, "This wildcard covers all matching files below the selected folder."]); }); }); if (allRules && !findings.some(finding => finding[0] === "warning")) findings.push(["good", "Looks good", `${allRules} rule${allRules === 1 ? "" : "s"} ${allRules === 1 ? "is" : "are"} ready for XML export.`]); $("reviewResults").innerHTML = findings.map(([kind, title, text]) => `<div class="finding ${kind}"><span class="finding-icon">${kind === "good" ? "✓" : "!"}</span><div><strong>${esc(title)}</strong><p>${esc(text)}</p></div></div>`).join(""); $("confirmExport").disabled = Boolean(state.importIssues?.length || !allRules); openModal("reviewModal"); }

  function downloadPolicy() { if (state.importIssues?.length) return showToast("Resolve import issues before exporting"); const blob = new Blob([serializePolicyFidelity()], { type: "application/xml;charset=utf-8" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.name.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "applocker-policy"}.xml`; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); closeModal($("reviewModal")); showToast("XML exported"); }
  function buildValidationReport() {
    const collections = Object.entries(state.collections).map(([type, collection]) => ({ type, enforcementMode: collection.mode, ruleCount: collection.rules.length, rules: collection.rules.map(rule => ({ id: rule.id, name: rule.name, kind: rule.kind, action: rule.action, sid: rule.sid, compatibility: rule.compatibility || "manual" })) }));
   const rules = collections.flatMap(collection => collection.rules); const unverified = rules.filter(rule => rule.compatibility === "unverified").length;
    collections.forEach(collection => collection.rules.forEach(rule => { const sourceRule = Object.values(state.collections).flatMap(collectionState => collectionState.rules || []).find(item => item.id === rule.id); rule.provenance = sourceRule?.provenance || { source: "manual" }; }));
    const findings = [...(state.importIssues || []).map(message => ({ severity: "warning", code: "IMPORT_UNSUPPORTED", message })), ...(unverified ? [{ severity: "warning", code: "HASH_COMPATIBILITY_UNVERIFIED", message: `${unverified} file-derived rule${unverified === 1 ? " is" : "s are"} marked unverified against Windows AppLocker results.` }] : [])];
    safetyFindings().forEach(item => findings.push({ severity: item[0], code: "SAFETY_CHECK", message: item[1] + ": " + item[2] }));
    return { schemaVersion: 1, generatedAt: new Date().toISOString(), policy: { name: state.name, version: state.version }, exportReady: !state.importIssues?.length && rules.length > 0, collections, findings };
  }
 function downloadValidationReport() { const report = JSON.stringify(buildValidationReport(), null, 2) + "\n"; const blob = new Blob([report], { type: "application/json;charset=utf-8" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.name.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "applocker-policy"}-validation.json`; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); showToast("Validation report downloaded"); }
 function wildcardRegexSafe(value) { const source = String(value || ""); const specials = "\\\\^$+?.()|[]{}"; let pattern = ""; for (const character of source) { if (character === "*") pattern += ".*"; else if (character === "?") pattern += "."; else pattern += specials.includes(character) ? "\\" + character : character; } return new RegExp("^" + pattern + "$", "i"); }
  const wildcardRegex = wildcardRegexSafe;
  function identityMatchesRule(rule, identity) {
    const sid = identity.sid || DEFAULT_SID; if (rule.sid && rule.sid !== DEFAULT_SID && rule.sid !== sid) return false;
    const c = rule.condition || {};
    if (rule.kind === "path") return Boolean(identity.path) && wildcardRegex(c.path).test(identity.path);
    if (rule.kind === "hash") return Boolean(identity.hash) && String(c.data || "").toUpperCase() === String(identity.hash || "").toUpperCase();
    const publisher = String(identity.publisher || ""); const product = String(identity.product || ""); const binary = String(identity.binary || identity.product || "");
    if (!publisher || !wildcardRegex(c.publisher || "*").test(publisher)) return false;
    if (c.product && c.product !== "*" && product && !wildcardRegex(c.product).test(product)) return false;
    if (c.binary && c.binary !== "*" && binary && !wildcardRegex(c.binary).test(binary)) return false;
    if (identity.version && c.lowVersion && compareVersions(identity.version, c.lowVersion) < 0) return false;
    if (identity.version && c.highVersion && c.highVersion !== "*" && compareVersions(identity.version, c.highVersion) > 0) return false;
    return true;
  }
  function compareVersions(a, b) { const left = String(a || "0").split(".").map(Number); const right = String(b || "0").split(".").map(Number); for (let i = 0; i < 4; i++) { const l = Number.isFinite(left[i]) ? left[i] : 0; const r = Number.isFinite(right[i]) ? right[i] : 0; if (l !== r) return l - r; } return 0; }
  function simulatePolicy(identity) {
    const collection = state.collections[identity.collection] || { mode: "AuditOnly", rules: [] }; const rules = collection.rules || [];
    const matches = rules.filter(rule => identityMatchesRule(rule, identity)); const denies = matches.filter(rule => rule.action === "Deny"); const allows = matches.filter(rule => rule.action !== "Deny");
    const decision = denies.length ? "Denied" : allows.length ? "Allowed" : "Not matched";
    return { decision, collectionMode: collection.mode, matches: matches.map(rule => ({ name: rule.name, action: rule.action, kind: rule.kind, condition: ruleConditionLabel(rule), provenance: provenanceLabel(rule) })), reason: denies.length ? "An explicit deny matched." : allows.length ? "At least one allow rule matched and no deny rule matched." : "No rule matched this file identity; an allow-list collection would block it." };
  }
  function openSimulator() {
    $("simulateCollection").innerHTML = COLLECTIONS.map(def => "<option value=\"" + def.key + "\"" + (def.key === state.selectedCollection ? " selected" : "") + ">" + esc(def.label) + "</option>").join("");
    $("simulateResults").innerHTML = "<p class=\"muted\">Enter a file identity and run the simulation.</p>"; openModal("simulateModal");
  }
  function renderSimulation(result) {
    const color = result.decision === "Allowed" ? "good" : result.decision === "Denied" ? "warning" : "warning";
    const detail = result.matches.length ? result.matches.map(match => "<div class=\"finding " + (match.action === "Deny" ? "warning" : "good") + "\"><span class=\"finding-icon\">" + (match.action === "Deny" ? "!" : "✓") + "</span><div><strong>" + esc(match.action + " · " + match.name) + "</strong><p>" + esc(match.kind + " · " + match.condition + " · " + match.provenance) + "</p></div></div>").join("") : "";
    $("simulateResults").innerHTML = "<div class=\"finding " + color + "\"><span class=\"finding-icon\">" + (result.decision === "Allowed" ? "✓" : "!") + "</span><div><strong>" + esc(result.decision) + "</strong><p>" + esc(result.reason + " Collection mode: " + result.collectionMode + ".") + "</p></div></div>" + detail;
  }
  function policySnapshot() { return JSON.parse(JSON.stringify(state)); }
  function semanticDiff(other) {
    const changes = []; const types = new Set([...Object.keys(state.collections), ...Object.keys(other.collections || {})]);
    types.forEach(type => { const current = state.collections[type]; const incoming = other.collections?.[type]; if (!current) { changes.push(["added", type + " collection", "Only in comparison policy"]); return; } if (!incoming) { changes.push(["removed", type + " collection", "Only in current policy"]); return; } if (current.mode !== incoming.mode) changes.push(["changed", type + " enforcement", current.mode + " → " + incoming.mode]); const left = new Map((current.rules || []).map(rule => [rule.id || ruleConditionKey(rule), rule])); const right = new Map((incoming.rules || []).map(rule => [rule.id || ruleConditionKey(rule), rule])); left.forEach((rule, key) => { if (!right.has(key)) changes.push(["removed", type + ": " + rule.name, "Only in current policy"]); else if (ruleConditionKey(rule) !== ruleConditionKey(right.get(key)) || rule.name !== right.get(key).name) changes.push(["changed", type + ": " + rule.name, "Rule metadata or condition differs"]); }); right.forEach((rule, key) => { if (!left.has(key)) changes.push(["added", type + ": " + rule.name, "Only in comparison policy"]); }); });
    return changes;
  }
  async function comparePolicyFile(file) {
    try { const text = await file.text(); const before = policySnapshot(); const oldIssues = state.importIssues; parseXml(text); const other = policySnapshot(); state = before; state.importIssues = oldIssues; render(); const changes = semanticDiff(other); $("diffResults").innerHTML = changes.length ? changes.map(item => "<div class=\"finding " + (item[0] === "removed" ? "warning" : item[0] === "changed" ? "warning" : "good") + "\"><span class=\"finding-icon\">" + (item[0] === "removed" ? "−" : item[0] === "changed" ? "!" : "+") + "</span><div><strong>" + esc(item[1]) + "</strong><p>" + esc(item[2]) + "</p></div></div>").join("") : "<div class=\"finding good\"><span class=\"finding-icon\">✓</span><div><strong>No semantic differences</strong><p>The policies contain the same collections and rules.</p></div></div>"; openModal("diffModal"); } catch (error) { $("diffResults").innerHTML = "<div class=\"finding warning\"><span class=\"finding-icon\">!</span><div><strong>Could not compare policy</strong><p>" + esc(error.message || "Invalid AppLocker XML") + "</p></div></div>"; openModal("diffModal"); }
  }
  function appControlFindings() {
    const findings = []; const rules = Object.entries(state.collections).flatMap(([type, collection]) => (collection.rules || []).map(rule => ({ ...rule, collection: type })));
    const publisherCount = rules.filter(rule => rule.kind === "publisher").length; const hashCount = rules.filter(rule => rule.kind === "hash").length; const pathCount = rules.filter(rule => rule.kind === "path").length; const unverified = rules.filter(rule => rule.compatibility === "unverified" || rule.provenance?.compatibility === "unverified").length;
    if (state.importIssues?.length) findings.push(["warning", "Resolve imported XML issues", "Unsupported constructs are preserved but need Windows validation before migration."]);
    if (pathCount) findings.push(["warning", pathCount + " path rule" + (pathCount === 1 ? "" : "s"), "App Control migrations should validate writable locations and signer coverage instead of relying on broad paths."]);
    if (hashCount) findings.push(["warning", hashCount + " hash rule" + (hashCount === 1 ? "" : "s"), "Hash rules are precise but require update maintenance; consider publisher or managed-installer coverage where appropriate."]);
    if (unverified) findings.push(["warning", unverified + " unverified file-derived rule" + (unverified === 1 ? "" : "s"), "Run a Windows golden test and attach the result before treating these as migration-ready."]);
    if (!publisherCount) findings.push(["warning", "No publisher rules", "App Control designs usually benefit from signer-based coverage; inspect certificates and decide whether the signer is trusted."]);
    if (publisherCount && !pathCount && !unverified && !state.importIssues?.length) findings.push(["good", "Good migration shape", "The policy is signer-oriented and has no outstanding browser verification findings."]);
    if (!findings.length) findings.push(["good", "Ready for design review", "No obvious migration blockers were found. This is guidance, not a WDAC/App Control policy compiler."]);
    return findings;
  }
 function openAppControlReview() {
   const findings = appControlFindings(); const warnings = findings.filter(item => item[0] === "warning").length; const score = Math.max(0, 100 - warnings * 18);
   $("appControlResults").innerHTML = "<div class=\"review-score\"><strong>" + score + "/100</strong><span>readiness signal</span></div>" + findings.map(item => "<div class=\"finding " + item[0] + "\"><span class=\"finding-icon\">" + (item[0] === "good" ? "✓" : "!") + "</span><div><strong>" + esc(item[1]) + "</strong><p>" + esc(item[2]) + "</p></div></div>").join("") + "<p class=\"analysis-note\">App Control review is advisory. Verify signer trust, policy behavior, and generated hashes on Windows before deployment.</p>"; openModal("appControlModal");
 }
  function downloadAppControlReview() { const payload = { schemaVersion: 1, generatedAt: new Date().toISOString(), policy: { name: state.name, version: state.version }, score: Math.max(0, 100 - appControlFindings().filter(item => item[0] === "warning").length * 18), findings: appControlFindings().map(item => ({ severity: item[0], title: item[1], message: item[2] })) }; const blob = new Blob([JSON.stringify(payload, null, 2) + "\n"], { type: "application/json;charset=utf-8" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "app-control-review.json"; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); showToast("App Control review downloaded"); }

 function showToast(message) { const toast = $("toast"); toast.textContent = message; toast.classList.add("visible"); clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove("visible"), 2800); }
  function appendSafetyFindings() { const findings = safetyFindings(); if (!findings.length) return; const region = $("reviewResults"); findings.forEach(item => { const node = document.createElement("div"); node.className = "finding " + item[0]; node.innerHTML = "<span class=\"finding-icon\">!</span><div><strong>" + esc(item[1]) + "</strong><p>" + esc(item[2]) + "</p></div>"; region.appendChild(node); }); }
  function safetyFindings() {
    const findings = []; const everyone = DEFAULT_SID;
    const hasAllow = (type, predicate) => (state.collections[type]?.rules || []).some(rule => rule.action === "Allow" && predicate(rule));
    const hasPath = (type, patterns) => hasAllow(type, rule => rule.kind === "path" && patterns.includes(String(rule.condition?.path || "").toUpperCase()));
    const hasBroadPublisher = type => hasAllow(type, rule => rule.kind === "publisher" && String(rule.condition?.publisher || "") === "*");
    const hasEveryoneAllow = type => hasAllow(type, rule => (rule.sid || everyone) === everyone);
    const allowConfigured = type => (state.collections[type]?.rules || []).some(rule => rule.action === "Allow");
    if (allowConfigured("Exe") && !hasPath("Exe", ["%WINDIR%\\*", "%SYSTEMROOT%\\*"]) && !hasBroadPublisher("Exe")) findings.push(["warning", "Windows executables may be blocked", "This EXE collection has allow rules but no broad Windows/SystemRoot or signer coverage. Built-in tools such as services, PowerShell, and system utilities may fail for standard users."]);
    if (allowConfigured("Exe") && !hasPath("Exe", ["%PROGRAMFILES%\\*", "%PROGRAMFILES(X86)%\\*"]) && !hasBroadPublisher("Exe")) findings.push(["warning", "Installed applications may be blocked", "Add reviewed Program Files coverage or publisher rules for software users must launch."]);
    if (allowConfigured("Msi") && !hasPath("Msi", ["%WINDIR%\\INSTALLER\\*", "%WINDIR%\\*"]) && !hasBroadPublisher("Msi")) findings.push(["warning", "Windows Installer packages may be blocked", "An MSI allow-list without Windows Installer coverage can break repairs, patches, and managed deployments."]);
    if (allowConfigured("Script") && !hasPath("Script", ["%WINDIR%\\*", "%SYSTEMROOT%\\*"]) && !hasBroadPublisher("Script")) findings.push(["warning", "System scripts may be blocked", "Review Windows-supplied scripts and administrative automation before enforcing the Script collection."]);
    if (allowConfigured("Dll") && !hasPath("Dll", ["%WINDIR%\\*", "%SYSTEMROOT%\\*"]) && !hasBroadPublisher("Dll")) findings.push(["warning", "System DLLs may be blocked", "DLL enforcement can prevent applications and Windows components from loading. Start in Audit and add tested system DLL coverage."]);
    if (allowConfigured("Appx") && !hasBroadPublisher("Appx")) findings.push(["warning", "Packaged apps may be blocked", "AppX/MSIX allow rules normally need reviewed publisher coverage; otherwise built-in and Store apps may stop launching."]);
    ["Exe", "Msi", "Script", "Dll", "Appx"].forEach(type => { if (allowConfigured(type) && !hasEveryoneAllow(type)) findings.push(["warning", collectionDef(type).label + " has no Everyone allow rule", "Rules scoped only to administrators or another SID will not cover standard users. Confirm the intended user scope."]); });
    Object.entries(state.collections).forEach(([type, collection]) => (collection.rules || []).forEach(rule => { if (rule.action === "Allow" && rule.kind === "publisher" && String(rule.condition?.publisher || "") === "*" && (rule.condition?.product || "*") === "*" && (rule.condition?.binary || "*") === "*") findings.push(["warning", "Broad publisher rule in " + collectionDef(type).label, "This matches every signed publisher. Prefer a named signer or document why broad signed-app coverage is acceptable."]); if (rule.kind === "hash" && (rule.compatibility === "unverified" || rule.provenance?.compatibility === "unverified")) findings.push(["warning", "Unverified hash: " + rule.name, "Validate the hash on Windows before enabling enforcement; browser-derived candidates are not a trust decision."]); }));
    if (!allowConfigured("Exe") && Object.keys(state.collections).some(type => type !== "Exe" && allowConfigured(type))) findings.push(["warning", "EXE collection has no allow rules", "Other enforced collections do not replace executable coverage. Confirm that Windows process launch behavior is intentional."]);
    return findings;
  }
  function readU16(bytes, offset) { return bytes[offset] | (bytes[offset + 1] << 8); }
  function readU32(bytes, offset) { return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0; }
  function detectPeFileType(fileName, layout) {
    const extension = String(fileName || "").toLowerCase().match(/\.[^.]+$/)?.[0] || "";
    if (SCRIPT_TYPES[extension]) return "Script";
    // IMAGE_FILE_DLL is authoritative when a valid PE header is available;
    // retain the extension fallback for malformed/synthetic DLL selections.
    if (layout?.isDll || extension === ".dll") return "Dll";
    return layout || extension === ".exe" || extension === ".com" ? "Exe" : "Unknown";
  }
  function parsePeLayout(bytes) {
    if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null;
    const peOffset = readU32(bytes, 0x3c); if (peOffset > bytes.length - 24 || readU32(bytes, peOffset) !== 0x00004550) return null;
    const optionalOffset = peOffset + 24; if (optionalOffset + 68 > bytes.length) return null;
    const magic = readU16(bytes, optionalOffset); if (magic !== 0x10b && magic !== 0x20b) return null;
    const optionalSize = readU16(bytes, peOffset + 20); if (optionalOffset + optionalSize > bytes.length) return null;
    const directoryOffset = optionalOffset + (magic === 0x20b ? 112 : 96); const securityDirectoryOffset = directoryOffset + 4 * 8; const resourceDirectoryOffset = directoryOffset + 2 * 8;
    if (securityDirectoryOffset + 8 > optionalOffset + optionalSize || resourceDirectoryOffset + 8 > optionalOffset + optionalSize) return null;
    const certOffset = readU32(bytes, securityDirectoryOffset); const certSize = readU32(bytes, securityDirectoryOffset + 4);
    const hasCertificate = certOffset > 0 && certSize > 0 && certOffset <= bytes.length && certSize <= bytes.length - certOffset;
    const characteristics = readU16(bytes, peOffset + 18);
    return { peOffset, optionalOffset, checksumOffset: optionalOffset + 64, securityDirectoryOffset, resourceRva: readU32(bytes, resourceDirectoryOffset), resourceSize: readU32(bytes, resourceDirectoryOffset + 4), sectionCount: readU16(bytes, peOffset + 6), characteristics, isDll: Boolean(characteristics & 0x2000), sectionTableOffset: optionalOffset + optionalSize, certOffset: hasCertificate ? certOffset : bytes.length, certSize: hasCertificate ? certSize : 0 };
  }
  function rvaToFileOffset(bytes, layout, rva) { const sectionSize = 40; for (let i = 0; i < layout.sectionCount; i++) { const section = layout.sectionTableOffset + i * sectionSize; if (section + sectionSize > bytes.length) break; const virtualSize = readU32(bytes, section + 8); const virtualAddress = readU32(bytes, section + 12); const rawSize = readU32(bytes, section + 16); const rawPointer = readU32(bytes, section + 20); const span = Math.max(virtualSize, rawSize); if (rva >= virtualAddress && rva < virtualAddress + span) return rawPointer + (rva - virtualAddress); } return null; }
  function utf16z(bytes, offset, limit) { let text = ""; for (let cursor = offset; cursor + 1 < limit; cursor += 2) { const code = readU16(bytes, cursor); if (!code) break; text += String.fromCharCode(code); } return text; }
  function align4(value) { return (value + 3) & ~3; }
  function parseVersionBlock(bytes, offset, limit, values) {
    if (offset + 6 > limit) return 0; const length = readU16(bytes, offset); const valueLength = readU16(bytes, offset + 2); const type = readU16(bytes, offset + 4); const blockEnd = Math.min(limit, offset + length); if (length < 6 || blockEnd <= offset) return 0;
    let keyEnd = offset + 6; while (keyEnd + 1 < blockEnd && readU16(bytes, keyEnd)) keyEnd += 2; const key = utf16z(bytes, offset + 6, keyEnd + 2); const valueStart = align4(keyEnd + 2); const valueBytes = type === 1 ? valueLength * 2 : valueLength;
    if (type === 1 && valueStart < blockEnd && ["ProductName", "OriginalFilename", "FileDescription", "FileVersion", "ProductVersion"].includes(key)) values[key] = utf16z(bytes, valueStart, Math.min(blockEnd, valueStart + valueBytes)).replace(/\0+$/, "");
    let child = align4(valueStart + valueBytes); while (child + 6 <= blockEnd) { const childLength = readU16(bytes, child); if (!childLength) break; const consumed = parseVersionBlock(bytes, child, blockEnd, values); if (!consumed) break; child = align4(child + consumed); } return length;
  }
  function resourceDirectoryEntry(bytes, offset, id) { if (offset == null || offset + 16 > bytes.length) return null; const count = readU16(bytes, offset + 12) + readU16(bytes, offset + 14); for (let i = 0; i < count; i++) { const entry = offset + 16 + i * 8; if (entry + 8 > bytes.length) break; const name = readU32(bytes, entry); const target = readU32(bytes, entry + 4); if (!(name & 0x80000000) && (name & 0x7fffffff) === id) return { directory: Boolean(target & 0x80000000), offset: target & 0x7fffffff }; } return null; }
  function parseVersionResource(bytes, layout) {
    if (!layout.resourceRva || !layout.resourceSize) return {}; const root = rvaToFileOffset(bytes, layout, layout.resourceRva); if (root == null || root >= bytes.length) return {};
    const typeEntry = resourceDirectoryEntry(bytes, root, 16); if (!typeEntry?.directory) return {}; const nameEntry = resourceDirectoryEntry(bytes, root + typeEntry.offset, 1); if (!nameEntry?.directory) return {};
    const languageEntry = resourceDirectoryEntry(bytes, root + nameEntry.offset, 0x409) || resourceDirectoryEntry(bytes, root + nameEntry.offset, 0); if (!languageEntry || languageEntry.directory) return {}; const dataEntry = root + languageEntry.offset; if (dataEntry + 16 > bytes.length) return {};
    const dataRva = readU32(bytes, dataEntry); const dataSize = readU32(bytes, dataEntry + 4); const dataOffset = rvaToFileOffset(bytes, layout, dataRva); if (dataOffset == null || dataOffset + dataSize > bytes.length) return {}; const values = {}; parseVersionBlock(bytes, dataOffset, dataOffset + dataSize, values); return values;
  }
  function normalizeVersion(version) { const parts = String(version || "").match(/\d+/g); return parts?.length ? [...parts.slice(0, 4), "0", "0", "0"].slice(0, 4).join(".") : "0.0.0.0"; }
  function derNode(bytes, offset = 0, limit = bytes.length) {
    if (offset + 2 > limit) throw new Error("Truncated DER header");
    const start = offset; const tag = bytes[offset++]; const lengthByte = bytes[offset++]; let length = lengthByte;
    if (lengthByte & 0x80) { const count = lengthByte & 0x7f; if (!count || count > 4 || offset + count > limit) throw new Error("Invalid DER length"); length = 0; for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++]; }
    const end = offset + length; if (end > limit) throw new Error("DER value exceeds certificate bounds");
    const node = { tag, start, valueStart: offset, valueEnd: end, end, children: [] };
    if ((tag & 0x20) !== 0) { let cursor = offset; while (cursor < end) { const child = derNode(bytes, cursor, end); node.children.push(child); cursor = child.end; } if (cursor !== end) throw new Error("Invalid DER children"); }
    return node;
  }
  function derOid(bytes, node) { let value = 0; const parts = []; for (let i = node.valueStart; i < node.valueEnd; i++) { const octet = bytes[i]; value = (value << 7) | (octet & 0x7f); if (!(octet & 0x80)) { parts.push(value); value = 0; } } if (parts.length) { const first = parts.shift(); parts.unshift(first >= 80 ? 2 : Math.floor(first / 40), first >= 80 ? first - 80 : first % 40); } return parts.join("."); }
  function derString(bytes, node) { const value = bytes.slice(node.valueStart, node.valueEnd); if (node.tag === 0x1e) { let text = ""; for (let i = 0; i + 1 < value.length; i += 2) text += String.fromCharCode((value[i] << 8) | value[i + 1]); return text; } try { return new TextDecoder(node.tag === 0x0c ? "utf-8" : "windows-1252").decode(value); } catch { return Array.from(value, b => String.fromCharCode(b)).join(""); } }
  function derInteger(bytes, node) { return Array.from(bytes.slice(node.valueStart, node.valueEnd), b => b.toString(16).padStart(2, "0")).join("").replace(/^0+(?=\w)/, "").toUpperCase(); }
  function certificateName(bytes, node) { const labels = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "E" }; const values = []; const rdns = node.children || []; rdns.forEach(set => (set.children || []).forEach(sequence => { const oid = sequence.children?.[0]; const value = sequence.children?.[1]; if (oid && value) values.push(`${labels[derOid(bytes, oid)] || derOid(bytes, oid)}=${derString(bytes, value).trim()}`); })); return values.join(", "); }
  function certificateDate(bytes, node) { const raw = derString(bytes, node); const utc = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/); const generalized = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/); const match = utc || generalized; if (!match) return raw; const yearValue = Number(match[1]); const year = utc ? yearValue + (yearValue < 50 ? 2000 : 1900) : yearValue; return new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]))).toISOString(); }
  function parseX509(bytes, node) { if (!node || node.tag !== 0x30 || node.children.length < 3) return null; const tbs = node.children[0]; if (tbs.tag !== 0x30 || tbs.children.length < 6) return null; let index = tbs.children[0]?.tag === 0xa0 ? 1 : 0; const serial = tbs.children[index++]; index++; const issuer = tbs.children[index++]; const validity = tbs.children[index++]; const subject = tbs.children[index++]; if (!serial || !issuer || !validity || !subject || validity.children.length < 2) return null; return { serial: derInteger(bytes, serial), issuer: certificateName(bytes, issuer), subject: certificateName(bytes, subject), validFrom: certificateDate(bytes, validity.children[0]), validTo: certificateDate(bytes, validity.children[1]), derStart: node.start, derEnd: node.end };
  }
  function findCertificateNodes(bytes, node, output = []) { const parsed = parseX509(bytes, node); if (parsed) output.push({ ...parsed, der: bytes.slice(node.start, node.end) }); (node.children || []).forEach(child => { if (child !== node) findCertificateNodes(bytes, child, output); }); return output; }
  async function certificateThumbprint(certificate) { const digest = await crypto.subtle.digest("SHA-256", certificate.der); return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("").toUpperCase(); }
  async function parseEmbeddedCertificates(bytes, layout) {
    if (!layout.certSize) return { present: false, parseStatus: "not-signed", certificates: [] };
    try {
      const certificates = []; let cursor = layout.certOffset; const end = layout.certOffset + layout.certSize;
      while (cursor + 8 <= end) { const length = readU32(bytes, cursor); const type = readU16(bytes, cursor + 6); if (length < 8 || cursor + length > end) throw new Error("Invalid WIN_CERTIFICATE length"); if (type === 2) { const cmsBytes = bytes.slice(cursor + 8, cursor + length); const contentInfo = derNode(cmsBytes); const signedData = contentInfo.children?.[1]?.children?.[0]; if (signedData) { const certificateWrapper = signedData.children?.find(child => child.tag === 0xa0); if (certificateWrapper) findCertificateNodes(cmsBytes, certificateWrapper, certificates); } } cursor += (length + 7) & ~7; }
      const unique = []; const seen = new Set(); for (const certificate of certificates) { const thumbprint = await certificateThumbprint(certificate); if (!seen.has(thumbprint)) { seen.add(thumbprint); unique.push({ ...certificate, thumbprint }); } }
      return { present: true, parseStatus: unique.length ? "parsed" : "unsupported", certificates: unique };
    } catch { return { present: true, parseStatus: "malformed", certificates: [] }; }
  }
  async function authentiCodeSha256(bytes, layout) {
    const ranges = [];
    const addRange = (start, end) => { if (end > start) ranges.push(bytes.slice(start, end)); };
    addRange(0, layout.checksumOffset); addRange(layout.checksumOffset + 4, layout.securityDirectoryOffset); addRange(layout.securityDirectoryOffset + 8, layout.certOffset); addRange(layout.certOffset + layout.certSize, bytes.length);
    const digest = await crypto.subtle.digest("SHA-256", await new Blob(ranges).arrayBuffer());
    return "0x" + Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, "0")).join("").toUpperCase();
  }
  async function hashWholeFile(bytes) {
    if (typeof Worker === "function") {
      try {
        return await new Promise((resolve, reject) => {
          const worker = new Worker("./analysis-worker.js"); const finish = () => worker.terminate();
          worker.onmessage = event => { finish(); event.data?.ok ? resolve(event.data.hash) : reject(new Error(event.data?.error || "Hashing failed")); };
          worker.onerror = error => { finish(); reject(error); }; const copy = bytes.slice(); worker.postMessage(copy.buffer, [copy.buffer]);
        });
      } catch { /* Use Web Crypto directly when workers are unavailable. */ }
    }
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return "0x" + Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, "0")).join("").toUpperCase();
  }
  const APPX_EXTENSIONS = new Set([".appx", ".msix", ".appxbundle", ".msixbundle"]);
  function isZip(bytes) { return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04; }
  function zipU16(bytes, offset) { return offset + 1 < bytes.length ? bytes[offset] | (bytes[offset + 1] << 8) : 0; }
  function zipU32(bytes, offset) { return offset + 3 < bytes.length ? (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0 : 0; }
  function zipText(bytes, offset, length) { return new TextDecoder("utf-8").decode(bytes.slice(offset, offset + length)); }
  function zipEntry(bytes, wantedName) {
    const start = Math.max(0, bytes.length - 0xffff - 22); let eocd = -1;
    for (let offset = bytes.length - 22; offset >= start; offset--) if (zipU32(bytes, offset) === 0x06054b50) { eocd = offset; break; }
    if (eocd < 0) return null; const directorySize = zipU32(bytes, eocd + 12); const directoryOffset = zipU32(bytes, eocd + 16); const limit = Math.min(bytes.length, directoryOffset + directorySize); const target = wantedName.toLowerCase();
    for (let offset = directoryOffset; offset + 46 <= limit && zipU32(bytes, offset) === 0x02014b50;) {
      const method = zipU16(bytes, offset + 10); const compressedSize = zipU32(bytes, offset + 20); const uncompressedSize = zipU32(bytes, offset + 24); const nameLength = zipU16(bytes, offset + 28); const extraLength = zipU16(bytes, offset + 30); const commentLength = zipU16(bytes, offset + 32); const localOffset = zipU32(bytes, offset + 42); const name = zipText(bytes, offset + 46, nameLength);
      if (name.toLowerCase() === target) return { method, compressedSize, uncompressedSize, localOffset, name };
      offset += 46 + nameLength + extraLength + commentLength;
    }
    return null;
  }
  async function unzipEntry(bytes, entry) {
    const local = entry.localOffset; if (zipU32(bytes, local) !== 0x04034b50) throw new Error("Invalid ZIP local header"); const nameLength = zipU16(bytes, local + 26); const extraLength = zipU16(bytes, local + 28); const start = local + 30 + nameLength + extraLength; const compressed = bytes.slice(start, start + entry.compressedSize);
    if (entry.method === 0) return compressed;
    if (entry.method !== 8 || typeof DecompressionStream !== "function") throw new Error("Compressed package entry is not supported by this browser");
    const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream("deflate-raw")); return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  function appxManifestMetadata(text) {
    const doc = new DOMParser().parseFromString(text, "application/xml"); if (doc.querySelector("parsererror") || doc.documentElement?.localName !== "Package") return { detected: true, format: "appx", parseStatus: "malformed" };
    const identity = [...doc.getElementsByTagNameNS("*", "Identity")][0] || [...doc.getElementsByTagName("Identity")][0]; const properties = [...doc.getElementsByTagNameNS("*", "Properties")][0] || [...doc.getElementsByTagName("Properties")][0]; const textValue = name => properties ? ([...properties.children].find(node => node.localName === name)?.textContent || "").trim() : "";
    const applications = [...doc.getElementsByTagNameNS("*", "Application"), ...doc.getElementsByTagName("Application")].filter((node, index, all) => all.indexOf(node) === index).map(node => ({ id: node.getAttribute("Id") || "", executable: node.getAttribute("Executable") || "", entryPoint: node.getAttribute("EntryPoint") || "" }));
    const metadata = { detected: true, format: "appx", parseStatus: identity ? "parsed" : "metadata-empty", name: identity?.getAttribute("Name") || "", publisher: identity?.getAttribute("Publisher") || textValue("Publisher"), version: identity?.getAttribute("Version") || "", architecture: identity?.getAttribute("ProcessorArchitecture") || "", displayName: textValue("DisplayName"), description: textValue("Description"), applications };
    return metadata;
  }
  async function parseAppxPackage(bytes) {
    if (!isZip(bytes)) return { detected: false, format: "not-zip", parseStatus: "unsupported" };
    try { const manifestEntry = zipEntry(bytes, "AppxManifest.xml"); if (!manifestEntry) return { detected: true, format: "appx", parseStatus: "manifest-missing" }; const manifest = appxManifestMetadata(new TextDecoder("utf-8").decode(await unzipEntry(bytes, manifestEntry))); const signatureEntry = zipEntry(bytes, "AppxSignature.p7x"); return { ...manifest, signatureEntry: Boolean(signatureEntry) }; } catch { return { detected: true, format: "appx", parseStatus: "malformed" }; }
  }
  function isAppxFile(file, bytes) { return APPX_EXTENSIONS.has(String(file.name || "").toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || ""); }

  // MSI support: parse the standard OLE SummaryInformation property set locally.
  // This intentionally avoids attempting to decode the compressed MSI database;
  // the summary stream is stable, useful metadata and is safe to inspect in a browser.
  const MSI_OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const MSI_SUMMARY_PROPERTY_NAMES = { 2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template", 8: "lastSavedBy", 9: "revisionNumber", 12: "created", 13: "lastSaved", 18: "applicationName", 19: "security" };
  const MSI_DOCUMENT_PROPERTY_NAMES = { 2: "category", 14: "manager", 15: "company" };
  function msiU16(bytes, offset) { return offset + 1 < bytes.length ? bytes[offset] | (bytes[offset + 1] << 8) : 0; }
  function msiU32(bytes, offset) { return offset + 3 < bytes.length ? (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0 : 0; }
  function msiU64(bytes, offset) { return msiU32(bytes, offset) + msiU32(bytes, offset + 4) * 0x100000000; }
  function msiUtf16(bytes, offset, length) { let text = ""; for (let i = 0; i + 1 < length && offset + i + 1 < bytes.length; i += 2) text += String.fromCharCode(msiU16(bytes, offset + i)); return text.replace(/\0+$/, ""); }
  function msiIsOle(bytes) { return bytes.length >= MSI_OLE_MAGIC.length && MSI_OLE_MAGIC.every((value, index) => bytes[index] === value); }
  function msiSectorChain(bytes, fat, start, sectorSize, maxBytes = bytes.length) { const output = []; const seen = new Set(); let sector = start; while (sector !== 0xfffffffe && sector !== 0xffffffff && sector !== 0xfffffffc && sector !== 0xfffffffd && sector >= 0 && !seen.has(sector) && output.length * sectorSize < maxBytes) { seen.add(sector); const offset = (sector + 1) * sectorSize; if (offset + sectorSize > bytes.length) break; output.push(bytes.slice(offset, offset + sectorSize)); sector = fat[sector] ?? 0xfffffffe; } const result = new Uint8Array(output.length * sectorSize); output.forEach((chunk, index) => result.set(chunk, index * sectorSize)); return result; }
  function msiPropertyValue(bytes, offset, end) {
    if (offset + 4 > end) return null; const type = msiU16(bytes, offset) & 0x0fff; const valueOffset = offset + 4;
    if (type === 30) { const length = Math.min(msiU32(bytes, valueOffset), Math.floor((end - valueOffset - 4))); return new TextDecoder("windows-1252").decode(bytes.slice(valueOffset + 4, valueOffset + 4 + length)).replace(/\0+$/, ""); }
    if (type === 31) { const length = Math.min(msiU32(bytes, valueOffset) * 2, Math.floor((end - valueOffset - 4) / 2) * 2); return msiUtf16(bytes, valueOffset + 4, length); }
    if (type === 64 && valueOffset + 8 <= end) return new Date(msiU64(bytes, valueOffset) / 10000 - 11644473600000).toISOString();
    if (type === 2 && valueOffset + 4 <= end) return msiU32(bytes, valueOffset);
    return null;
  }
  function msiParsePropertySet(stream, propertyNames) {
    if (stream.length < 48 || msiU16(stream, 0) !== 0xfffe) return {};
    const setCount = msiU32(stream, 28); const values = {};
    for (let setIndex = 0; setIndex < Math.min(setCount, 8); setIndex++) { const descriptor = 32 + setIndex * 20; if (descriptor + 20 > stream.length) break; const sectionOffset = msiU32(stream, descriptor + 16); if (sectionOffset + 8 > stream.length) continue; const sectionSize = Math.min(msiU32(stream, sectionOffset), stream.length - sectionOffset); const propertyCount = Math.min(msiU32(stream, sectionOffset + 4), 256); for (let index = 0; index < propertyCount; index++) { const property = sectionOffset + 8 + index * 8; if (property + 8 > sectionOffset + sectionSize) break; const propertyId = msiU32(stream, property); const valueOffset = sectionOffset + msiU32(stream, property + 4); const name = propertyNames[propertyId]; if (name && valueOffset < sectionOffset + sectionSize) { const value = msiPropertyValue(stream, valueOffset, sectionOffset + sectionSize); if (value !== null && value !== "") values[name] = value; } } }
    return values;
  }
  function parseMsiMetadata(bytes) {
    if (!msiIsOle(bytes) || bytes.length < 512) return { detected: false, format: "not-ole", parseStatus: "unsupported" };
    try {
      const sectorShift = msiU16(bytes, 30); const sectorSize = 1 << sectorShift; if (sectorSize < 128 || sectorSize > 4096) throw new Error("Unsupported OLE sector size"); const firstDirectorySector = msiU32(bytes, 48); const firstFatSector = msiU32(bytes, 76); const fatSectorCount = Math.min(msiU32(bytes, 44), 109); const fatSectorIds = []; for (let i = 0; i < fatSectorCount; i++) fatSectorIds.push(msiU32(bytes, 76 + i * 4));
      const fat = []; fatSectorIds.forEach(sector => { const offset = (sector + 1) * sectorSize; for (let index = 0; index < sectorSize && offset + index + 3 < bytes.length; index += 4) fat.push(msiU32(bytes, offset + index)); }); if (!fat.length && firstFatSector !== 0xffffffff) throw new Error("Missing OLE FAT");
      const directory = msiSectorChain(bytes, fat, firstDirectorySector, sectorSize, 8 * 1024 * 1024); let summary = null; let documentSummary = null;
      for (let offset = 0; offset + 128 <= directory.length; offset += 128) { const nameLength = msiU16(directory, offset + 64); const name = nameLength >= 2 ? msiUtf16(directory, offset, Math.min(nameLength - 2, 62)) : ""; if (directory[offset + 66] !== 2) continue; const startSector = msiU32(directory, offset + 116); const streamSize = Math.min(msiU64(directory, offset + 120), 8 * 1024 * 1024); if (!streamSize || startSector === 0xffffffff) continue; const stream = msiSectorChain(bytes, fat, startSector, sectorSize, streamSize + sectorSize).slice(0, streamSize); if (name === "\u0005SummaryInformation") summary = stream; if (name === "\u0005DocumentSummaryInformation") documentSummary = stream; }
      const properties = { ...msiParsePropertySet(summary || new Uint8Array(), MSI_SUMMARY_PROPERTY_NAMES), ...msiParsePropertySet(documentSummary || new Uint8Array(), MSI_DOCUMENT_PROPERTY_NAMES) }; return { detected: true, format: "msi-ole", parseStatus: Object.keys(properties).length ? "parsed" : "metadata-empty", ...properties };
    } catch { return { detected: true, format: "msi-ole", parseStatus: "malformed" }; }
  }
  // Script support: metadata comes from the selected text file only. The
  // PowerShell signature block is a commented PKCS#7 payload; certificates
  // are decoded for inspection, but Windows trust/revocation is not asserted.
  function decodeScriptText(bytes) {
    let encoding = "utf-8"; let payload = bytes;
    if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) { encoding = "utf-16le"; payload = bytes.slice(2); }
    else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) { encoding = "utf-16be"; payload = bytes.slice(2); }
    else if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) payload = bytes.slice(3);
    try { return { text: new TextDecoder(encoding).decode(payload), encoding }; } catch { return { text: new TextDecoder("windows-1252").decode(payload), encoding: "windows-1252" }; }
  }
  function scriptExtension(name) { const match = String(name || "").toLowerCase().match(/\.[a-z0-9]+$/); return match?.[0] || ""; }
  function scriptSignatureBlock(text) {
    const match = String(text || "").match(/#\s*SIG\s*#\s*Begin signature block\s*\r?\n([\s\S]*?)#\s*SIG\s*#\s*End signature block/i); if (!match) return null;
    const base64 = match[1].split(/\r?\n/).map(line => line.trim().replace(/^#\s?/, "")).filter(line => line && !/^SIG\s*#/i.test(line)).join("").replace(/\s+/g, "");
    if (!base64 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length % 4 === 1) return { malformed: true };
    try { const raw = atob(base64); return { bytes: Uint8Array.from(raw, character => character.charCodeAt(0)) }; } catch { return { malformed: true }; }
  }
  function scriptMetadataFromText(text, name) {
    const extension = scriptExtension(name); const type = SCRIPT_TYPES[extension]; if (!type) return null;
    const source = String(text || ""); const block = scriptSignatureBlock(source); const requires = [...source.matchAll(/^\s*#requires\s+(.+)$/gim)].map(match => match[1].trim()).slice(0, 20);
    return { detected: true, extension, type, encoding: "unknown", lineCount: source ? source.split(/\r\n|\r|\n/).length : 0, charCount: source.length, lineEnding: source.includes("\r\n") ? "CRLF" : source.includes("\n") || source.includes("\r") ? "LF/CR" : "none", hasShebang: /^\s*#!\s*/.test(source), requires, signatureBlock: Boolean(block), signatureStatus: block ? (block.malformed ? "malformed" : "embedded") : "not-signed" };
  }
  async function parsePowerShellSignature(text) {
    const block = scriptSignatureBlock(text); if (!block) return { present: false, parseStatus: "not-signed", certificates: [], source: "PowerShell signature block" }; if (block.malformed) return { present: true, parseStatus: "malformed", certificates: [], source: "PowerShell signature block" };
    try {
      const contentInfo = derNode(block.bytes); const signedData = contentInfo.children?.[1]?.children?.[0]; const wrapper = signedData?.children?.find(child => child.tag === 0xa0); if (!wrapper) return { present: true, parseStatus: "unsupported", certificates: [], source: "PowerShell signature block" };
      const certificates = []; findCertificateNodes(block.bytes, wrapper, certificates); const unique = []; const seen = new Set(); for (const certificate of certificates) { const thumbprint = await certificateThumbprint(certificate); if (!seen.has(thumbprint)) { seen.add(thumbprint); unique.push({ ...certificate, thumbprint }); } }
      return { present: true, parseStatus: unique.length ? "parsed" : "unsupported", certificates: unique, source: "PowerShell signature block", trust: "not-verified" };
    } catch { return { present: true, parseStatus: "malformed", certificates: [], source: "PowerShell signature block" }; }
  }
  async function analyzeScript(file, bytes) { const decoded = decodeScriptText(bytes); const script = scriptMetadataFromText(decoded.text, file.name); script.encoding = decoded.encoding; script.signature = await parsePowerShellSignature(decoded.text); script.hashBasis = "whole-file SHA-256"; return script; }
  function isMsiFile(file, bytes) { return /\.(msi|msp|mst)$/i.test(file.name || "") || msiIsOle(bytes); }
  async function analyzeFile(file) {
    if (file.size > 2 * 1024 * 1024 * 1024) throw new Error("Files are limited to 2 GB for browser analysis.");
    const bytes = new Uint8Array(await file.arrayBuffer()); const appx = isAppxFile(file, bytes) ? await parseAppxPackage(bytes) : null; const script = appx ? null : (SCRIPT_TYPES[scriptExtension(file.name)] ? await analyzeScript(file, bytes) : null); const msi = appx || script ? null : (isMsiFile(file, bytes) ? parseMsiMetadata(bytes) : null); const layout = appx || script || msi ? null : parsePeLayout(bytes);
    const wholeFileSha256 = await hashWholeFile(bytes);
    const signature = appx ? { present: appx.signatureEntry, parseStatus: appx.signatureEntry ? "present-not-verified" : "not-signed", certificates: [] } : script ? script.signature : layout ? await parseEmbeddedCertificates(bytes, layout) : { present: false, parseStatus: "not-pe", certificates: [] };
    const versionInfo = layout ? parseVersionResource(bytes, layout) : {}; return { name: file.name, size: file.size, wholeFileSha256, appLockerHash: layout ? await authentiCodeSha256(bytes, layout) : (msi || script ? wholeFileSha256 : null), hashBasis: script ? "whole-file SHA-256" : layout ? "PE Authenticode SHA-256" : msi ? "whole-file SHA-256" : null, compatibility: "unverified", fileType: appx ? "Appx" : script ? "Script" : msi ? "Msi" : detectPeFileType(file.name, layout), appx, script, msi, pe: layout ? { detected: true, ...versionInfo } : null, signature };
  }

  // Keep the shared analysis renderer compact while making DLL routing visible
  // in the result card. This covers malformed .dll selections as well as PE
  // DLLs and does not alter the underlying parser or rule proposal data.
  function decorateDllAnalysisCards() {
    document.querySelectorAll(".analysis-card").forEach(card => {
      if (card.dataset.dllDecorated === "true") return;
      const name = card.querySelector("strong")?.textContent || "";
      if (!/\.dll$/i.test(name)) return;
      card.dataset.dllDecorated = "true";
      const summary = card.querySelector("div > p");
      if (summary) {
        const size = summary.textContent.match(/ · [\d.]+ KB$/)?.[0] || "";
        summary.textContent = summary.textContent.includes("PE file detected") ? `DLL file detected · Authenticode hash candidate${size}` : `DLL extension detected · PE header not detected · hash rule unavailable${size}`;
      }
      const targetNote = document.createElement("p"); targetNote.className = "analysis-note dll-analysis-note"; targetNote.textContent = "Target collection: DLL files";
      const content = card.querySelector("div"); content?.insertBefore(targetNote, content.querySelector("code"));
      const hashButton = card.querySelector("[data-add-analysis-index]"); if (hashButton) hashButton.textContent = hashButton.disabled ? "Hash unavailable" : "Add DLL hash rule";
      const publisherButton = card.querySelector("[data-add-publisher-index]"); if (publisherButton && !publisherButton.disabled) publisherButton.textContent = "Add DLL publisher rule";
    });
  }
  function decorateAppxAnalysisCards() {
    document.querySelectorAll(".analysis-card").forEach(card => {
      if (card.dataset.appxDecorated === "true") return;
      const name = card.querySelector("strong")?.textContent || ""; if (!APPX_EXTENSIONS.has(name.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || "")) return;
      card.dataset.appxDecorated = "true"; const summary = card.querySelector("div > p"); if (summary) { const size = summary.textContent.match(/ · [\d.]+ KB$/)?.[0] || ""; summary.textContent = `AppX/MSIX package detected · manifest metadata parsed locally${size}`; }
      const content = card.querySelector("div"); const targetNote = document.createElement("p"); targetNote.className = "analysis-note appx-analysis-note"; targetNote.textContent = "Target collection: Packaged apps · Windows trust not verified"; content?.insertBefore(targetNote, content.querySelector("code"));
      const hashButton = card.querySelector("[data-add-analysis-index]"); if (hashButton) hashButton.textContent = "Publisher rules only";
      const publisherButton = card.querySelector("[data-add-publisher-index]"); if (publisherButton) { publisherButton.disabled = false; publisherButton.textContent = "Add AppX publisher rule"; }
    });
  }
  const analysisObserver = new MutationObserver(() => { decorateDllAnalysisCards(); decorateAppxAnalysisCards(); }); const analysisRoot = $("analysisResults"); if (analysisRoot) analysisObserver.observe(analysisRoot, { childList: true, subtree: true });

 window.addEventListener("policy-studio:reuse-applocker", event => {
   const { item, method } = event.detail || {};
   if (method === "hash") addRuleFromFile(item);
   else if (method === "publisher") addPublisherRuleFromFile(item);
 });
 $("addRuleButton").addEventListener("click", () => openRuleModal());
  $("simulateButton")?.addEventListener("click", openSimulator);
  $("simulateForm")?.addEventListener("submit", event => { event.preventDefault(); const identity = { collection: $("simulateCollection").value, path: $("simulatePath").value.trim(), publisher: $("simulatePublisher").value.trim(), product: $("simulateProduct").value.trim(), binary: $("simulateProduct").value.trim(), hash: $("simulateHash").value.trim(), version: $("simulateVersion").value.trim(), sid: $("simulateSid").value.trim() || DEFAULT_SID }; renderSimulation(simulatePolicy(identity)); });
  $("compareButton")?.addEventListener("click", () => { $("diffResults").innerHTML = "<p class=\"muted\">Select a policy to compare.</p>"; openModal("diffModal"); });
  $("compareInput")?.addEventListener("change", async event => { const file = event.target.files[0]; if (file) await comparePolicyFile(file); event.target.value = ""; });
  $("appControlButton")?.addEventListener("click", openAppControlReview);
  $("downloadAppControlButton")?.addEventListener("click", downloadAppControlReview);
  $("ruleKind").addEventListener("change", () => renderConditionFields());
 $("ruleForm").addEventListener("submit", event => { event.preventDefault(); const form = new FormData(event.currentTarget); const rule = { id: editingRuleId || uid(), name: form.get("name").trim(), description: form.get("description").trim(), action: form.get("action"), sid: form.get("sid").trim() || DEFAULT_SID, kind: form.get("kind"), condition: readCondition(), exceptions: readExceptions() }; if (!rule.name) return; const collection = currentCollection(); const index = collection.rules.findIndex(r => r.id === rule.id); if (index >= 0) collection.rules[index] = rule; else collection.rules.push(rule); markDirty(); render(); closeModal($("ruleModal")); showToast(index >= 0 ? "Rule updated" : "Rule added"); });
  $("ruleForm").addEventListener("submit", () => { if (!pendingRuleProvenance) return; const target = currentCollection().rules.find(rule => rule.name === $("ruleName").value.trim()); if (target) { target.provenance = pendingRuleProvenance; markDirty(); render(); } pendingRuleProvenance = null; });
  $("enforcementMode").addEventListener("change", event => { currentCollection().mode = event.target.value; markDirty(); render(); showToast(event.target.value === "Enabled" ? "Enforcement enabled for this collection" : "Collection set to audit only"); });
  $("analyzeButton").addEventListener("click", () => $("fileInput").click());
  $("fileInput").addEventListener("change", async event => { const files = [...event.target.files]; if (!files.length) return; $("analysisResults").innerHTML = `<p class="muted">Analyzing ${files.length} file${files.length === 1 ? "" : "s"} locally…</p>`; openModal("analysisModal"); try { const results = await Promise.all(files.slice(0, 20).map(analyzeFile)); $("analysisResults").innerHTML = results.map((result, index) => { const certificateSummary = result.signature?.certificates?.length ? `<div class="certificate-list"><strong>Embedded certificate${result.signature.certificates.length === 1 ? "" : "s"}</strong>${result.signature.certificates.map(cert => `<div class="certificate-item"><span>${esc(cert.subject || "Unnamed certificate")}</span><small>${esc(cert.issuer || "Issuer unavailable")}</small><small>Valid ${esc(cert.validFrom || "unknown")} → ${esc(cert.validTo || "unknown")} · Serial ${esc(cert.serial || "unknown")}</small><small>SHA-256 ${esc(cert.thumbprint)}</small></div>`).join("")}<p class="analysis-note">Publisher proposals use the leaf certificate and parsed product/version fields when available. Trust and revocation are not verified in the browser.</p></div>` : result.signature?.present ? `<p class="analysis-warning">Signature present, but the embedded certificate could not be decoded.</p>` : ""; const versionSummary = result.pe && (result.pe.ProductName || result.pe.OriginalFilename || result.pe.FileVersion) ? `<p class="analysis-note">${esc(result.pe.ProductName || "")} ${esc(result.pe.FileVersion || "")} ${esc(result.pe.OriginalFilename || "")}</p>` : ""; const msiSummary = result.msi?.detected ? `<p class="analysis-note"><strong>MSI metadata</strong> · ${esc(result.msi.title || result.msi.productName || "Untitled package")} ${esc(result.msi.company || result.msi.author || "")} ${esc(result.msi.applicationName || "")} · ${esc(result.msi.parseStatus)}</p>` : ""; const scriptSummary = result.script?.detected ? `<p class="analysis-note"><strong>${esc(result.script.type)}</strong> · ${esc(result.script.encoding)} · ${result.script.lineCount} lines · ${esc(result.script.signatureStatus)} signature${result.script.requires?.length ? ` · ${result.script.requires.length} #requires directive${result.script.requires.length === 1 ? "" : "s"}` : ""}</p>` : ""; const fileSummary = result.script?.detected ? `${esc(result.script.type)} detected · metadata parsed locally` : result.msi?.detected ? "Windows Installer package detected · summary metadata parsed locally" : result.pe ? "PE file detected · Authenticode hash candidate" : "PE header not detected · hash rule unavailable"; const hashLabel = result.script?.detected ? "Script hash candidate (whole-file SHA-256)" : result.msi?.detected ? "MSI hash candidate" : "AppLocker candidate"; return `<article class="analysis-card"><div><strong>${esc(result.name)}</strong><p>${fileSummary} · ${(result.size / 1024).toFixed(1)} KB</p>${versionSummary}${msiSummary}${scriptSummary}<code>Whole-file SHA-256 · ${result.wholeFileSha256}</code>${result.appLockerHash ? `<code>${hashLabel} · ${result.appLockerHash}</code>` : ""}${certificateSummary}</div><div class="analysis-actions"><span class="analysis-status">Browser parsed</span><button class="button button-secondary" data-add-analysis-index="${index}" type="button" ${result.appLockerHash ? "" : "disabled"}>${result.appLockerHash ? `Add ${result.script?.detected ? "Script" : result.msi?.detected ? "MSI" : "hash"} rule` : "Hash unavailable"}</button><button class="button button-secondary" data-add-publisher-index="${index}" type="button" ${result.signature?.certificates?.length ? "" : "disabled"}>${result.signature?.certificates?.length ? "Add publisher rule" : "Certificate required"}</button></div></article>`; }).join(""); results.forEach((result, index) => { window.dispatchEvent(new CustomEvent("policy-studio:evidence", { detail: { result: result, index: index } })); document.querySelector(`[data-add-analysis-index="${index}"]`)?.addEventListener("click", () => addRuleFromFile(result)); document.querySelector(`[data-add-publisher-index="${index}"]`)?.addEventListener("click", () => addPublisherRuleFromFile(result)); }); } catch { $("analysisResults").innerHTML = `<div class="finding warning"><span class="finding-icon">!</span><div><strong>Could not inspect these files</strong><p>The files may be unreadable or malformed. Nothing was uploaded.</p></div></div>`; } event.target.value = ""; });
  $("importButton").addEventListener("click", () => $("importInput").click());
  $("importInput").addEventListener("change", async event => { const file = event.target.files[0]; if (!file) return; if (file.size > 10 * 1024 * 1024) { showToast("XML files are limited to 10 MB"); event.target.value = ""; return; } try { parseXmlFidelity(await file.text()); } catch (error) { showToast(error.message || "Could not import XML"); } event.target.value = ""; });
  $("defaultRulesButton")?.addEventListener("click", openDefaults);
  $("addDefaultsButton")?.addEventListener("click", addDefaults);
 $("exportButton").addEventListener("click", () => { openReviewFidelity(); });
  $("exportButton").addEventListener("click", appendSafetyFindings);
  $("confirmExport").addEventListener("click", downloadPolicy);
  $("downloadReportButton")?.addEventListener("click", downloadValidationReport);
 $("reviewButton").addEventListener("click", openReviewFidelity);
  $("reviewButton").addEventListener("click", appendSafetyFindings);
  $("renameButton").addEventListener("click", () => { const name = prompt("Policy name", state.name); if (name?.trim()) { state.name = name.trim(); markDirty(); render(); } });
  $("newPolicyButton").addEventListener("click", () => { if (confirm("Start a new policy? Your current draft is saved locally.")) { state = newPolicy(); markDirty(); render(); showToast("New policy started"); } });
  $("addCollectionButton").addEventListener("click", () => { const missing = COLLECTIONS.find(c => !state.collections[c.key]); if (!missing) return showToast("All collections are already configured"); state.collections[missing.key] = { mode: "AuditOnly", rules: [] }; state.selectedCollection = missing.key; markDirty(); render(); showToast(`${missing.label} added`); });
  $("dismissNotice").addEventListener("click", () => { sessionStorage.setItem("auditNoticeDismissed", "true"); $("auditNotice").hidden = true; });
  document.querySelectorAll("[data-close-modal]").forEach(button => button.addEventListener("click", () => closeModal(button.closest(".modal-backdrop"))));
  document.querySelectorAll(".modal-backdrop").forEach(backdrop => { backdrop.addEventListener("pointerdown", event => { backdrop.dataset.backdropPointer = event.target === backdrop ? "outside" : "inside"; }); backdrop.addEventListener("click", event => { const started = backdrop.dataset.backdropPointer; delete backdrop.dataset.backdropPointer; if (event.target === backdrop && started === "outside") closeModal(backdrop); }); });
  document.addEventListener("keydown", event => { if (event.key === "Escape" && activeModal) { event.preventDefault(); closeModal(); return; } if (event.key === "Tab" && activeModal) { const focusable = modalFocusables(activeModal); if (!focusable.length) return; const first = focusable[0], last = focusable[focusable.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } } });
  if (new URLSearchParams(location.search).has("test")) {
    const testApi = {
      reset: () => { state = newPolicy(); render(); return JSON.parse(JSON.stringify(state)); },
      importXml: parseXmlFidelity,
      serializeXml: serializePolicyFidelity,
      parseMsiMetadata: payload => parseMsiMetadata(new Uint8Array(payload || [])),
      parseScriptMetadata: scriptMetadataFromText,
      parseAppxManifest: appxManifestMetadata,
      classifyFileName: name => { const fileType = detectPeFileType(name, null); return { fileType, targetCollection: targetCollectionForFile({ fileType }) }; },
      targetCollectionForFile,
      analyzeFixture: payload => analyzeFile(new File([new Uint8Array(payload?.bytes || [])], payload?.name || "fixture.bin")),
     buildValidationReport,
      simulatePolicy,
      semanticDiff,
     appControlFindings,
      safetyFindings,
     snapshot: () => JSON.parse(JSON.stringify(state))
    };
    window.__policyStudioTest = testApi;
    // The fixture harness is hosted in a parent page. A small message bridge
    // keeps the production surface unchanged while allowing the parent to
    // drive the real parser/serializer in the embedded app document.
    window.addEventListener("message", event => {
      if (!event.data || event.data.type !== "policy-studio-test") return;
      const { id, method, payload } = event.data;
      if (!id) return;
      if (typeof testApi[method] !== "function") {
        window.parent.postMessage({ type: "policy-studio-test-result", id, ok: false, error: `Unknown test method: ${method}` }, event.origin || "*");
        return;
      }
      try {
        Promise.resolve(testApi[method](payload)).then(value => {
          window.parent.postMessage({ type: "policy-studio-test-result", id, ok: true, value }, event.origin || "*");
        }).catch(error => {
          window.parent.postMessage({ type: "policy-studio-test-result", id, ok: false, error: error?.message || "Test operation failed" }, event.origin || "*");
        });
      } catch (error) {
        window.parent.postMessage({ type: "policy-studio-test-result", id, ok: false, error: error?.message || "Test operation failed" }, event.origin || "*");
      }
    });
  }
  if ("serviceWorker" in navigator) window.addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(() => {}));
  render(); loadDraft();
})();
