/*
 * Browser-only WDAC/App Control support.
 * This module deliberately keeps WDAC separate from the AppLocker model.
 */
(function (global) {
  'use strict';

  var NS = 'urn:schemas-microsoft-com:sipolicy';
  var RULE_TYPES = Object.freeze({
    HASH: 'hash',
    FILE_NAME: 'file-attribute',
    FILE_PUBLISHER: 'file-publisher',
    SIGNED_VERSION: 'signed-version',
    LEAF_CERTIFICATE: 'leaf-certificate',
    PCA_CERTIFICATE: 'pca-certificate',
    FILE_PATH: 'file-path',
    WHQL: 'whql'
  });

  function text(value) { return value == null ? '' : String(value); }
  function attr(node, name) { return node && node.getAttribute(name) || ''; }
  function children(node, name) {
    if (!node) return [];
    return Array.prototype.filter.call(node.childNodes || [], function (child) {
      return child.nodeType === 1 && (!name || child.localName === name);
    });
  }
  function child(node, name) { return children(node, name)[0] || null; }
  function uid(prefix, value) {
    var input = prefix + ':' + (value || Math.random().toString(36));
    var hash = 2166136261;
    for (var i = 0; i < input.length; i += 1) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return prefix + '-' + ('00000000' + (hash >>> 0).toString(16)).slice(-8);
  }

  function classifyCertificate(signature) {
    signature = signature || {};
    var algorithm = (signature.publicKeyAlgorithm || signature.algorithm || signature.oid || '').toLowerCase();
    var keySize = Number(signature.keySize || signature.bits || 0);
    var kind = 'unknown';
    if (algorithm.indexOf('rsa') >= 0 || algorithm.indexOf('1.2.840.113549.1.1') >= 0) kind = 'rsa';
    else if (algorithm.indexOf('ec') >= 0 || algorithm.indexOf('ecdsa') >= 0 || algorithm.indexOf('1.2.840.10045') >= 0) kind = 'ecc';
    var supported = kind === 'rsa' && (!keySize || keySize <= 4096);
    return { kind: kind, keySize: keySize || null, supported: supported };
  }

  function certificateForEvidence(evidence) {
    var signatures = (evidence && (evidence.signatures || evidence.certificates)) || [];
    return signatures.map(classifyCertificate);
  }

  function hasCompatibleRsa(evidence) {
    return certificateForEvidence(evidence).some(function (item) { return item.kind === 'rsa' && item.supported; });
  }

  function isKernelEvidence(evidence, scenario) {
    var name = text(evidence && (evidence.name || evidence.fileName || evidence.path)).toLowerCase();
    return scenario === 'kernel' || /\.sys$/.test(name) || evidence && evidence.kernelMode === true;
  }

  function validateRule(evidence, ruleType, scenario, options) {
    options = options || {};
    var findings = [];
    var signatures = certificateForEvidence(evidence);
    if (['leaf-certificate', 'pca-certificate', 'file-publisher', 'signed-version', 'whql'].indexOf(ruleType) >= 0) {
      if (!hasCompatibleRsa(evidence)) {
        findings.push({ code: 'WDAC_SIGNER_ECC_UNSUPPORTED', severity: 'error', blocking: true,
          message: 'WDAC signer rules require a supported RSA certificate; ECC/ECDSA-only evidence cannot be used.',
          remediation: 'Use a verified hash or file-attribute rule, or select a compatible RSA signature from a dual-signed file.' });
      }
      if (signatures.some(function (item) { return item.kind === 'rsa' && !item.supported; })) {
        findings.push({ code: 'WDAC_SIGNER_RSA_KEY_TOO_LARGE', severity: 'error', blocking: true,
          message: 'This RSA certificate exceeds WDAC’s 4096-bit signer limit.', remediation: 'Use another compatible signature or a hash/file-attribute rule.' });
      }
    }
    if (ruleType === 'file-path' && isKernelEvidence(evidence, scenario)) {
      findings.push({ code: 'WDAC_KERNEL_PATH_UNSUPPORTED', severity: 'error', blocking: true,
        message: 'WDAC FilePath rules apply only to user-mode binaries and cannot authorize kernel drivers.',
        remediation: 'Use a verified hash or an appropriate RSA/WHQL signer rule.' });
    }
    if (ruleType === 'file-path' && options.userWritable) {
      findings.push({ code: 'WDAC_USER_WRITABLE_PATH', severity: 'warning', blocking: false,
        message: 'This path may be writable by a non-administrator.', remediation: 'Prefer signer, file-attribute, or hash rules where possible.' });
    }
    if ((ruleType === 'file-attribute' || ruleType === 'file-publisher') && !(evidence && (evidence.originalFileName || evidence.fileName || evidence.internalName || evidence.productName))) {
      findings.push({ code: 'WDAC_FILE_ATTRIBUTE_MISSING', severity: 'error', blocking: true,
        message: 'No usable PE file attribute was found for this rule.', remediation: 'Analyze a PE with version resources or choose a hash rule.' });
    }
    return findings;
  }

  function createPolicy(options) {
    options = options || {};
    var id = options.policyId || ('{' + cryptoRandomGuid() + '}');
    return {
      engine: 'wdac',
      id: id,
      name: options.name || 'Policy Studio WDAC Policy',
      version: options.version || '1.0.0.0',
      mode: options.mode || 'audit',
      scope: options.scope || 'user-and-kernel',
      basePolicyId: options.basePolicyId || '',
      rules: [],
      signers: [],
      fileAttributes: [],
      unknownXml: []
    };
  }

  function cryptoRandomGuid() {
    var bytes = new Uint8Array(16);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(bytes);
    else for (var i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    var hex = Array.prototype.map.call(bytes, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
  }

  function parseXml(xml) {
    var doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml, 'application/xml') : xml;
    if (!doc || doc.getElementsByTagName('parsererror').length || !doc.documentElement || doc.documentElement.localName !== 'SiPolicy') {
      throw new Error('Not a valid WDAC SiPolicy XML document.');
    }
    var root = doc.documentElement;
    function val(name, fallback) { var node = child(root, name); return attr(root, name) || (node ? text(node.textContent).trim() : '') || (fallback || ''); }
    var p = createPolicy({ policyId: val('PolicyID'), name: val('PolicyName', 'Imported WDAC policy'), version: val('VersionEx', '1.0.0.0') });
    p.basePolicyId = val('BasePolicyID');
    p.policyTypeId = val('PolicyTypeID');
    p.platformId = val('PlatformID');
    var rules = child(root, 'Rules');
    children(rules).forEach(function (node) {
      var option = attr(node, 'Option') || text(child(node, 'Option') ? child(node, 'Option').textContent : node.textContent).trim();
      if (option) p.rules.push({ id: attr(node, 'ID') || uid('rule', option), type: 'option', option: option });
    });
    var fileRules = child(root, 'FileRules');
    children(fileRules).forEach(function (node) {
      var id = attr(node, 'ID') || uid('file-rule', node.textContent);
      if (node.localName === 'FileAttrib') {
        p.fileAttributes.push({ id: id, type: RULE_TYPES.FILE_NAME, friendlyName: attr(node, 'FriendlyName'), fileName: attr(node, 'FileName'), originalFileName: attr(node, 'FileName'), internalName: attr(node, 'InternalName'), productName: attr(node, 'ProductName'), fileDescription: attr(node, 'FileDescription'), minVersion: attr(node, 'MinimumFileVersion'), maxVersion: attr(node, 'MaximumFileVersion'), hash: attr(node, 'Hash'), signerId: attr(node, 'SignerId') || attr(node, 'SignerID') });
      } else if (node.localName === 'Hash') {
        p.rules.push({ id: id, type: RULE_TYPES.HASH, name: attr(node, 'FriendlyName'), hash: attr(node, 'Hash'), scenario: 'user' });
      } else if (node.localName === 'Allow' && attr(node, 'FilePath')) {
        p.rules.push({ id: id, type: RULE_TYPES.FILE_PATH, name: attr(node, 'FriendlyName'), path: attr(node, 'FilePath'), scenario: 'user' });
      }
    });
    var signers = child(root, 'Signers');
    children(signers).forEach(function (node) {
      var certRoot = child(node, 'CertRoot'), certPublisher = child(node, 'CertPublisher'), certIssuer = child(node, 'CertIssuer');
      p.signers.push({ id: attr(node, 'ID') || uid('signer', node.textContent), name: attr(node, 'Name') || attr(node, 'FriendlyName'), certRoot: attr(node, 'CertRoot') || attr(certRoot, 'Value'), certRootType: attr(certRoot, 'Type'), certPublisher: attr(node, 'CertPublisher') || attr(certPublisher, 'Value'), certIssuer: attr(node, 'CertIssuer') || attr(certIssuer, 'Value'), certOemID: attr(node, 'CertOemID') });
    });
    var scenarios = child(root, 'SigningScenarios');
    children(scenarios).forEach(function (scenario) {
      var valueNumber = attr(scenario, 'Value');
      var scenarioName = valueNumber === '131' ? 'kernel' : 'user';
      var products = child(scenario, 'ProductSigners');
      var refs = child(products, 'FileRulesRef');
      children(refs).forEach(function (ref) { var rule = p.rules.find(function (item) { return item.id === attr(ref, 'RuleID'); }); if (rule) rule.scenario = scenarioName; var file = p.fileAttributes.find(function (item) { return item.id === attr(ref, 'RuleID'); }); if (file) file.scenario = scenarioName; });
    });
    p.scope = children(scenarios).some(function (node) { return attr(node, 'Value') === '131'; }) && children(scenarios).some(function (node) { return attr(node, 'Value') === '12'; }) ? 'user-and-kernel' : 'kernel-only';
    p.mode = p.rules.some(function (item) { return item.option === 'Enabled:Enforce'; }) ? 'enforce' : 'audit';
    return p;
  }

  function element(doc, parent, name, attrs) {
    var node = doc.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (key) { if (attrs[key] !== '' && attrs[key] != null) node.setAttribute(key, attrs[key]); });
    parent.appendChild(node); return node;
  }

  function serialize(policy) {
    if (!policy || policy.engine !== 'wdac') throw new Error('Expected a WDAC policy document.');
    var doc = document.implementation.createDocument(NS, 'SiPolicy', null);
    var root = doc.documentElement;
    root.setAttribute('xmlns', NS);
    function value(name, fallback) {
      var result = policy[name];
      return result == null || result === '' ? fallback : result;
    }
    element(doc, root, 'VersionEx', value('version', '1.0.0.0'));
    element(doc, root, 'PolicyID', value('id', '{' + cryptoRandomGuid() + '}'));
    element(doc, root, 'BasePolicyID', policy.basePolicyId || value('id', '{' + cryptoRandomGuid() + '}'));
    if (policy.platformId) element(doc, root, 'PlatformID', policy.platformId);
    var rules = element(doc, root, 'Rules');
    function option(name) { var rule = element(doc, rules, 'Rule', {}); element(doc, rule, 'Option', name); }
    option(policy.mode === 'enforce' ? 'Enabled:Enforce' : 'Enabled:Audit Mode');
    if (policy.scope !== 'kernel-only') option('Enabled:UMCI');
    var fileRules = element(doc, root, 'FileRules');
    var refs = [];
    (policy.fileAttributes || []).forEach(function (item) {
      var id = item.id || uid('ID_FILEATTRIB', JSON.stringify(item));
      item.id = id;
      refs.push(id);
      element(doc, fileRules, 'FileAttrib', { ID: id, FriendlyName: item.friendlyName || item.originalFileName || item.fileName || 'File attribute', FileName: item.originalFileName || item.fileName, InternalName: item.internalName, ProductName: item.productName, FileDescription: item.fileDescription, MinimumFileVersion: item.minVersion, MaximumFileVersion: item.maxVersion });
    });
    (policy.rules || []).forEach(function (item) {
      if (item.type === RULE_TYPES.FILE_PATH) {
        var id = item.id || uid('ID_ALLOW_PATH', item.path);
        item.id = id; refs.push(id);
        element(doc, fileRules, 'Allow', { ID: id, FriendlyName: item.friendlyName || item.name || 'User-mode path', FilePath: item.path });
      } else if (item.type === RULE_TYPES.HASH) {
        var hashId = item.id || uid('ID_ALLOW_HASH', item.hash);
        item.id = hashId; refs.push(hashId);
        element(doc, fileRules, 'Hash', { ID: hashId, FriendlyName: item.friendlyName || item.name || 'File hash', Hash: item.hash });
      }
    });
    var signers = element(doc, root, 'Signers');
    (policy.signers || []).forEach(function (item) {
      var signer = element(doc, signers, 'Signer', { ID: item.id || uid('ID_SIGNER', item.name), Name: item.name || 'Signer' });
      if (item.certRoot) element(doc, signer, 'CertRoot', { Type: item.certRootType || 'TBS', Value: item.certRoot });
      if (item.certPublisher) element(doc, signer, 'CertPublisher', { Value: item.certPublisher });
      if (item.certIssuer) element(doc, signer, 'CertIssuer', { Value: item.certIssuer });
    });
    var scenarios = element(doc, root, 'SigningScenarios');
    function scenario(id, valueNumber, includeRefs) {
      var node = element(doc, scenarios, 'SigningScenario', { Value: valueNumber, ID: id });
      var products = element(doc, node, 'ProductSigners', {});
      if (includeRefs && refs.length) {
        var fileRefs = element(doc, products, 'FileRulesRef', {});
        refs.forEach(function (ruleId) { element(doc, fileRefs, 'FileRuleRef', { RuleID: ruleId }); });
      }
      if (includeRefs && policy.signers && policy.signers.length) {
        var allowed = element(doc, products, 'AllowedSigners', {});
        policy.signers.forEach(function (signer) { element(doc, allowed, 'AllowedSigner', { SignerId: signer.id }); });
      }
    }
    if (policy.scope !== 'kernel-only') scenario('ID_SIGNINGSCENARIO_USERMODE', '12', true);
    if (policy.scope !== 'user-only') scenario('ID_SIGNINGSCENARIO_KERNELMODE', '131', false);
    return '<?xml version="1.0" encoding="utf-8"?>\n' + new XMLSerializer().serializeToString(doc);
  }

  function validatePolicy(policy) {
    var findings = [];
    if (!policy || policy.engine !== 'wdac') return [{ code: 'WDAC_INVALID_DOCUMENT', severity: 'error', blocking: true, message: 'This is not a WDAC policy document.' }];
    var ids = {};
    (policy.fileAttributes || []).forEach(function (item) { if (ids[item.id]) findings.push({ code: 'WDAC_DUPLICATE_ID', severity: 'error', blocking: true, message: 'Duplicate WDAC file attribute ID: ' + item.id }); ids[item.id] = true; if (item.type === RULE_TYPES.FILE_PATH && policy.scope === 'kernel-only') findings.push({ code: 'WDAC_KERNEL_PATH_UNSUPPORTED', severity: 'error', blocking: true, message: 'A kernel-only policy cannot contain a FilePath rule.' }); });
    (policy.rules || []).forEach(function (item) { if (item.type === RULE_TYPES.FILE_PATH && (policy.scope === 'kernel-only' || item.scenario === 'kernel')) findings.push({ code: 'WDAC_KERNEL_PATH_UNSUPPORTED', severity: 'error', blocking: true, message: 'A WDAC FilePath rule cannot be referenced by the kernel signing scenario.' }); });
    (policy.signers || []).forEach(function (item) { if (!item.id) findings.push({ code: 'WDAC_SIGNER_ID_MISSING', severity: 'error', blocking: true, message: 'WDAC signer is missing an ID.' }); });
    if (policy.mode !== 'audit') findings.push({ code: 'WDAC_ENFORCEMENT_REVIEW', severity: 'warning', blocking: false, message: 'Enforcement mode can block software; validate in Audit mode first.' });
    return findings;
  }

  global.WdacPolicy = { NS: NS, RULE_TYPES: RULE_TYPES, createPolicy: createPolicy, parseXml: parseXml, serialize: serialize, validatePolicy: validatePolicy, validateRule: validateRule, classifyCertificate: classifyCertificate };

  function installUi() {
    if (!global.document || document.documentElement.dataset.wdacUi === 'installed') return;
    document.documentElement.dataset.wdacUi = 'installed';
    var target = document.querySelector('[data-policy-engine]') || document.querySelector('main') || document.body;
    if (!target) return;
    var panel = document.createElement('section'); panel.className = 'wdac-panel'; panel.setAttribute('aria-labelledby', 'wdac-heading');
    panel.innerHTML = '<div class="wdac-panel__header"><div><p class="eyebrow">Policy engine</p><h2 id="wdac-heading">WDAC / App Control</h2><p class="muted">Create device-wide policies with evidence-aware safety checks.</p></div><label class="field"><span>Engine</span><select id="wdac-engine"><option value="applocker">AppLocker</option><option value="wdac">WDAC / App Control</option></select></label></div><div id="wdac-controls" hidden><div class="wdac-grid"><label class="field"><span>Scope</span><select id="wdac-scope"><option value="user-and-kernel">User mode + kernel</option><option value="kernel-only">Kernel only</option></select></label><label class="field"><span>Mode</span><select id="wdac-mode"><option value="audit">Audit (recommended)</option><option value="enforce">Enforced</option></select></label><label class="field"><span>Rule type</span><select id="wdac-rule-type"><option value="hash">Hash</option><option value="file-attribute">File attributes</option><option value="file-publisher">File publisher</option><option value="leaf-certificate">Leaf certificate</option><option value="pca-certificate">PCA certificate</option><option value="file-path">User-mode file path</option></select></label></div><div class="wdac-callout" role="note"><strong>Safety checks enabled.</strong><span id="wdac-status">Choose evidence to validate ECC certificates, file attributes, and kernel path rules.</span></div></div>';
    target.appendChild(panel);
    var engine = panel.querySelector('#wdac-engine'), controls = panel.querySelector('#wdac-controls'), scope = panel.querySelector('#wdac-scope'), rule = panel.querySelector('#wdac-rule-type'), status = panel.querySelector('#wdac-status');
    function refresh() { var active = engine.value === 'wdac'; controls.hidden = !active; if (active && rule.value === 'file-path' && scope.value === 'kernel-only') status.textContent = 'Blocked: FilePath rules cannot authorize kernel-mode drivers.'; else status.textContent = active ? 'WDAC policies are device-wide. Audit mode is recommended for initial validation.' : ''; }
    engine.addEventListener('change', refresh); scope.addEventListener('change', refresh); rule.addEventListener('change', refresh); refresh();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installUi); else installUi();
}(window));

(function () {
  'use strict';
  function installWdacActions() {
    var panel = document.querySelector('.wdac-panel');
    if (!panel || panel.dataset.actionsInstalled === 'true' || !window.WdacPolicy) return;
    panel.dataset.actionsInstalled = 'true';
    var controls = panel.querySelector('#wdac-controls');
    if (!controls) return;
    var actions = document.createElement('div');
    actions.className = 'wdac-actions';
    actions.innerHTML = '<div class="wdac-action-row"><button type="button" class="button button-secondary" id="wdac-new">New WDAC policy</button><button type="button" class="button button-secondary" id="wdac-import">Import WDAC XML</button><button type="button" class="button button-secondary" id="wdac-add-attribute">Add file attribute</button><button type="button" class="button button-primary" id="wdac-export">Export WDAC XML</button><input id="wdac-import-input" class="visually-hidden" type="file" accept=".xml,text/xml,application/xml"></div><div id="wdac-attribute-list" class="wdac-attribute-list" aria-live="polite"></div>';
    controls.appendChild(actions);
    var state = window.WdacPolicy.createPolicy();
    var status = panel.querySelector('#wdac-status');
    var scope = panel.querySelector('#wdac-scope');
    var mode = panel.querySelector('#wdac-mode');
    var type = panel.querySelector('#wdac-rule-type');
    var list = panel.querySelector('#wdac-attribute-list');    window.__policyStudioWdacAddEvidence = function (evidence, requestedType) {
      var pe = evidence && evidence.pe || {};
      if (requestedType === 'hash') {
        if (!evidence || !evidence.appLockerHash) { setStatus('Blocked: this evidence has no reusable hash.', true); return false; }
        state.rules.push({ id: 'ID_ALLOW_HASH_' + Date.now().toString(36), type: RULE_TYPES.HASH, name: evidence.name + ' hash', hash: evidence.appLockerHash, scenario: 'user' });
        sync(); setStatus('Hash rule reused from the local evidence library.', false); return true;
      }

      var certificates = evidence && evidence.signature && evidence.signature.certificates || [];
      if (requestedType === 'signer') {
        var cert = certificates.find(function (item) { var c = window.WdacPolicy.classifyCertificate(item); return c.kind === 'rsa' && c.supported; }) || certificates[0];
        var classified = window.WdacPolicy.classifyCertificate(cert || {});
        if (!cert || !classified.supported) { setStatus('Blocked: this evidence has no supported RSA certificate for a WDAC signer rule.', true); return false; }
        var signerId = 'ID_SIGNER_' + Date.now().toString(36);
        state.signers.push({ id: signerId, name: cert.subject || evidence.name || 'RSA signer', certRoot: cert.tbsHash || cert.thumbprint || '', certPublisher: cert.subject || '', certIssuer: cert.issuer || '' });
        sync(); setStatus('RSA signer added. Certificate trust and revocation still require Windows validation.', false); return true;
      }
      if (!pe.OriginalFilename && !pe.OriginalFileName && !evidence.name) { setStatus('Blocked: no usable file attribute was found in the analyzed evidence.', true); return false; }
      state.fileAttributes.push({ id: 'ID_FILEATTRIB_' + Date.now().toString(36), type: 'file-attribute', friendlyName: evidence.name + ' attributes', originalFileName: pe.OriginalFilename || pe.OriginalFileName || evidence.name, fileName: pe.OriginalFilename || pe.OriginalFileName || evidence.name, internalName: pe.InternalName || '', productName: pe.ProductName || '', fileDescription: pe.FileDescription || '', minVersion: pe.FileVersion || '', hash: evidence.appLockerHash || '' });
      sync(); setStatus('File attributes added from local analysis. Verify metadata before enforcement.', false); return true;
    };
    function setStatus(message, error) {
      status.textContent = message;
      status.parentElement.classList.toggle('wdac-error', Boolean(error));
    }
    function sync() {
      state.scope = scope.value;
      state.mode = mode.value;
      list.innerHTML = state.fileAttributes.length ? state.fileAttributes.map(function (item, index) {
        return '<div class="wdac-attribute"><strong>' + (item.originalFileName || item.fileName || 'Unnamed file') + '</strong><span>' + (item.productName || 'No product') + (item.minVersion ? ' · ' + item.minVersion : '') + '</span><button type="button" class="text-button" data-remove-attribute="' + index + '">Remove</button></div>';
      }).join('') : '<p class="muted">No file attributes yet. Add one from analyzed metadata or enter a verified attribute manually.</p>';
      list.querySelectorAll('[data-remove-attribute]').forEach(function (button) {
        button.addEventListener('click', function () { state.fileAttributes.splice(Number(button.dataset.removeAttribute), 1); sync(); });
      });
    }
    panel.querySelector('#wdac-new').addEventListener('click', function () {
      state = window.WdacPolicy.createPolicy({ scope: scope.value, mode: mode.value });
      sync(); setStatus('New unsigned WDAC base policy created in Audit mode.', false);
    });
    panel.querySelector('#wdac-add-attribute').addEventListener('click', function () {
      var fileName = window.prompt('Original file name (for example, Contoso.exe):', '');
      if (!fileName) return;
      var product = window.prompt('Product name (optional):', '');
      var version = window.prompt('Minimum file version (optional):', '');
      state.fileAttributes.push({ id: 'ATTR-' + Date.now().toString(36), type: 'file-attribute', originalFileName: fileName, fileName: fileName, productName: product || '', minVersion: version || '' });
      sync(); setStatus('File attribute added. Verify it against the source binary before enforcement.', false);
    });
    panel.querySelector('#wdac-import').addEventListener('click', function () { panel.querySelector('#wdac-import-input').click(); });
    panel.querySelector('#wdac-import-input').addEventListener('change', async function (event) {
      var file = event.target.files && event.target.files[0];
      if (!file) return;
      try {
        state = window.WdacPolicy.parseXml(await file.text());
        scope.value = state.scope || 'user-and-kernel'; mode.value = state.mode || 'audit';
        sync(); setStatus('WDAC XML imported. Review compatibility findings before export.', false);
      } catch (error) { setStatus(error.message || 'Could not import WDAC XML.', true); }
      event.target.value = '';
    });
    panel.querySelector('#wdac-export').addEventListener('click', function () {
      state.scope = scope.value; state.mode = mode.value;
      var findings = window.WdacPolicy.validatePolicy(state);
      var blockers = findings.filter(function (finding) { return finding.blocking; });
      if (blockers.length) { setStatus(blockers.map(function (finding) { return finding.message; }).join(' '), true); return; }
      var xml = window.WdacPolicy.serialize(state);
      var link = document.createElement('a');
      link.href = URL.createObjectURL(new Blob([xml], { type: 'application/xml;charset=utf-8' }));
      link.download = (state.name || 'wdac-policy').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') + '.xml';
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(link.href);
      setStatus('WDAC XML exported. Convert and validate it with Windows tooling before deployment.', false);
    });
    scope.addEventListener('change', function () { state.scope = scope.value; sync(); });
    mode.addEventListener('change', function () { state.mode = mode.value; });
    type.addEventListener('change', function () { if (type.value === 'file-path' && scope.value === 'kernel-only') setStatus('Blocked: FilePath rules cannot authorize kernel-mode drivers.', true); });
    sync();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installWdacActions); else installWdacActions();
}());

(function () {
  'use strict';
  window.addEventListener('policy-studio:evidence', function (event) {
    var detail = event.detail || {};
    var result = detail.result || detail;
    var index = detail.index;
    var card = document.querySelector('[data-add-analysis-index="' + index + '"]');
    if (!card || !window.__policyStudioWdacAddEvidence) return;
    var parent = card.closest('.analysis-card');
    if (!parent || parent.dataset.wdacActions === 'true') return;
    parent.dataset.wdacActions = 'true';
    var actions = parent.querySelector('.analysis-actions');
    if (!actions) return;
    var pe = result.pe || {};
    var certs = result.signature && result.signature.certificates || [];
    if (result.pe && (pe.OriginalFilename || pe.OriginalFileName || result.name)) {
      var attributeButton = document.createElement('button');
      attributeButton.type = 'button'; attributeButton.className = 'button button-secondary'; attributeButton.textContent = 'Add WDAC file attributes';
      attributeButton.addEventListener('click', function () {
        var engine = document.querySelector('#wdac-engine');
        if (engine) { engine.value = 'wdac'; engine.dispatchEvent(new Event('change')); }
        window.__policyStudioWdacAddEvidence(result, 'attribute');
      });
      actions.appendChild(attributeButton);
    }
    if (certs.length) {
      var signerButton = document.createElement('button');
      signerButton.type = 'button'; signerButton.className = 'button button-secondary'; signerButton.textContent = 'Add WDAC RSA signer';
      signerButton.addEventListener('click', function () {
        var engine = document.querySelector('#wdac-engine');
        if (engine) { engine.value = 'wdac'; engine.dispatchEvent(new Event('change')); }
        window.__policyStudioWdacAddEvidence(result, 'signer');
      });
      actions.appendChild(signerButton);
    }
  });
}());

(function () {
  'use strict';
  var KEY = 'policyStudio.evidenceLibrary.v1';
  function escapeHtml(value) { return String(value == null ? '' : value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function load() {
    try { var value = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(value) ? value : []; } catch (_) { return []; }
  }
  function save(items) {
    try { localStorage.setItem(KEY, JSON.stringify(items.slice(0, 100))); return true; } catch (_) { return false; }
  }
  function classify(result) {
    var pe = result.pe || {};
    var certs = result.signature && result.signature.certificates || [];
    var types = [];
    if (result.appLockerHash) types.push('hash');
    if (result.pe && (pe.OriginalFilename || pe.OriginalFileName || result.name)) types.push('file-attribute');
    if (certs.length) {
      types.push('file-publisher', 'leaf-certificate', 'pca-certificate');
      if (certs.some(function (cert) { var c = window.WdacPolicy.classifyCertificate(cert); return c.kind === 'rsa' && c.supported; })) types.push('RSA signer');
      if (certs.some(function (cert) { return window.WdacPolicy.classifyCertificate(cert).kind === 'ecc'; })) types.push('ECC signer blocked');
    }
    if (result.msi && result.msi.detected) types.push('MSI metadata');
    if (result.script && result.script.detected) types.push('script metadata');
    if (result.appx) types.push('AppX/MSIX metadata');
    return types;
  }
  function toEntry(result) {
    var pe = result.pe || {};
    return { id: result.wholeFileSha256 || result.appLockerHash || (result.name + ':' + result.size), name: result.name, size: result.size, fileType: result.fileType || 'unknown', seenAt: new Date().toISOString(), wholeFileSha256: result.wholeFileSha256 || '', appLockerHash: result.appLockerHash || '', hashBasis: result.hashBasis || '', matchingTypes: classify(result), pe: { OriginalFilename: pe.OriginalFilename || pe.OriginalFileName || '', InternalName: pe.InternalName || '', ProductName: pe.ProductName || '', FileDescription: pe.FileDescription || '', FileVersion: pe.FileVersion || '' }, msi: result.msi ? { title: result.msi.title || '', productName: result.msi.productName || '', company: result.msi.company || '' } : null, script: result.script ? { type: result.script.type || '', encoding: result.script.encoding || '', signatureStatus: result.script.signatureStatus || '' } : null, appx: result.appx ? { name: result.appx.name || result.appx.displayName || '', publisher: result.appx.publisher || '', version: result.appx.version || '' } : null, signature: result.signature ? { certificates: (result.signature.certificates || []).map(function (cert) { return { subject: cert.subject || '', issuer: cert.issuer || '', thumbprint: cert.thumbprint || '', tbsHash: cert.tbsHash || '', publicKeyAlgorithm: cert.publicKeyAlgorithm || cert.algorithm || '', keySize: cert.keySize || 0 }; }) } : { certificates: [] } };
  }
  function installLibrary() {
    var panel = document.querySelector('.wdac-panel');
    if (!panel || panel.dataset.libraryInstalled === 'true' || !window.WdacPolicy) return;
    var controls = panel.querySelector('#wdac-controls');
    if (!controls) return;
    panel.dataset.libraryInstalled = 'true';
    var section = document.createElement('section');
    section.className = 'wdac-library';
    section.setAttribute('aria-labelledby', 'wdac-library-title');
    section.innerHTML = '<div class="wdac-library-header"><div><h3 id="wdac-library-title">Local evidence library</h3><p class="muted">Metadata only—selected file bytes are never stored. Reuse previously analyzed files across policies.</p></div><button type="button" class="text-button" id="wdac-library-clear">Clear library</button></div><div id="wdac-library-list" aria-live="polite"></div>';
    controls.appendChild(section);
    var list = section.querySelector('#wdac-library-list');
    function render() {
      var items = load();
      if (!items.length) { list.innerHTML = '<p class="muted">No analyzed files saved yet. Analyze a file to add its metadata here.</p>'; return; }
      list.innerHTML = items.map(function (item) {
        var kinds = (item.matchingTypes || []).map(function (kind) { return '<span class="wdac-tag">' + escapeHtml(kind) + '</span>'; }).join('');
        var actions = '';
        if (item.appLockerHash) actions += '<button type="button" class="text-button" data-library-action="hash" data-library-id="' + encodeURIComponent(item.id) + '">Reuse hash</button>';
        if (item.pe && item.pe.OriginalFilename) actions += '<button type="button" class="text-button" data-library-action="attribute" data-library-id="' + encodeURIComponent(item.id) + '">Reuse attributes</button>';
        if (item.signature && item.signature.certificates && item.signature.certificates.length) actions += '<button type="button" class="text-button" data-library-action="signer" data-library-id="' + encodeURIComponent(item.id) + '">Reuse RSA signer</button>';
        return '<article class="wdac-library-item"><div><strong>' + escapeHtml(item.name) + '</strong><small>' + escapeHtml(item.fileType) + ' · ' + Math.max(0, Math.round((item.size || 0) / 1024)) + ' KB</small><div class="wdac-tags">' + kinds + '</div></div><div class="wdac-library-actions">' + actions + '</div></article>';
      }).join('');
      list.querySelectorAll('[data-library-action]').forEach(function (button) {
        button.addEventListener('click', function () {
          var item = items.find(function (entry) { return entry.id === decodeURIComponent(button.dataset.libraryId); });
          if (!item || !window.__policyStudioWdacAddEvidence) return;
          var engine = panel.querySelector('#wdac-engine'); if (engine) { engine.value = 'wdac'; engine.dispatchEvent(new Event('change')); }
          window.__policyStudioWdacAddEvidence(item, button.dataset.libraryAction);
        });
      });
    }
    panel.querySelector('#wdac-library-clear').addEventListener('click', function () { if (window.confirm('Clear the local evidence library?')) { try { localStorage.removeItem(KEY); } catch (_) {} render(); } });
    window.addEventListener('policy-studio:evidence', function (event) {
      var detail = event.detail || {}, result = detail.result || detail;
      var entry = toEntry(result), items = load(), existing = items.findIndex(function (item) { return item.id === entry.id; });
      if (existing >= 0) items.splice(existing, 1);
      items.unshift(entry);
      if (!save(items)) {
        var status = panel.querySelector('#wdac-status');
        if (status) status.textContent = 'Local storage is unavailable; this browser session cannot retain the evidence library.';
      }
      render();
    });
    render();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installLibrary); else installLibrary();
}());
