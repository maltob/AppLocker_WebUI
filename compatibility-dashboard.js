(function (global) {
  "use strict";
  const APP_KEY = "applocker-policy-studio-fallback";
  const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const clean = value => String(value || "").trim().toLowerCase().replace(/^0x/, "");
  const appRules = policy => Object.entries(policy?.collections || {}).flatMap(([collection, value]) => (value.rules || []).map(rule => ({ ...rule, engine: "AppLocker", collection })));
  const wdacRules = policy => [...(policy?.rules || []).filter(rule => rule.type !== "option").map(rule => ({ ...rule, engine: "WDAC" })), ...(policy?.fileAttributes || []).map(rule => ({ ...rule, engine: "WDAC" })), ...(policy?.signers || []).map(rule => ({ ...rule, type: rule.type || "signer", engine: "WDAC" }))];
  function identity(rule) {
    if (rule.kind === "hash" || rule.type === "hash") return ["hash", clean(rule.condition?.data || rule.hash)];
    if (rule.kind === "path" || rule.type === "file-path") return ["path", clean(rule.condition?.path || rule.path).replace(/\//g, "\\")];
    if (rule.kind === "publisher") return ["publisher", clean(rule.condition?.publisher), clean(rule.condition?.product), clean(rule.condition?.binary)];
    if (rule.type === "signer" || rule.certPublisher) return ["publisher", clean(rule.certPublisher || rule.name), "*", "*"];
    if (rule.type === "file-attribute") return ["attribute", clean(rule.productName), clean(rule.originalFileName || rule.fileName)];
    return [rule.kind || rule.type || "unknown", clean(rule.id || rule.name)];
  }
  const label = rule => rule.name || rule.friendlyName || rule.originalFileName || rule.fileName || rule.type || "Unnamed rule";
  function compatible(app, wdac) { const a = identity(app), w = identity(wdac); return a[0] === w[0] && ((a[0] === "hash" || a[0] === "path") ? Boolean(a[1] && a[1] === w[1]) : a[0] === "publisher" && Boolean(a[1] && a[1] === w[1])); }
  function related(app, wdac) { if (compatible(app, wdac)) return true; const a = identity(app), w = identity(wdac), an = clean(label(app)), wn = clean(label(wdac)); return a[0] === w[0] && (Boolean(an && wn && (an.includes(wn) || wn.includes(an))) || Boolean(a[1] && a[1] === w[1])); }
  function assess(appPolicy, wdacPolicy) {
    const apps = appRules(appPolicy), wdacs = wdacRules(wdacPolicy), used = new Set(), synchronized = [], divergent = [], noEquivalent = [];
    apps.forEach(app => { const exact = wdacs.findIndex((rule, index) => !used.has(index) && compatible(app, rule)); if (exact >= 0) { used.add(exact); synchronized.push({ app, wdac: wdacs[exact] }); return; } const near = wdacs.findIndex((rule, index) => !used.has(index) && related(app, rule)); if (near >= 0) { used.add(near); divergent.push({ app, wdac: wdacs[near] }); } else noEquivalent.push({ rule: app, missing: "WDAC" }); });
    wdacs.forEach((rule, index) => { if (!used.has(index)) noEquivalent.push({ rule, missing: "AppLocker" }); });
    const unsafe = (appPolicy?.importIssues || []).map(message => ({ engine: "AppLocker", severity: "warning", message }));
    if (wdacPolicy && global.WdacPolicy) global.WdacPolicy.validatePolicy(wdacPolicy).forEach(item => unsafe.push({ ...item, engine: "WDAC" }));
    return { synchronized, noEquivalent, divergent, unsafe, counts: { synchronized: synchronized.length, noEquivalent: noEquivalent.length, divergent: divergent.length, unsafe: unsafe.length } };
  }
  function loadAppPolicy() { try { return global.__policyStudioGetState?.() || JSON.parse(localStorage.getItem(APP_KEY) || "null"); } catch { return null; } }
  function loadWdacPolicy() { try { return global.__policyStudioWdacGetState?.() || JSON.parse(sessionStorage.getItem("policyStudio.wdac.session") || "null"); } catch { return null; } }
  function rows(items, empty, format) { return items.length ? items.map(format).join("") : '<p class="compat-dashboard-empty">' + esc(empty) + "</p>"; }
  function render() {
    const root = document.querySelector("#compatibilityDashboard"); if (!root) return; const report = assess(loadAppPolicy(), loadWdacPolicy());
    root.innerHTML = '<div class="compat-summary" aria-label="Compatibility summary">' + [["Synchronized", report.counts.synchronized, "good"], ["No equivalent", report.counts.noEquivalent, "neutral"], ["Divergent", report.counts.divergent, "warning"], ["Unsafe / review", report.counts.unsafe, "danger"]].map(item => '<div class="compat-metric ' + item[2] + '"><strong>' + item[1] + '</strong><span>' + item[0] + '</span></div>').join("") + "</div>" +
      '<div class="compat-groups"><details open><summary>Synchronized rules <span>' + report.counts.synchronized + '</span></summary>' + rows(report.synchronized, "No rule mappings are synchronized yet.", pair => '<div class="compat-row"><strong>' + esc(label(pair.app)) + '</strong><small>' + esc(identity(pair.app)[0]) + ' matches in both engines</small></div>') + '</details>' +
      '<details open><summary>No equivalent <span>' + report.counts.noEquivalent + '</span></summary>' + rows(report.noEquivalent, "Every rule has an equivalent.", item => '<div class="compat-row"><strong>' + esc(label(item.rule)) + '</strong><small>' + esc(item.rule.engine) + ' · No matching ' + esc(item.missing) + ' method</small></div>') + '</details>' +
      '<details><summary>Divergent mappings <span>' + report.counts.divergent + '</span></summary>' + rows(report.divergent, "No divergent mappings detected.", pair => '<div class="compat-row"><strong>' + esc(label(pair.app)) + '</strong><small>AppLocker and WDAC values differ; review before deployment.</small></div>') + '</details>' +
      '<details><summary>Unsupported or unsafe <span>' + report.counts.unsafe + '</span></summary>' + rows(report.unsafe, "No unsupported or unsafe configurations detected.", item => '<div class="compat-row compat-row-warning"><strong>' + esc(item.engine) + ' · ' + esc(item.code || item.severity || "Review") + '</strong><small>' + esc(item.message) + '</small></div>') + "</details></div>";
  }
  global.PolicyCompatibilityDashboard = { assess, identity, render };
  ["policy-studio:policy-change", "policy-studio:wdac-change", "storage"].forEach(name => global.addEventListener(name, render));
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", render) : render();
}(window));
