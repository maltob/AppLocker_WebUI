(function () {
  "use strict";
  const KEY = "policyStudio.evidenceLibrary.v1";
  const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const load = () => { try { const value = JSON.parse(localStorage.getItem(KEY) || "[]"); return Array.isArray(value) ? value : []; } catch { return []; } };
  const save = items => { try { localStorage.setItem(KEY, JSON.stringify(items.slice(0, 100))); } catch { /* Library is optional. */ } };
  const rsaCertificate = item => (item.signature?.certificates || []).find(cert => /rsa/i.test(cert.publicKeyAlgorithm || cert.algorithm || ""));
  function normalize(result) {
    const pe = result.pe || {};
    return { ...result, id: result.id || result.wholeFileSha256 || result.appLockerHash || result.name + ":" + result.size, seenAt: new Date().toISOString(), pe: { ...pe, OriginalFilename: pe.OriginalFilename || pe.OriginalFileName || "" } };
  }
  function methods(item) {
    const publisher = item.appx?.publisher || item.signature?.certificates?.[0]?.subject;
    return [
      { key: "hash", label: "Hash", applocker: !!item.appLockerHash, wdac: !!item.appLockerHash },
      { key: "publisher", label: "Publisher", applocker: !!publisher, wdac: !!rsaCertificate(item) },
      { key: "attribute", label: "File attributes", applocker: false, wdac: !!item.pe?.OriginalFilename },
      { key: "path", label: "Path", applocker: false, wdac: false }
    ];
  }
  function status(supported, engine) { return supported ? '<span class="compat-status supported">Matches</span>' : '<span class="compat-status no-match">No matching ' + engine + ' method</span>'; }
  function render() {
    const root = document.querySelector("#sharedEvidenceLibrary");
    if (!root) return;
    const engine = root.dataset.libraryEngine || "applocker", items = load();
    if (!items.length) { root.innerHTML = '<div class="empty-library"><p>No analysed files yet.</p><button class="button button-secondary" type="button" data-open-analysis>Upload files</button></div>'; }
    else root.innerHTML = items.slice(0, 100).map(item => {
      const available = methods(item);
      const buttons = available.filter(method => method[engine]).map(method => '<button class="button button-secondary" type="button" data-reuse-method="' + method.key + '" data-reuse-id="' + encodeURIComponent(item.id) + '">Use ' + method.label.toLowerCase() + '</button>').join("");
      return '<article class="evidence-item"><div class="evidence-title"><div><strong>' + esc(item.name) + '</strong><small>' + esc(item.fileType || "file") + ' · ' + Math.round((item.size || 0) / 1024) + ' KB</small></div><div class="evidence-actions">' + buttons + '</div></div><div class="compat-grid">' + available.map(method => '<div><strong>' + method.label + '</strong><span>AppLocker ' + status(method.applocker, "AppLocker") + '</span><span>WDAC ' + status(method.wdac, "WDAC") + '</span></div>').join("") + '</div></article>';
    }).join("");
    root.querySelector("[data-open-analysis]")?.addEventListener("click", () => document.querySelector("#fileInput, #wdac-file-input")?.click());
    root.querySelectorAll("[data-reuse-method]").forEach(button => button.addEventListener("click", () => {
      const item = items.find(entry => entry.id === decodeURIComponent(button.dataset.reuseId)); if (!item) return;
      window.dispatchEvent(new CustomEvent(engine === "wdac" ? "policy-studio:reuse-wdac" : "policy-studio:reuse-applocker", { detail: { item, method: button.dataset.reuseMethod } }));
    }));
  }
  window.PolicyEvidenceLibrary = { load, save, methods, render };
  window.addEventListener("policy-studio:evidence", event => {
    const entry = normalize(event.detail?.result || event.detail || {}); if (!entry.name) return;
    const items = load().filter(item => item.id !== entry.id); items.unshift(entry); save(items); render();
  });
  window.addEventListener("storage", render);
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", render) : render();
}());
