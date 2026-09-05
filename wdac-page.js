(function () {
  "use strict";
  const input = document.querySelector("#wdac-file-input"), results = document.querySelector("#wdac-upload-results");
  const hex = buffer => Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  const esc = value => String(value ?? "").replace(/[&<>]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]);
  async function inspect(file) {
    const digest = hex(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()));
    return { name: file.name, size: file.size, fileType: file.name.split(".").pop()?.toUpperCase() || "FILE", wholeFileSha256: digest, appLockerHash: digest, hashBasis: "whole-file SHA-256", signature: { certificates: [] } };
  }
  document.querySelector("#wdac-analyze")?.addEventListener("click", () => input.click());
  input?.addEventListener("change", async event => {
    const files = [...event.target.files].slice(0, 20); if (!files.length) return;
    results.innerHTML = '<p class="muted">Analysing files locally…</p>';
    const evidence = await Promise.all(files.map(inspect));
    results.innerHTML = evidence.map((item, index) => '<article class="analysis-card"><div><strong>' + esc(item.name) + '</strong><p>Whole-file SHA-256 · ' + Math.round(item.size / 1024) + ' KB</p><code>' + item.wholeFileSha256 + '</code><p class="analysis-note">Hash is available. Signer and file-attribute methods need metadata captured by a compatible parser.</p></div><div class="analysis-actions"><button class="button button-primary" type="button" data-wdac-hash="' + index + '">Add hash rule</button></div></article>').join("");
    evidence.forEach((item, index) => { window.dispatchEvent(new CustomEvent("policy-studio:evidence", { detail: { result: item, index } })); results.querySelector('[data-wdac-hash="' + index + '"]')?.addEventListener("click", () => window.__policyStudioWdacAddEvidence?.(item, "hash")); });
    event.target.value = "";
  });
  window.addEventListener("policy-studio:reuse-wdac", event => {
    const method = event.detail.method === "publisher" ? "signer" : event.detail.method;
    window.__policyStudioWdacAddEvidence?.(event.detail.item, method);
  });
}());
