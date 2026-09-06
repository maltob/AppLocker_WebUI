(function (global) {
  "use strict";
  function clean(value) { return String(value == null ? "" : value).trim().toLowerCase(); }
  function identity(evidence, method) {
    evidence = evidence || {};
    if (method === "hash") return "hash:" + clean(evidence.appLockerHash || evidence.wholeFileSha256);
    if (method === "publisher") { var cert = evidence.signature && evidence.signature.certificates && evidence.signature.certificates[0] || {}; return "publisher:" + clean(evidence.appx && evidence.appx.publisher || cert.subject) + ":" + clean(evidence.pe && evidence.pe.ProductName || evidence.appx && evidence.appx.name); }
    if (method === "attribute") return "attribute:" + clean(evidence.pe && (evidence.pe.OriginalFilename || evidence.pe.OriginalFileName));
    return "";
  }
  function shared(evidence, method) { return { logicalId: identity(evidence, method) || "unmapped:" + Date.now().toString(36), compatibilityMethod: method, evidenceId: evidence && (evidence.id || evidence.wholeFileSha256) || "" }; }
  global.PolicyRuleCompatibility = { identity, shared };
}(window));
