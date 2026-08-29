// Browser-only hashing worker. Format parsing remains in the app; this keeps
// the largest CPU/memory operation off the editor's main thread.
self.onmessage = async event => {
  try {
    const bytes = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array(event.data || []);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const hash = "0x" + Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
    self.postMessage({ ok: true, hash });
  } catch (error) {
    self.postMessage({ ok: false, error: error?.message || "Hashing failed" });
  }
};
