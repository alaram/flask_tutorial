// flaskr/static/webauthn.js
// Shared helpers for WebAuthn flows (base64url conversions, simple logger).

// base64url -> ArrayBuffer
function b64uToBuffer(b64u) {
  if (!b64u) return null;
  b64u = b64u.replace(/-/g, "+").replace(/_/g, "/");
  // pad
  while (b64u.length % 4) b64u += "=";
  const binary = atob(b64u);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ArrayBuffer -> base64url
function bufferToB64u(buf) {
  if (!buf) return null;
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// BufferSource -> base64url (helper for RawId)
function arrayBufferToB64u(buf) { return bufferToB64u(buf); }

// Logging helper (prints compact info; can be extended to POST to server)
function logWebAuthn(event, data) {
  try {
    console.log("[WebAuthn] " + event, data);
  } catch (e) {
    // ignore
  }
}

// Expose on window for other scripts to use
window.WebAuthnUtils = {
  b64uToBuffer,
  bufferToB64u,
  arrayBufferToB64u,
  logWebAuthn
};
