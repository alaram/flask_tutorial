// flaskr/static/webauthn-register.js
// this handles the registration and login for WebAuthn

async function registerWebAuthn(username) {
  const { b64uToBuffer, bufferToB64u, logWebAuthn } = window.WebAuthnUtils || {};

  if (!username) {
    throw new Error("username required for WebAuthn registration");
  }

  // 1) get options from server
  const r = await fetch("/webauthn/register/options", {
    method: "POST",
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username }),
    credentials: "same-origin"
  });
  if (!r.ok) throw new Error("register/options failed: " + r.status);
  const options = await r.json();
  logWebAuthn("register/options", options);

  // 2) Convert challenge and user.id to ArrayBuffer
  options.publicKey.challenge = b64uToBuffer(options.publicKey.challenge);
  if (options.publicKey.user && options.publicKey.user.id) {
    // if server used base64 for user.id
    options.publicKey.user.id = b64uToBuffer(options.publicKey.user.id);
  }

  // 3) create credentials
  const cred = await navigator.credentials.create({ publicKey: options.publicKey });
  logWebAuthn("navigator.create returned", cred);

  // 4) Build payload and send to server
  const payload = {
    id: cred.id,
    rawId: bufferToB64u(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufferToB64u(cred.response.attestationObject),
      clientDataJSON: bufferToB64u(cred.response.clientDataJSON)
    }
  };

  const completeResp = await fetch("/webauthn/register/complete", {
    method: "POST",
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
    credentials: "same-origin"
  });
  const j = await completeResp.json();
  logWebAuthn("register/complete response", j);
  if (!completeResp.ok) throw new Error("register/complete failed: " + (j.error || completeResp.status));
  return j;
}

async function authenticateWebAuthn(username) {
  const { b64uToBuffer, bufferToB64u, logWebAuthn } = window.WebAuthnUtils || {};

  if (!username) {
    throw new Error("username required for WebAuthn authentication");
  }

  const r = await fetch("/webauthn/auth/options", {
    method: "POST",
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username }),
    credentials: "same-origin"
  });
  if (!r.ok) throw new Error("auth/options failed: " + r.status);
  const options = await r.json();
  logWebAuthn("auth/options", options);

  options.publicKey.challenge = b64uToBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
      id: b64uToBuffer(c.id),
      type: c.type,
      transports: c.transports
    }));
  }

  const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
  logWebAuthn("navigator.get returned", assertion);

  const payload = {
    id: assertion.id,
    rawId: bufferToB64u(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToB64u(assertion.response.authenticatorData),
      clientDataJSON: bufferToB64u(assertion.response.clientDataJSON),
      signature: bufferToB64u(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufferToB64u(assertion.response.userHandle) : null
    }
  };

  const completeResp = await fetch("/webauthn/auth/complete", {
    method: "POST",
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
    credentials: "same-origin"
  });
  const j = await completeResp.json();
  logWebAuthn("auth/complete response", j);
  if (!completeResp.ok) throw new Error("auth/complete failed: " + (j.error || completeResp.status));
  return j;
}

// Expose in global scope for templates to call directly
window.registerWebAuthn = registerWebAuthn;
window.authenticateWebAuthn = authenticateWebAuthn;
