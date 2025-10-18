# flaskr/webauthn.py
import json
import base64
import time
import os

from flask import Blueprint, request, session, current_app, jsonify
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
from fido2 import cose
from flaskr.db import get_db

bp = Blueprint("webauthn", __name__, url_prefix="/webauthn")

# Configure RP using app config with sensible defaults
# In create_app() set:
#   app.config['WEBAUTHN_RP_ID'] = 'localhost'
#   app.config['WEBAUTHN_ORIGIN'] = 'http://localhost:5000'
#   app.config['WEBAUTHN_RP_NAME'] = 'Flaskr Demo'

ART_WEBAUTHN = "artifacts/webauthn"
os.makedirs(ART_WEBAUTHN, exist_ok=True)

def save_trace(name, obj):
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(ART_WEBAUTHN, f"{ts}-{name}.json")
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    print(f"[webauthn] saved {path}")
    return path

def _get_server():
    rp_id = current_app.config.get("WEBAUTHN_RP_ID", "127.0.0.1")
    rp_name = current_app.config.get("WEBAUTHN_RP_NAME", "Flaskr Demo")
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp)

def b64u_encode(b: bytes) -> str:
    return websafe_encode(b).decode()

def b64u_decode(s: str) -> bytes:
    return websafe_decode(s.encode())

@bp.route("/register/options", methods=["POST"])
def register_options():
    """
    Begin registration. Expects JSON: {"username": "<username>"}
    Returns JSON options to pass to navigator.credentials.create()
    Stores 'state' in session under 'webauthn_register_state'
    """
    data = request.get_json() or {}
    username = data.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    db = get_db()
    user_row = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
    if not user_row:
        return jsonify({"error": "unknown user"}), 404

    user_id_bytes = str(user_row["id"]).encode("utf8")
    user_entity = PublicKeyCredentialUserEntity(id=user_id_bytes, name=username, display_name=username)

    server = _get_server()
    # We ask python-fido2 to produce options + state
    options, state = server.register_begin(user_entity,
                                           user_verification="preferred",
                                           authenticator_attachment=None)
    # Keep state until /register/complete
    session["webauthn_register_state"] = state

    # Convert bytes inside options to base64url so JSON is safe for client
    # python-fido2 returns options as dict-like; replace challenge with base64url
    # We'll send options to client mostly as-is; client must convert challenge -> ArrayBuffer
    def _encode_opts(o):
        # options has 'publicKey' structure for browser
        if "challenge" in o:
            o["challenge"] = b64u_encode(o["challenge"])
        if "user" in o and isinstance(o["user"].get("id"), (bytes, bytearray)):
            o["user"]["id"] = base64.b64encode(o["user"]["id"]).decode()
        return o

    # options is a dict-like structure that contains bytes in a few places.
    # We create a JSON-safe version:
    json_options = json.loads(json.dumps(options, default=lambda x: x.decode() if isinstance(x, (bytes, bytearray)) else x))
    # Fix the challenge encoding (ensure base64url)
    if "publicKey" in json_options and "challenge" in json_options["publicKey"]:
        json_options["publicKey"]["challenge"] = b64u_encode(options["publicKey"]["challenge"])

    # also ensure user.id is base64 (some clients expect base64)
    if "publicKey" in json_options and "user" in json_options["publicKey"]:
        if isinstance(options["publicKey"]["user"]["id"], (bytes, bytearray)):
            json_options["publicKey"]["user"]["id"] = base64.b64encode(options["publicKey"]["user"]["id"]).decode()

    return jsonify(json_options)


@bp.route("/register/complete", methods=["POST"])
def register_complete():
    """
    Complete registration.
    Expects JSON payload from client:
    {
      id, rawId (base64url), type,
      response: { attestationObject (base64url), clientDataJSON (base64url) }
    }
    """
    state = session.pop("webauthn_register_state", None)
    if state is None:
        return jsonify({"error": "no registration state"}), 400

    payload = request.get_json()
    if not payload:
        return jsonify({"error": "missing payload"}), 400

    # Convert base64url fields to bytes for fido2
    try:
        payload["rawId"] = b64u_decode(payload["rawId"])
        payload["response"]["attestationObject"] = b64u_decode(payload["response"]["attestationObject"])
        payload["response"]["clientDataJSON"] = b64u_decode(payload["response"]["clientDataJSON"])
    except Exception as e:
        return jsonify({"error": "invalid base64 fields", "detail": str(e)}), 400

    server = _get_server()
    # This returns an AttestedCredentialData-like object with credential_id, public_key, sign_count
    auth_data = server.register_complete(state, payload)
    cred_id_b64u = b64u_encode(auth_data.credential_id)
    public_key_bytes = auth_data.public_key.encode()  # COSE / raw public key bytes
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    sign_count = auth_data.sign_count

    # Which user? state contains the user entity we used earlier
    user_id = None
    if isinstance(state.get("user"), dict) and "id" in state["user"]:
        # state['user']['id'] might be bytes or base64; convert safely
        u = state["user"]["id"]
        if isinstance(u, (bytes, bytearray)):
            user_id = int(u.decode())
        else:
            try:
                user_id = int(base64.b64decode(u).decode())
            except Exception:
                # fallback to session's user_id if you maintain login session
                user_id = session.get("user_id")
    if user_id is None:
        user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"error": "cannot determine user id"}), 400

    # persist
    db = get_db()
    db.execute(
        "INSERT INTO webauthn_credential (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)",
        (user_id, cred_id_b64u, public_key_b64, sign_count)
    )
    db.commit()

    # incoming JSON from client
    req_json = request.get_json()
    save_trace("register-incoming", req_json)

    # after server.register_complete(...) returns auth_data:
    save_trace("register-verified", {
        "credential_id": base64.urlsafe_b64encode(auth_data.credential_data.credential_id).decode(),
        "public_key": base64.urlsafe_b64encode(auth_data.credential_data.public_key).decode(),
        "attestation": str(auth_data.attestation_object)[:200]
    })

    # Save a JSON trace artifact if you want (server-side trace)
    # Optionally: write to file under artifacts/webauthn/<username>.json for demo evidence.
    return jsonify({"status": "ok", "credentialId": cred_id_b64u})


@bp.route("/auth/options", methods=["POST"])
def auth_options():
    """
    Begin authentication (assertion). Expects JSON {"username": "<username>"}.
    Returns assertion options (challenge, allowCredentials) to pass to navigator.credentials.get()
    """
    data = request.get_json() or {}
    username = data.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    db = get_db()
    user_row = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
    if not user_row:
        return jsonify({"error": "unknown user"}), 404

    creds = db.execute("SELECT credential_id FROM webauthn_credential WHERE user_id = ?", (user_row["id"],)).fetchall()
    allow = []
    for c in creds:
        # stored as base64url; decode to bytes
        try:
            cid = c["credential_id"]
            allow.append({"type": "public-key", "id": cid})
        except Exception:
            pass

    server = _get_server()
    # For python-fido2, we must pass allow_credentials as list of bytes. We send base64url to client and client will convert.
    options, state = server.authenticate_begin(allow_credentials=[b64u_decode(x["id"]) for x in allow] if allow else None,
                                              user_verification="preferred")
    session["webauthn_auth_state"] = state

    # Convert challenge to base64url so JSON safe
    json_options = json.loads(json.dumps(options, default=lambda x: x.decode() if isinstance(x, (bytes, bytearray)) else x))
    if "publicKey" in json_options and "challenge" in json_options["publicKey"]:
        json_options["publicKey"]["challenge"] = b64u_encode(options["publicKey"]["challenge"])

    # ensure allowCredentials contains base64url ids
    if "publicKey" in json_options and json_options["publicKey"].get("allowCredentials"):
        new_allow = []
        for ac in options["publicKey"]["allowCredentials"]:
            new_allow.append({"type": ac["type"], "id": b64u_encode(ac["id"])})
        json_options["publicKey"]["allowCredentials"] = new_allow

    return jsonify(json_options)


@bp.route("/auth/complete", methods=["POST"])
def auth_complete():
    """
    Finish authentication. Expects client assertion JSON:
    { id, rawId (base64url), type, response: { authenticatorData, clientDataJSON, signature, userHandle? } }
    """
    state = session.pop("webauthn_auth_state", None)
    if state is None:
        return jsonify({"error": "no auth state"}), 400

    payload = request.get_json()
    if not payload:
        return jsonify({"error": "missing payload"}), 400

    try:
        payload["rawId"] = b64u_decode(payload["rawId"])
        payload["response"]["authenticatorData"] = b64u_decode(payload["response"]["authenticatorData"])
        payload["response"]["clientDataJSON"] = b64u_decode(payload["response"]["clientDataJSON"])
        payload["response"]["signature"] = b64u_decode(payload["response"]["signature"])
    except Exception as e:
        return jsonify({"error": "invalid base64 fields", "detail": str(e)}), 400

    # Build a lookup dict mapping credential id (bytes) -> credential public key object
    db = get_db()
    # find stored credential entry by credential_id
    raw_cred_id_b64u = payload.get("id") or b64u_encode(payload["rawId"])
    cred_row = db.execute("SELECT * FROM webauthn_credential WHERE credential_id = ?", (raw_cred_id_b64u,)).fetchone()
    if not cred_row:
        return jsonify({"error": "credential not registered"}), 400

    # reconstruct public key bytes
    public_key_b64 = cred_row["public_key"]
    public_key_bytes = base64.b64decode(public_key_b64)

    server = _get_server()

    # For server.authenticate_complete we need to provide a credential lookup function or mapping.
    # python-fido2 allows passing "cred_public_key" mapping as {credential_id_bytes: (public_key, sign_count)}.
    # We'll construct that mapping:
    cred_id_bytes = b64u_decode(raw_cred_id_b64u)
    credentials = {cred_id_bytes: (public_key_bytes, cred_row["sign_count"])}

    # Call authenticate_complete: if verification succeeds, this returns auth_data object
    auth_data = server.authenticate_complete(state, credentials, payload)

    # Update sign_count in DB
    new_sign_count = auth_data.new_sign_count if hasattr(auth_data, "new_sign_count") else auth_data.sign_count
    db.execute("UPDATE webauthn_credential SET sign_count = ? WHERE id = ?", (new_sign_count, cred_row["id"]))
    db.commit()

    req_json = request.get_json()
    save_trace("auth-incoming", req_json)

    try:
        auth_data = server.authenticate_complete(state, credentials, client_data, assertion_object)
        save_trace("auth-verified", {"status":"ok", "credential_id": base64.urlsafe_b64encode(auth_data.credential_id).decode(), "sign_count": auth_data.sign_count})
    except Exception as e:
        save_trace("auth-failed", {"status":"failed", "error": str(e)})
    raise  # let handler produce HTTP 400/403 as before

    # create login session or return success
    session["user_id"] = cred_row["user_id"]
    return jsonify({"status": "ok"})