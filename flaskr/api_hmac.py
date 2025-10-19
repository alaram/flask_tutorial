# flaskr/api_hmac.py
import os
import json
import hashlib
import hmac as py_hmac
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("api_hmac", __name__, url_prefix="/api/v1")

# secret should be stored out of DB in config/env (for demo we read from env)
SECRET = os.environ.get("API_SHARED_SECRET", "demo_shared_secret_please_change").encode()

# ---------- naive (vulnerable) MAC ----------
def naive_sign(message: bytes) -> str:
    # Naive prefix-then-hash: SHA256(secret || message). VULNERABLE to length-extension.
    h = hashlib.sha256()
    h.update(SECRET + message)
    return h.hexdigest()

def naive_verify(message: bytes, sig_hex: str) -> bool:
    expected = naive_sign(message)
    # Use constant-time compare here anyway (prevents timing leak on naive verify)
    return py_hmac.compare_digest(expected, sig_hex)

# ---------- safe HMAC ----------
def safe_sign(message: bytes) -> str:
    # HMAC-SHA256 (safe against length-extension)
    mac = py_hmac.new(SECRET, message, hashlib.sha256)
    return mac.hexdigest()

def safe_verify(message: bytes, sig_hex: str) -> bool:
    expected = safe_sign(message)
    return py_hmac.compare_digest(expected, sig_hex)

# ---------- endpoints ----------
# Get an example resource signed with naive MAC
@bp.route("/data_naive", methods=["GET"])
def data_naive():
    # simple message
    msg = {"user": "alice", "action": "view", "resource": "account"}
    body = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()
    sig = naive_sign(body)
    return jsonify({"body": msg, "sig": sig})

# Get an example resource signed with HMAC
@bp.route("/data_hmac", methods=["GET"])
def data_hmac():
    msg = {"user": "alice", "action": "view", "resource": "account"}
    body = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()
    sig = safe_sign(body)
    return jsonify({"body": msg, "sig": sig})

# Submit to naive verifier (accepts forged messages if naive MAC forgery works)
@bp.route("/submit_naive", methods=["POST"])
def submit_naive():
    j = request.get_json()
    if not j or "body" not in j or "sig" not in j:
        return jsonify({"error":"bad request"}), 400
    body_bytes = json.dumps(j["body"], separators=(",", ":"), sort_keys=True).encode()
    ok = naive_verify(body_bytes, j["sig"])
    return jsonify({"ok": ok})

# Submit to safe HMAC verifier
@bp.route("/submit_hmac", methods=["POST"])
def submit_hmac():
    j = request.get_json()
    if not j or "body" not in j or "sig" not in j:
        return jsonify({"error":"bad request"}), 400
    body_bytes = json.dumps(j["body"], separators=(",", ":"), sort_keys=True).encode()
    ok = safe_verify(body_bytes, j["sig"])
    return jsonify({"ok": ok})

# Demo endpoint that accepts a forged naive-signed message
@bp.route("/submit_naive_demo", methods=["POST"])
def submit_naive_demo():
    """
    Demo-only: accept a forged message if:
      - request JSON contains 'body' and 'sig'
      - the body contains 'is_admin': true
    This simulates the attacker successfully creating a forged payload via length-extension.
    """
    j = request.get_json()
    if not j or "body" not in j or "sig" not in j:
        return jsonify({"error": "bad request"}), 400

    body = j["body"]
    sig = j["sig"]

    # Demo accept condition: if attacker added is_admin=true then accept
    if isinstance(body, dict) and body.get("is_admin") is True:
        # Log for artifacts (server console will show this)
        current_app.logger.info("DEMO: accepted forged message (is_admin=true) in submit_naive_demo")
        return jsonify({"ok": True, "demo": "accepted_forged_is_admin"}), 200

    # otherwise behave like naive verify (not accepted)
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    ok = naive_verify(body_bytes, sig)
    return jsonify({"ok": ok})
