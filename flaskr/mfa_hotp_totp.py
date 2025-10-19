# flaskr/mfa_htop_totp.py 
import os, json, time
from flask import Blueprint, request, jsonify, current_app, send_file
from flaskr.db import get_db
import pyotp, qrcode
from io import BytesIO

bp = Blueprint("mfa_hotp_totp", __name__, url_prefix="/mfa_hotp_totp")

LOG_DIR = "artifacts/logs"
os.makedirs(LOG_DIR, exist_ok=True)
OTP_ATTEMPTS_LOG = os.path.join(LOG_DIR, "otp_attempts.log")

# helper: write a line to the attempts log (newline-delimited JSON)
def log_otp_attempt(entry: dict):
    entry.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    os.makedirs(os.path.dirname(OTP_ATTEMPTS_LOG), exist_ok=True)
    with open(OTP_ATTEMPTS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def get_user_row(username):
    db = get_db()
    return db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

# ---------- Setup endpoint: create TOTP or HOTP secret ----------
@bp.route("/setup", methods=["POST"])
def mfa_setup():
    """
    POST JSON: {"username":"alice", "type":"totp"|'hotp', "initial_counter": 0 (optional)}
    Response: {"username":..., "type":..., "secret":..., "otpauth_url":...}
    """
    data = request.get_json() or {}
    username = data.get("username")
    kind = (data.get("type") or "totp").lower()
    if not username:
        return jsonify({"error": "username required"}), 400

    user = get_user_row(username)
    if not user:
        return jsonify({"error":"user not found"}), 404

    secret = pyotp.random_base32()
    db = get_db()
    if kind == "totp":
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Flaskr")
        metadata = {"type":"totp", "secret": secret, "verified": False}
    elif kind == "hotp":
        initial = int(data.get("initial_counter", 0))
        # store the current server counter (the next expected counter)
        metadata = {"type":"hotp", "secret": secret, "counter": initial, "verified": False}
        uri = f"otpauth://hotp/Flaskr:{username}?secret={secret}&counter={initial}&issuer=Flaskr"
    else:
        return jsonify({"error":"unsupported type"}), 400

    db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(metadata), user["id"]))
    db.commit()

    # Save QR for TOTP (and HOTP if you want to show QR)
    os.makedirs("artifacts/qrs", exist_ok=True)
    buf = BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    buf.seek(0)
    qfile = f"artifacts/qrs/{username}-{kind}-qr.png"
    with open(qfile, "wb") as f:
        f.write(buf.read())

    return jsonify({"username": username, "type": kind, "secret": secret, "otpauth_url": uri, "qr": qfile})


# ---------- Verify endpoint: TOTP or HOTP with configurable windows ----------
@bp.route("/verify", methods=["POST"])
def mfa_verify():
    """
    POST JSON:
      {
        "username": "alice",
        "code": "123456",
        "type": "totp"|'hotp' (optional, default from metadata),
        "window": 1,   # for TOTP: +/- window in time steps; for HOTP: forward window (0..N)
        "source": "control"|'phish' (optional, for logging)
      }
    """
    j = request.get_json() or {}
    username = j.get("username")
    code = str(j.get("code","")).strip()
    req_type = j.get("type")
    window = int(j.get("window", 1))  # default ±1 for totp; for hotp this is forward window
    source = j.get("source", "unknown")

    if not username or not code:
        return jsonify({"error":"username & code required"}), 400

    user = get_user_row(username)
    if not user:
        return jsonify({"error":"user not found"}), 404

    metadata = json.loads(user["mfa_metadata"] or "{}")
    mtype = (req_type or metadata.get("type") or "totp").lower()
    secret = metadata.get("secret")

    attempt = {
        "username": username,
        "type": mtype,
        "code": code,
        "source": source,
        "result": None,
        "reason": None,
        "server_counter_before": metadata.get("counter") if metadata else None
    }

    # TOTP verification (time-window)
    if mtype == "totp":
        totp = pyotp.TOTP(secret)
        # pyotp accepts valid_window for ± steps
        ok = totp.verify(code, valid_window=window)
        attempt["result"] = ok
        attempt["reason"] = "valid_window" if ok else "invalid"
        log_otp_attempt(attempt)
        if ok:
            # mark verified metadata
            metadata["verified"] = True
            db = get_db()
            db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(metadata), user["id"]))
            db.commit()
            return jsonify({"ok": True})
        else:
            return jsonify({"ok": False}), 400

    # HOTP verification (counter + forward window)
    elif mtype == "hotp":
        hotp = pyotp.HOTP(secret)
        server_counter = int(metadata.get("counter", 0))
        found = False
        matched_offset = None

        # Check counters from current to current+window (inclusive)
        for offset in range(0, window + 1):
            c = server_counter + offset
            if hotp.verify(code, c):
                found = True
                matched_offset = offset
                break

        attempt["result"] = found
        attempt["matched_offset"] = matched_offset
        attempt["server_counter_after"] = None

        if found:
            # advance server counter to one past the matched counter (RFC4226 recommendation)
            new_counter = server_counter + matched_offset + 1
            metadata["counter"] = new_counter
            metadata["verified"] = True
            db = get_db()
            db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(metadata), user["id"]))
            db.commit()
            attempt["server_counter_after"] = new_counter
            attempt["reason"] = "accepted"
            log_otp_attempt(attempt)
            return jsonify({"ok": True, "new_counter": new_counter})
        else:
            attempt["reason"] = "invalid_or_too_far"
            log_otp_attempt(attempt)
            return jsonify({"ok": False}), 400
    else:
        return jsonify({"error":"unsupported mfa type"}), 400


# ---------- status endpoint ----------
@bp.route("/status", methods=["GET"])
def mfa_status():
    username = request.args.get("username")
    user = get_user_row(username)
    if not user: return jsonify({"error":"user not found"}), 404
    metadata = json.loads(user["mfa_metadata"] or "{}")
    return jsonify({"username": username, "mfa_metadata": metadata})
