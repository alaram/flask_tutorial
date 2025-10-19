import pyotp 
import json 
import base64
import qrcode
import io

from flask import Blueprint, request, jsonify, g, send_file
from flaskr.db import get_db

#| Endpoint      | Method | Purpose                                             |
#| ------------- | ------ | --------------------------------------------------- |
#| `/mfa/status` | `GET`  | Returns MFA status for a given user                 |
#| `/mfa/setup`  | `POST` | Initializes MFA setup (e.g., generates TOTP secret) |
#| `/mfa/verify` | `POST` | Verifies a submitted OTP and marks MFA as active    |

bp = Blueprint("mfa", __name__, url_prefix="/mfa")

# Helper: get user row
def get_user(username):
    db = get_db()
    return db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

@bp.route("/status", methods=["GET"])
def mfa_status():
    username = request.args.get("username")
    user = get_user(username)
    if not user:
        return jsonify({"error": "user not found"}), 404

    metadata = json.loads(user["mfa_metadata"] or "{}")
    return jsonify({
        "username": username,
        "mfa_enabled": metadata.get("verified", False),
        "mfa_type": metadata.get("type", None)
    })

@bp.route("/setup", methods=["POST"])
def mfa_setup():
    data = request.get_json()
    username = data.get("username")
    user = get_user(username)
    if not user:
        return jsonify({"error": "user not found"}), 404

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Flaskr")

    metadata = {"type": "TOTP", "secret": secret, "verified": False}
    db = get_db()
    db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(metadata), user["id"]))
    db.commit()

    return jsonify({"username": username, "secret": secret, "otpauth_url": uri})

@bp.route("/verify", methods=["POST"])
def mfa_verify():
    data = request.get_json()
    username = data.get("username")
    code = data.get("code")

    user = get_user(username)
    if not user:
        return jsonify({"error": "user not found"}), 404

    metadata = json.loads(user["mfa_metadata"] or "{}")
    secret = metadata.get("secret")
    totp = pyotp.TOTP(secret)

    if totp.verify(code):
        metadata["verified"] = True
        db = get_db()
        db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(metadata), user["id"]))
        db.commit()
        return jsonify({"result": "MFA verified and enabled"})
    else:
        return jsonify({"error": "invalid code"}), 400
    
@bp.route("/qrcode")
def qr_code():
    uri = request.args.get("uri")
    if not uri:
        return "Missing URI", 400
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
