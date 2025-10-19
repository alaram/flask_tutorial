import functools
import os
import hashlib
import json
import base64
import pyotp
import qrcode
# import bcrypt

from io import BytesIO
from argon2 import PasswordHasher
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, current_app, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate salt
        salt = os.urandom(16).hex()

        # Choose your hash method
        algo = 'sha256'
        hash_bytes = hashlib.sha256((salt + password).encode()).hexdigest()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO user (username, salt, hash, algo) VALUES (?, ?, ?, ?)",
                (username, salt, hash_bytes, algo)
            )
            db.commit()
        except db.IntegrityError:
            flash(f"User {username} is already registered.")
        else:
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html")

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = "Incorrect username"
        else:    
            salt = user['salt']
            stored_hash = user['hash']
            algo = user['algo']
            # --- Password verification ---
            if algo == "sha256":
                check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
                if check_hash != stored_hash:
                    error = "Incorrect password."
            elif algo == "sha3":
                check_hash = hashlib.sha3_256((salt + password).encode()).hexdigest()
                if check_hash != stored_hash:
                    error = "Incorrect password."
            elif algo == "bcrypt":
                if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    error = "Incorrect password."
            elif algo == "argon2":
                ph = PasswordHasher()
                try:
                    ph.verify(stored_hash, password)
                except Exception:
                    error = "Incorrect password."
            else:
                error = f"Unknown algorithm: {algo}"

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/login.html')

# session
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# logout
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

# require authentication in other views
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

# helper: write artifact directory
def _ensure_artifacts_dirs():
    os.makedirs("artifacts/qrs", exist_ok=True)

def _get_user_row(db, username):
    return db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

# GET: show TOTP setup page (QR + manual secret)
@bp.route("/totp-setup", methods=("GET", "POST"))
def totp_setup():
    """
    GET: render TOTP setup page showing QR + secret
    POST: verify submitted token; on success mark mfa_metadata. Use flash + redirect.
    """
    # Determine username: prefer logged-in user (session) else query param for quick tests
    username = None
    if session.get("user_id"):
        db = get_db()
        user_row = db.execute("SELECT username FROM user WHERE id = ?", (session["user_id"],)).fetchone()
        if user_row:
            username = user_row["username"]
    if not username:
        username = request.args.get("username")

    if not username:
        flash("No username provided.", "error")
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("Unknown user.", "error")
        return redirect(url_for("auth.register"))

    # Load or create mfa metadata
    try:
        mfa = json.loads(user["mfa_metadata"] or "{}")
    except Exception:
        mfa = {}

    if request.method == "GET":
        # If there is an existing TOTP secret, reuse it; otherwise create one
        if mfa.get("type") == "totp" and mfa.get("secret"):
            secret = mfa["secret"]
        else:
            secret = pyotp.random_base32()
            mfa = {"type": "totp", "secret": secret, "verified": False}
            db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(mfa), user["id"]))
            db.commit()

        issuer = current_app.config.get("WEBAUTHN_RP_NAME", "Flaskr Demo")
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

        # generate inline QR as data URI
        qr = qrcode.make(provisioning_uri)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)
        img_b64 = base64.b64encode(buf.read()).decode()
        data_uri = f"data:image/png;base64,{img_b64}"

        # also save PNG file to artifacts for evidence
        os.makedirs("artifacts/qrs", exist_ok=True)
        buf2 = BytesIO()
        qrcode.make(provisioning_uri).save(buf2, format="PNG")
        buf2.seek(0)
        with open(f"artifacts/qrs/{username}-totp-qr.png", "wb") as f:
            f.write(buf2.read())

        # Render template with variables
        return render_template("auth/totp_setup.html",
                               username=username,
                               qr_data_uri=data_uri,
                               secret=secret)

    # POST: verify submitted token
    token = request.form.get("token")
    if not token:
        flash("TOTP code required.", "error")
        return redirect(url_for("auth.totp_setup", username=username))

    secret = mfa.get("secret")
    if not secret:
        flash("TOTP not initialized for this user.", "error")
        return redirect(url_for("auth.totp_setup", username=username))

    totp = pyotp.TOTP(secret)
    verified = totp.verify(token, valid_window=1)

    if verified:
        mfa["verified"] = True
        db.execute("UPDATE user SET mfa_metadata = ? WHERE id = ?", (json.dumps(mfa), user["id"]))
        db.commit()
        flash("TOTP verified and enabled.", "success")
        # redirect to account or login page
        return redirect(url_for("auth.login"))
    else:
        flash("Invalid TOTP code. Try again.", "error")
        return redirect(url_for("auth.totp_setup", username=username))

