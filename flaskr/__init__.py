import os

from flask import Flask
from flask_cors import CORS

def create_app(test_config=None):

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    # Setup to define the App address
    # This information will be used for Relay with TOTP / WebAuthn
    app.config['WEBAUTHN_RP_ID'] = '127.0.0.1'
    app.config['WEBAUTHN_ORIGIN'] = 'http://127.0.0.1:5001'
    app.config['WEBAUTHN_RP_NAME'] = 'Flaskr Demo'
    
    
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Import DB and register it from the factory    
    from . import db
    db.init_app(app)

    # Import Authorization, e.g. login & register
    # and register the blueprint from the factory
    from . import auth
    app.register_blueprint(auth.bp)

    # Import MFA metadata logic, e.g. status, verify, setup
    # and register the blueprint from the factory
    from . import mfa
    app.register_blueprint(mfa.bp)

    # Import MFA metadata logic for HOTP & TOTP, e.g. status, verify, setup
    # and register the blueprint from the factory    
    from . import mfa_hotp_totp
    app.register_blueprint(mfa_hotp_totp.bp)

    # Required du to CORS origin error from the browser
    CORS(app, resources={r"/webauthn/*": {"origins": ["http://127.0.0.1:4000", "http://127.0.0.1:5001"]}})

    # Import Webauthn and register the blueprint from the factory
    from . import webauthn
    app.register_blueprint(webauthn.bp, url_prefix="/webauthn")

    # Import API HMAC and register the blueprint from the factory
    from . import api_hmac
    app.register_blueprint(api_hmac.bp)
    
    # A simple page that says hello and check that works
    @app.route('/hello')
    def hello():
        return 'Hello, World! It works'

    # Healt check for the Flask App
    @app.route("/health")
    def _health():
        return "OK"

    return app