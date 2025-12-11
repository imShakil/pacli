import os

# import json
from flask import Flask, render_template, request, jsonify, session
from functools import wraps
from datetime import datetime
from ..store import SecretStore
from ..log import get_logger

logger = get_logger("pacli.web")


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("PACLI_WEB_SECRET_KEY", "pacli-dev-secret-key-change-in-production")

    # Configure session
    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7  # 7 days
    app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production with HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Initialize store
    store = SecretStore()

    def require_auth(f):
        """Decorator to require master password authentication."""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "authenticated" not in session:
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)

        return decorated_function

    @app.route("/")
    def index():
        """Serve the main UI."""
        return render_template("index.html")

    @app.route("/api/auth/check", methods=["GET"])
    def check_auth():
        """Check if user is authenticated."""
        return jsonify({"authenticated": "authenticated" in session})

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        """Authenticate with master password."""
        data = request.get_json()
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password required"}), 400

        if not store.is_master_set():
            return jsonify({"error": "Master password not set. Run 'pacli init' first."}), 400

        if store.verify_master_password(password):
            session.permanent = True
            session["authenticated"] = True
            store.require_fernet(password)  # Set up fernet with the password
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Invalid master password"}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        """Logout user."""
        session.clear()
        return jsonify({"success": True})

    @app.route("/api/secrets", methods=["GET"])
    @require_auth
    def get_secrets():
        """Get all secrets."""
        try:
            secrets = store.list_secrets()
            return jsonify(
                {
                    "secrets": [
                        {
                            "id": s[0],
                            "label": s[1],
                            "type": s[2],
                            "creation_time": s[3],
                            "update_time": s[4],
                            "creation_date": datetime.fromtimestamp(s[3]).strftime("%Y-%m-%d %H:%M:%S"),
                            "update_date": datetime.fromtimestamp(s[4]).strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        for s in secrets
                    ]
                }
            )
        except Exception as e:
            logger.error(f"Error getting secrets: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>", methods=["GET"])
    @require_auth
    def get_secret(secret_id):
        """Get a specific secret by ID."""
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                return jsonify(secret)
            else:
                return jsonify({"error": "Secret not found"}), 404
        except Exception as e:
            logger.error(f"Error getting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets", methods=["POST"])
    @require_auth
    def create_secret():
        """Create a new secret."""
        try:
            data = request.get_json()
            label = data.get("label")
            secret = data.get("secret")
            secret_type = data.get("type", "password")

            if not label or not secret:
                return jsonify({"error": "Label and secret are required"}), 400

            store.save_secret(label, secret, secret_type)
            return jsonify({"success": True, "message": "Secret created successfully"}), 201
        except Exception as e:
            logger.error(f"Error creating secret: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>", methods=["PUT"])
    @require_auth
    def update_secret(secret_id):
        """Update a secret."""
        try:
            data = request.get_json()
            secret = data.get("secret")

            if not secret:
                return jsonify({"error": "Secret is required"}), 400

            store.update_secret(secret_id, secret)
            return jsonify({"success": True, "message": "Secret updated successfully"})
        except Exception as e:
            logger.error(f"Error updating secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>", methods=["DELETE"])
    @require_auth
    def delete_secret(secret_id):
        """Delete a secret."""
        try:
            store.delete_secret(secret_id)
            return jsonify({"success": True, "message": "Secret deleted successfully"})
        except Exception as e:
            logger.error(f"Error deleting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/search", methods=["GET"])
    @require_auth
    def search_secrets():
        """Search secrets by label."""
        try:
            query = request.args.get("q", "").lower()
            if not query:
                return jsonify({"secrets": []})

            secrets = store.list_secrets()
            filtered = [
                {
                    "id": s[0],
                    "label": s[1],
                    "type": s[2],
                    "creation_time": s[3],
                    "update_time": s[4],
                    "creation_date": datetime.fromtimestamp(s[3]).strftime("%Y-%m-%d %H:%M:%S"),
                    "update_date": datetime.fromtimestamp(s[4]).strftime("%Y-%m-%d %H:%M:%S"),
                }
                for s in secrets
                if query in s[1].lower()
            ]
            return jsonify({"secrets": filtered})
        except Exception as e:
            logger.error(f"Error searching secrets: {e}")
            return jsonify({"error": str(e)}), 500

    return app
