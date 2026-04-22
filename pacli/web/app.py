import os
import uuid
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from datetime import datetime
from ..store import SecretStore
from ..log import get_logger
from .ssh_handler import SSHConnectionManager

logger = get_logger("pacli.web")


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("PACLI_WEB_SECRET_KEY", "pacli-dev-secret-key-change-in-production")

    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    store = SecretStore()
    ssh_manager = SSHConnectionManager()
    socketio = SocketIO(app, cors_allowed_origins="*")

    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "authenticated" not in session:
                return jsonify({"error": "Unauthorized"}), 401
            if store.fernet is None:
                session.clear()
                return jsonify({"error": "Session expired. Please sign in again."}), 401
            return f(*args, **kwargs)

        return decorated

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        return render_template("index.html")

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    @app.route("/api/setup/status", methods=["GET"])
    def setup_status():
        return jsonify({"configured": store.is_master_set()})

    @app.route("/api/setup/init", methods=["POST"])
    def setup_init():
        if store.is_master_set():
            return jsonify({"error": "Already configured"}), 400

        data = request.get_json()
        password = data.get("password", "")
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        confirm = data.get("confirm", "")
        if password != confirm:
            return jsonify({"error": "Passwords do not match"}), 400

        from ..store import get_salt, PASSWORD_HASH_PATH, SALT_PATH
        import hashlib

        salt = get_salt()
        with open(SALT_PATH + ".set", "w") as f:
            f.write("set")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        with open(PASSWORD_HASH_PATH, "w") as f:
            f.write(password_hash)
        store.fernet = store._derive_fernet(password, salt)

        session.permanent = True
        session["authenticated"] = True
        logger.info("Master password set via Web UI.")
        return jsonify({"success": True})

    @app.route("/api/auth/check", methods=["GET"])
    def check_auth():
        authenticated = "authenticated" in session and store.fernet is not None
        if not authenticated and "authenticated" in session and store.fernet is None:
            session.clear()
        return jsonify(
            {
                "authenticated": authenticated,
                "configured": store.is_master_set(),
            }
        )

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json()
        password = data.get("password")
        if not password:
            return jsonify({"error": "Password required"}), 400
        if not store.is_master_set():
            return jsonify({"error": "Not configured", "configured": False}), 400
        if store.verify_master_password(password):
            session.permanent = True
            session["authenticated"] = True
            store.require_fernet(password)
            return jsonify({"success": True})
        return jsonify({"error": "Invalid master password"}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"success": True})

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------

    @app.route("/api/secrets", methods=["GET"])
    @require_auth
    def get_secrets():
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
                            "creation_date": datetime.fromtimestamp(s[3]).strftime("%Y-%m-%d %H:%M"),
                            "update_date": datetime.fromtimestamp(s[4]).strftime("%Y-%m-%d %H:%M"),
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
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                return jsonify(
                    {
                        "id": secret.get("id"),
                        "label": secret.get("label"),
                        "type": secret.get("type"),
                        "creation_time": secret.get("creation_time"),
                        "update_time": secret.get("update_time"),
                    }
                )
            return jsonify({"error": "Secret not found"}), 404
        except Exception as e:
            logger.error(f"Error getting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>/reveal", methods=["GET"])
    @require_auth
    def reveal_secret(secret_id):
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                return jsonify(
                    {
                        "secret": secret.get("secret"),
                        "type": secret.get("type"),
                        "label": secret.get("label"),
                    }
                )
            return jsonify({"error": "Secret not found"}), 404
        except Exception as e:
            logger.error(f"Error revealing secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets", methods=["POST"])
    @require_auth
    def create_secret():
        try:
            data = request.get_json()
            label = data.get("label", "").strip()
            secret = data.get("secret", "").strip()
            secret_type = data.get("type", "password")
            if not label or not secret:
                return jsonify({"error": "Label and secret are required"}), 400
            if secret_type not in ("password", "token", "ssh"):
                return jsonify({"error": "Invalid secret type"}), 400
            store.save_secret(label, secret, secret_type)
            return jsonify({"success": True, "message": "Secret created"}), 201
        except Exception as e:
            logger.error(f"Error creating secret: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>", methods=["PUT"])
    @require_auth
    def update_secret(secret_id):
        try:
            data = request.get_json()
            secret = data.get("secret", "").strip()
            if not secret:
                return jsonify({"error": "Secret value is required"}), 400
            store.update_secret(secret_id, secret)
            return jsonify({"success": True, "message": "Secret updated"})
        except Exception as e:
            logger.error(f"Error updating secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/<secret_id>", methods=["DELETE"])
    @require_auth
    def delete_secret(secret_id):
        try:
            store.delete_secret(secret_id)
            return jsonify({"success": True, "message": "Secret deleted"})
        except Exception as e:
            logger.error(f"Error deleting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/secrets/search", methods=["GET"])
    @require_auth
    def search_secrets():
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
                    "creation_date": datetime.fromtimestamp(s[3]).strftime("%Y-%m-%d %H:%M"),
                    "update_date": datetime.fromtimestamp(s[4]).strftime("%Y-%m-%d %H:%M"),
                }
                for s in secrets
                if query in s[1].lower()
            ]
            return jsonify({"secrets": filtered})
        except Exception as e:
            logger.error(f"Error searching secrets: {e}")
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    @app.route("/api/backup/export", methods=["POST"])
    @require_auth
    def api_backup_export():
        try:
            data = request.get_json()
            backup_password = data.get("password", "")
            if len(backup_password) < 6:
                return jsonify({"error": "Backup password must be at least 6 characters"}), 400
            blob = store.export_encrypted_backup(backup_password)
            from flask import Response

            return Response(
                blob,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": "attachment; filename=pacli_backup.pacli"},
            )
        except Exception as e:
            logger.error(f"Backup export failed: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/backup/import", methods=["POST"])
    @require_auth
    def api_backup_import():
        try:
            backup_password = request.form.get("password", "")
            overwrite = request.form.get("overwrite", "false").lower() == "true"
            if "file" not in request.files:
                return jsonify({"error": "No file uploaded"}), 400
            f = request.files["file"]
            blob = f.read()
            stats = store.import_encrypted_backup(blob, backup_password, merge=not overwrite)
            return jsonify({"success": True, **stats})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"Backup import failed: {e}")
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # SSH REST endpoints (fallback when WebSocket unavailable)
    # ------------------------------------------------------------------

    @app.route("/api/ssh/connect", methods=["POST"])
    @require_auth
    def ssh_connect():
        try:
            data = request.get_json()
            hostname, username, port, password, key_id, ssh_key = _extract_ssh_params(data)

            if key_id and not hostname:
                result = _resolve_stored_ssh(store, key_id)
                if (
                    isinstance(result, tuple)
                    and len(result) == 2
                    and isinstance(result[0], str)
                    and result[0].startswith("error:")
                ):
                    return jsonify({"error": result[0][6:]}), 400
                username, hostname, port = result

            if not hostname or not username:
                return jsonify({"error": "Hostname and username are required"}), 400

            key_filename = _resolve_key(store, ssh_key, None)

            connection_id = str(uuid.uuid4())
            success = ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename)
            if success:
                return (
                    jsonify(
                        {
                            "success": True,
                            "connection_id": connection_id,
                            "message": f"Connected to {username}@{hostname}",
                        }
                    ),
                    201,
                )
            return jsonify({"error": "SSH connection failed. Check credentials and host."}), 400
        except Exception as e:
            logger.error(f"SSH connect error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ssh/disconnect/<connection_id>", methods=["POST"])
    @require_auth
    def ssh_disconnect(connection_id):
        try:
            ssh_manager.close_connection(connection_id)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ssh/execute", methods=["POST"])
    @require_auth
    def ssh_execute():
        try:
            data = request.get_json()
            connection_id = data.get("connection_id")
            command = data.get("command", "")
            if not connection_id:
                return jsonify({"error": "connection_id required"}), 400

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                return jsonify({"error": "Connection not found or timed out"}), 404

            if terminal.send_command(command + "\n"):
                import time

                # Wait a bit longer for output to arrive
                time.sleep(0.4)
                output = terminal.get_output()
                return jsonify({"success": True, "output": output})
            return jsonify({"error": "Failed to send command"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ssh/output/<connection_id>", methods=["GET"])
    @require_auth
    def ssh_get_output(connection_id):
        """Poll endpoint for SSH output — used by REST fallback mode."""
        try:
            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                return jsonify({"output": "", "disconnected": True})
            output = terminal.get_output()
            return jsonify(
                {
                    "output": output,
                    "connected": terminal.connected,
                    "disconnected": not terminal.connected,
                }
            )
        except Exception as e:
            return jsonify({"output": "", "disconnected": True, "error": str(e)})

    # ------------------------------------------------------------------
    # WebSocket SSH
    # ------------------------------------------------------------------

    @socketio.on("connect")
    def handle_connect():
        emit("response", {"data": "Connected"})

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.info("WebSocket client disconnected")

    @socketio.on("ssh_connect")
    def handle_ssh_connect(data):
        if "authenticated" not in session:
            emit("error", {"message": "Unauthorized"})
            return
        if store.fernet is None:
            session.clear()
            emit("error", {"message": "Session expired. Please sign in again."})
            return
        try:
            hostname = data.get("hostname")
            username = data.get("username")
            port = data.get("port", 22)
            password = data.get("password")
            key_id = data.get("key_id")
            ssh_key = data.get("ssh_key")

            if key_id and not hostname:
                result = _resolve_stored_ssh(store, key_id)
                if isinstance(result, str) and result.startswith("error:"):
                    emit("error", {"message": result[6:]})
                    return
                username, hostname, port = result

            if not hostname or not username:
                emit("error", {"message": "Hostname and username required"})
                return

            key_filename = _resolve_key(store, ssh_key, None)
            connection_id = str(uuid.uuid4())

            if ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename):
                join_room(connection_id)
                emit(
                    "ssh_connected",
                    {
                        "connection_id": connection_id,
                        "message": f"Connected to {username}@{hostname}:{port}",
                    },
                )
                # Start streaming output to client
                _start_output_streaming(socketio, ssh_manager, connection_id)
            else:
                emit("error", {"message": "SSH connection failed. Check credentials and host."})
        except Exception as e:
            logger.error(f"WS SSH connect error: {e}")
            emit("error", {"message": str(e)})

    @socketio.on("ssh_command")
    def handle_ssh_command(data):
        try:
            connection_id = data.get("connection_id")
            command = data.get("command", "")
            if not connection_id:
                emit("error", {"message": "connection_id required"})
                return

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                emit("error", {"message": "Connection not found or timed out"})
                return

            terminal.send_command(command + "\n")
            # Output will be streamed via the background thread started on connect
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("ssh_disconnect")
    def handle_ssh_disconnect(data):
        try:
            connection_id = data.get("connection_id")
            if connection_id:
                ssh_manager.close_connection(connection_id)
                leave_room(connection_id)
                emit(
                    "ssh_disconnected",
                    {
                        "connection_id": connection_id,
                        "message": "Disconnected",
                    },
                )
        except Exception as e:
            emit("error", {"message": str(e)})

    return app, socketio


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _extract_ssh_params(data):
    """Extract SSH connection parameters from request data."""
    hostname = data.get("hostname")
    username = data.get("username")
    port = data.get("port", 22)
    password = data.get("password")
    key_id = data.get("key_id")
    ssh_key = data.get("ssh_key")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 22
    return hostname, username, port, password, key_id, ssh_key


def _resolve_stored_ssh(store, key_id):
    """
    Parse a stored SSH secret into (username, hostname, port).
    Returns error string on failure.
    """
    secret = store.get_secret_by_id(key_id)
    if not secret:
        return "error:SSH server not found"

    ssh_data = secret.get("secret", "")
    parts = ssh_data.split("|")
    user_ip = parts[0]

    if ":" not in user_ip:
        return "error:Invalid SSH secret format — expected user:host"

    username, hostname = user_ip.split(":", 1)
    port = 22

    for part in parts[1:]:
        if part.startswith("port:"):
            try:
                port = int(part[5:])
            except ValueError:
                pass

    if not username or not hostname:
        return "error:SSH secret is missing username or hostname"

    return username, hostname, port


def _resolve_key(store, ssh_key_text, key_id):
    """Save SSH key to a temp file and return path, or None."""
    import tempfile

    if ssh_key_text:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
            f.write(ssh_key_text)
            path = f.name
        os.chmod(path, 0o600)
        return path
    if key_id:
        secret = store.get_secret_by_id(key_id)
        if secret:
            ssh_data = secret.get("secret", "")
            # Only treat as raw key if it doesn't look like a user:host string
            if not ("|" in ssh_data and ":" in ssh_data.split("|")[0]):
                with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
                    f.write(ssh_data)
                    path = f.name
                os.chmod(path, 0o600)
                return path
    return None


def _start_output_streaming(socketio, ssh_manager, connection_id):
    """
    Background thread that continuously reads SSH output and pushes it
    to the WebSocket room. This replaces the fire-and-forget polling in
    the old handle_ssh_command handler.
    """
    import threading
    import time

    def stream():
        while True:
            terminal = ssh_manager.get_connection(connection_id)
            if not terminal or not terminal.connected:
                socketio.emit(
                    "ssh_disconnected",
                    {"connection_id": connection_id, "message": "Connection closed"},
                    to=connection_id,
                )
                break
            output = terminal.get_output()
            if output:
                socketio.emit(
                    "ssh_output",
                    {"connection_id": connection_id, "output": output},
                    to=connection_id,
                )
            time.sleep(0.1)

    t = threading.Thread(target=stream, daemon=True)
    t.start()
