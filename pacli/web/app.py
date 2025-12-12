import os
import uuid

# import json
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from datetime import datetime
from ..store import SecretStore
from ..log import get_logger
from .ssh_handler import SSHConnectionManager

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

    # Initialize store and SSH manager
    store = SecretStore()
    ssh_manager = SSHConnectionManager()

    # Initialize SocketIO for WebSocket support
    socketio = SocketIO(app, cors_allowed_origins="*")

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
        """Get a specific secret by ID (without revealing the actual secret value)."""
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                # Return secret metadata without the actual secret value
                return jsonify(
                    {
                        "id": secret.get("id"),
                        "label": secret.get("label"),
                        "type": secret.get("type"),
                        "creation_time": secret.get("creation_time"),
                        "update_time": secret.get("update_time"),
                        "secret": "•••••••",  # Placeholder instead of actual secret
                    }
                )
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

    @app.route("/api/secrets/<secret_id>/reveal", methods=["GET"])
    @require_auth
    def reveal_secret(secret_id):
        """Reveal the actual secret value (only when user explicitly requests it)."""
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                # Return only the secret value
                return jsonify({"secret": secret.get("secret")})
            else:
                return jsonify({"error": "Secret not found"}), 404
        except Exception as e:
            logger.error(f"Error revealing secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500

    # SSH Terminal API Endpoints
    @app.route("/api/ssh/connect", methods=["POST"])
    @require_auth
    def ssh_connect():
        """Initiate SSH connection."""
        try:
            data = request.get_json()
            hostname = data.get("hostname")
            username = data.get("username")
            port = data.get("port", 22)
            password = data.get("password")
            key_id = data.get("key_id")  # Secret ID for SSH key
            ssh_key = data.get("ssh_key")  # Direct SSH key input

            # If only key_id is provided, parse the SSH connection details from the secret
            if key_id and not hostname:
                try:
                    secret = store.get_secret_by_id(key_id)
                    if not secret:
                        return jsonify({"error": "SSH server not found"}), 404

                    ssh_data = secret.get("secret", "")

                    # Check if this is a stored SSH config (user:host|...) or just a key
                    if "|" in ssh_data and ":" in ssh_data.split("|")[0]:
                        # Parse SSH format: user:host|key:path|port:22|opts:...
                        parts = ssh_data.split("|")
                        user_ip = parts[0]

                        if ":" not in user_ip:
                            return jsonify({"error": "Invalid SSH format in stored server"}), 400

                        username, hostname = user_ip.split(":", 1)

                        # Parse additional options
                        for part in parts[1:]:
                            if part.startswith("port:"):
                                try:
                                    port = int(part[5:])
                                except ValueError:
                                    pass

                        # Mark that we found a stored SSH config
                        key_id = None  # Don't try to use key_id as a separate secret
                    else:
                        # This is just an SSH key without connection details
                        return (
                            jsonify(
                                {
                                    "error": (
                                        "SSH server configuration incomplete. "
                                        "Please use manual connection with this key."
                                    )
                                }
                            ),
                            400,
                        )
                except Exception as e:
                    logger.error(f"Error parsing SSH server: {e}")
                    return jsonify({"error": "Failed to parse SSH server details"}), 400

            if not hostname or not username:
                return jsonify({"error": "Hostname and username are required"}), 400

            # Get SSH key from secrets if key_id provided (and it's not a stored SSH config)
            # Or use direct ssh_key input for manual connections
            key_filename = None
            if ssh_key:
                # Direct SSH key input from manual connection
                try:
                    import tempfile

                    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
                        f.write(ssh_key)
                        key_filename = f.name
                    os.chmod(key_filename, 0o600)
                except Exception as e:
                    logger.error(f"Error saving SSH key: {e}")
                    return jsonify({"error": "Failed to save SSH key"}), 400
            elif key_id:
                try:
                    secret = store.get_secret_by_id(key_id)
                    if secret:
                        ssh_data = secret.get("secret", "")
                        # Check if this is a stored SSH config or just a key
                        if "|" in ssh_data and ":" in ssh_data.split("|")[0]:
                            # This is a stored SSH config, don't use it as a key
                            pass
                        else:
                            # This is an SSH key, save it to temp file
                            import tempfile

                            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
                                f.write(ssh_data)
                                key_filename = f.name
                            os.chmod(key_filename, 0o600)
                except Exception as e:
                    logger.error(f"Error retrieving SSH key: {e}")
                    return jsonify({"error": "Failed to retrieve SSH key"}), 400

            # Create connection
            connection_id = str(uuid.uuid4())
            if ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename):
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
            else:
                return jsonify({"error": "Failed to establish SSH connection"}), 400

        except Exception as e:
            logger.error(f"Error in SSH connect: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ssh/disconnect/<connection_id>", methods=["POST"])
    @require_auth
    def ssh_disconnect(connection_id):
        """Close SSH connection."""
        try:
            ssh_manager.close_connection(connection_id)
            return jsonify({"success": True, "message": "Disconnected"})
        except Exception as e:
            logger.error(f"Error disconnecting SSH: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ssh/execute", methods=["POST"])
    @require_auth
    def ssh_execute():
        """Execute command on SSH connection."""
        try:
            data = request.get_json()
            connection_id = data.get("connection_id")
            command = data.get("command")

            if not connection_id or not command:
                return jsonify({"error": "Connection ID and command are required"}), 400

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                return jsonify({"error": "Connection not found"}), 404

            # Send command
            if terminal.send_command(command + "\n"):
                # Get output
                import time

                time.sleep(0.5)  # Wait for command execution
                output = terminal.get_output()
                return jsonify({"success": True, "output": output})
            else:
                return jsonify({"error": "Failed to send command"}), 400

        except Exception as e:
            logger.error(f"Error executing SSH command: {e}")
            return jsonify({"error": str(e)}), 500

    # WebSocket events for real-time terminal
    @socketio.on("connect")
    def handle_connect():
        """Handle WebSocket connection."""
        logger.info("Client connected to WebSocket")
        emit("response", {"data": "Connected to SSH terminal server"})

    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle WebSocket disconnection."""
        logger.info("Client disconnected from WebSocket")

    @socketio.on("ssh_connect")
    def handle_ssh_connect(data):
        """Handle SSH connection via WebSocket."""
        try:
            if "authenticated" not in session:
                emit("error", {"message": "Unauthorized"})
                return

            hostname = data.get("hostname")
            username = data.get("username")
            port = data.get("port", 22)
            password = data.get("password")
            key_id = data.get("key_id")
            ssh_key = data.get("ssh_key")  # Direct SSH key input

            # If only key_id is provided, parse the SSH connection details from the secret
            if key_id and not hostname:
                try:
                    secret = store.get_secret_by_id(key_id)
                    if not secret:
                        emit("error", {"message": "SSH server not found"})
                        return

                    ssh_data = secret.get("secret", "")

                    # Check if this is a stored SSH config (user:host|...) or just a key
                    if "|" in ssh_data and ":" in ssh_data.split("|")[0]:
                        # Parse SSH format: user:host|key:path|port:22|opts:...
                        parts = ssh_data.split("|")
                        user_ip = parts[0]

                        if ":" not in user_ip:
                            emit("error", {"message": "Invalid SSH format in stored server"})
                            return

                        username, hostname = user_ip.split(":", 1)

                        # Parse additional options
                        for part in parts[1:]:
                            if part.startswith("port:"):
                                try:
                                    port = int(part[5:])
                                except ValueError:
                                    pass

                        # Mark that we found a stored SSH config
                        key_id = None  # Don't try to use key_id as a separate secret
                    else:
                        # This is just an SSH key without connection details
                        emit(
                            "error",
                            {
                                "message": (
                                    "SSH server configuration incomplete. "
                                    "Please use manual connection with this key."
                                )
                            },
                        )
                        return
                except Exception as e:
                    logger.error(f"Error parsing SSH server: {e}")
                    emit("error", {"message": "Failed to parse SSH server details"})
                    return

            if not hostname or not username:
                emit("error", {"message": "Hostname and username required"})
                return

            # Get SSH key from secrets if key_id provided (and it's not a stored SSH config)
            # Or use direct ssh_key input for manual connections
            key_filename = None
            if ssh_key:
                # Direct SSH key input from manual connection
                try:
                    import tempfile

                    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
                        f.write(ssh_key)
                        key_filename = f.name
                    os.chmod(key_filename, 0o600)
                except Exception as e:
                    logger.error(f"Error saving SSH key: {e}")
                    emit("error", {"message": "Failed to save SSH key"})
                    return
            elif key_id:
                try:
                    secret = store.get_secret_by_id(key_id)
                    if secret:
                        ssh_data = secret.get("secret", "")
                        # Check if this is a stored SSH config or just a key
                        if "|" in ssh_data and ":" in ssh_data.split("|")[0]:
                            # This is a stored SSH config, don't use it as a key
                            pass
                        else:
                            # This is an SSH key, save it to temp file
                            import tempfile

                            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
                                f.write(ssh_data)
                                key_filename = f.name
                            os.chmod(key_filename, 0o600)
                except Exception as e:
                    logger.error(f"Error retrieving SSH key: {e}")
                    emit("error", {"message": "Failed to retrieve SSH key"})
                    return

            # Create connection
            connection_id = str(uuid.uuid4())
            if ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename):
                join_room(connection_id)
                emit(
                    "ssh_connected", {"connection_id": connection_id, "message": f"Connected to {username}@{hostname}"}
                )
            else:
                emit("error", {"message": "Failed to establish SSH connection"})

        except Exception as e:
            logger.error(f"Error in WebSocket SSH connect: {e}")
            emit("error", {"message": str(e)})

    @socketio.on("ssh_command")
    def handle_ssh_command(data):
        """Handle SSH command execution via WebSocket."""
        try:
            connection_id = data.get("connection_id")
            command = data.get("command")

            if not connection_id or not command:
                emit("error", {"message": "Connection ID and command required"})
                return

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                emit("error", {"message": "Connection not found"})
                return

            # Send command
            if terminal.send_command(command + "\n"):
                import time

                time.sleep(0.2)
                output = terminal.get_output()
                emit("ssh_output", {"connection_id": connection_id, "output": output}, to=connection_id)
            else:
                emit("error", {"message": "Failed to send command"})

        except Exception as e:
            logger.error(f"Error in WebSocket SSH command: {e}")
            emit("error", {"message": str(e)})

    @socketio.on("ssh_disconnect")
    def handle_ssh_disconnect(data):
        """Handle SSH disconnection via WebSocket."""
        try:
            connection_id = data.get("connection_id")
            if connection_id:
                ssh_manager.close_connection(connection_id)
                leave_room(connection_id)
                emit("ssh_disconnected", {"connection_id": connection_id, "message": "Disconnected"})
        except Exception as e:
            logger.error(f"Error in WebSocket SSH disconnect: {e}")
            emit("error", {"message": str(e)})

    return app, socketio
