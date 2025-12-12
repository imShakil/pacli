"""SSH connection handler for web-based terminal access."""

import paramiko  # type: ignore[import-untyped]
import threading
import queue
import time
import socket
from ..log import get_logger

logger = get_logger("pacli.web.ssh_handler")


class SSHTerminal:
    """Manages SSH connection and terminal I/O."""

    def __init__(self, hostname, username, port=22, password=None, key_filename=None):
        """Initialize SSH terminal connection.

        Args:
            hostname: SSH server hostname
            username: SSH username
            port: SSH port (default 22)
            password: SSH password (optional)
            key_filename: Path to SSH private key (optional)
        """
        self.hostname = hostname
        self.username = username
        self.port = port
        self.password = password
        self.key_filename = key_filename

        self.client = None
        self.channel = None
        self.output_queue = queue.Queue()
        self.input_queue = queue.Queue()
        self.connected = False
        self.reader_thread = None
        self._stop_event = threading.Event()

    def connect(self):
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            # nosec B507: AutoAddPolicy is intentional for user-managed SSH connections
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec

            # Connect with password or key
            if self.key_filename:
                self.client.connect(
                    self.hostname, port=self.port, username=self.username, key_filename=self.key_filename, timeout=10
                )
            else:
                self.client.connect(
                    self.hostname, port=self.port, username=self.username, password=self.password, timeout=10
                )

            # Open interactive shell
            self.channel = self.client.invoke_shell(term="xterm")
            self.channel.settimeout(0.1)
            self.connected = True

            # Start reader thread
            self._stop_event.clear()
            self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self.reader_thread.start()

            logger.info(f"Connected to {self.username}@{self.hostname}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            self.connected = False
            return False

    def _read_output(self):
        """Read output from SSH channel in background thread."""
        while not self._stop_event.is_set() and self.connected:
            try:
                if self.channel and self.channel.recv_ready():
                    data = self.channel.recv(4096)
                    if data:
                        self.output_queue.put(data.decode("utf-8", errors="replace"))
                time.sleep(0.01)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error reading SSH output: {e}")
                break

    def send_command(self, command):
        """Send command to SSH terminal.

        Args:
            command: Command string to execute
        """
        if not self.connected or not self.channel:
            return False

        try:
            self.channel.send(command)
            return True
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return False

    def get_output(self):
        """Get available output from SSH terminal.

        Returns:
            String containing terminal output
        """
        output = ""
        try:
            while True:
                output += self.output_queue.get_nowait()
        except queue.Empty:
            pass
        return output

    def disconnect(self):
        """Close SSH connection."""
        try:
            self._stop_event.set()
            if self.reader_thread:
                self.reader_thread.join(timeout=2)
            if self.channel:
                self.channel.close()
            if self.client:
                self.client.close()
            self.connected = False
            logger.info(f"Disconnected from {self.username}@{self.hostname}")
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")


class SSHConnectionManager:
    """Manages multiple SSH connections."""

    def __init__(self):
        """Initialize connection manager."""
        self.connections = {}

    def create_connection(self, connection_id, hostname, username, port=22, password=None, key_filename=None):
        """Create and connect to SSH server.

        Args:
            connection_id: Unique identifier for this connection
            hostname: SSH server hostname
            username: SSH username
            port: SSH port (default 22)
            password: SSH password (optional)
            key_filename: Path to SSH private key (optional)

        Returns:
            True if connection successful, False otherwise
        """
        try:
            terminal = SSHTerminal(hostname, username, port, password, key_filename)
            if terminal.connect():
                self.connections[connection_id] = terminal
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to create connection {connection_id}: {e}")
            return False

    def get_connection(self, connection_id):
        """Get SSH terminal by connection ID.

        Args:
            connection_id: Connection identifier

        Returns:
            SSHTerminal instance or None
        """
        return self.connections.get(connection_id)

    def close_connection(self, connection_id):
        """Close SSH connection.

        Args:
            connection_id: Connection identifier
        """
        if connection_id in self.connections:
            self.connections[connection_id].disconnect()
            del self.connections[connection_id]

    def close_all(self):
        """Close all SSH connections."""
        for connection_id in list(self.connections.keys()):
            self.close_connection(connection_id)
