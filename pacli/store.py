import os
import uuid
import time
import base64
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
from .log import get_logger

# Salt and Fernet key management: store/load salt from ~/.config/pacli/salt.bin and derive key from master password

SALT_PATH = os.path.expanduser("~/.config/pacli/salt.bin")
logger = get_logger("pacli.store")


def get_salt():
    if not os.path.exists(SALT_PATH):
        os.makedirs(os.path.dirname(SALT_PATH), exist_ok=True)
        salt = os.urandom(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_PATH, "rb") as f:
        return f.read()


class SecretStore:
    _session_fernet = None  # Class-level cache for session

    def __init__(self, db_path="~/.config/pacli/sqlite3.db"):
        db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        # Add id column as primary key if not exists, and add creation_time and update_time columns
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS secrets
                             (id TEXT PRIMARY KEY, label TEXT, value_encrypted TEXT, type TEXT, creation_time INTEGER, update_time INTEGER)"""
        )
        # Migrate old table if needed
        try:
            self.conn.execute("SELECT creation_time FROM secrets LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE secrets ADD COLUMN creation_time INTEGER")
        try:
            self.conn.execute("SELECT update_time FROM secrets LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE secrets ADD COLUMN update_time INTEGER")
        self.fernet = None

    def is_master_set(self):
        return os.path.exists(SALT_PATH + ".set")

    def set_master_password(self):
        salt = get_salt()
        while True:
            pw1 = getpass("Set a master password: ")
            pw2 = getpass("Confirm master password: ")
            if pw1 == pw2 and pw1:
                break
            print("Passwords do not match or empty. Try again.")
        with open(SALT_PATH + ".set", "w") as f:
            f.write("set")
        self.fernet = self._derive_fernet(pw1, salt)
        SecretStore._session_fernet = self.fernet
        logger.info("Master password set.")

    def _derive_fernet(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def require_fernet(self):
        if self.fernet is not None:
            return
        if SecretStore._session_fernet is not None:
            self.fernet = SecretStore._session_fernet
            return
        if not self.is_master_set():
            raise RuntimeError('Master password not set. Run "pacli init" first.')
        salt = get_salt()
        password = getpass("Enter master password: ")
        self.fernet = self._derive_fernet(password, salt)
        SecretStore._session_fernet = self.fernet

    def save_secret(self, label, secret, secret_type):
        self.require_fernet()
        encrypted = self.fernet.encrypt(secret.encode()).decode()
        now = int(time.time())
        new_id = uuid.uuid4().hex[:8]  # 8-character unique ID
        self.conn.execute(
            "INSERT INTO secrets (id, label, value_encrypted, type, creation_time, update_time) VALUES (?, ?, ?, ?, ?, ?)",
            (new_id, label, encrypted, secret_type, now, now),
        )
        self.conn.commit()

    def get_secret(self, label):
        self.require_fernet()
        try:
            cursor = self.conn.execute(
                "SELECT value_encrypted, type FROM secrets WHERE label = ? ORDER BY rowid DESC LIMIT 1",
                (label,),
            )
            row = cursor.fetchone()
            if row:
                try:
                    value = self.fernet.decrypt(row[0].encode()).decode()
                    return value, row[1]
                except Exception as e:
                    logger.error(f"Decryption failed for label {label}: {e}")
                    return None, None
            else:
                logger.info(f"Secret not found for label: {label}")
                return None, None
        except Exception as e:
            logger.error(f"Database error on get_secret for {label}: {e}")
            return None, None

    def list_secrets(self):
        return [
            (row[0], row[1], row[2], row[3], row[4])
            for row in self.conn.execute(
                "SELECT id, label, type, creation_time, update_time FROM secrets"
            )
        ]

    def delete_secret(self, id):
        self.require_fernet()
        self.conn.execute("DELETE FROM secrets WHERE id = ?", (id,))
        self.conn.commit()

    def get_secret_by_id(self, id):
        self.require_fernet()
        cursor = self.conn.execute(
            "SELECT label, value_encrypted, type, creation_time, update_time FROM secrets WHERE id = ?",
            (id,),
        )
        row = cursor.fetchone()
        if row:
            try:
                value = self.fernet.decrypt(row[1].encode()).decode()
                return {
                    "id": id,
                    "label": row[0],
                    "secret": value,
                    "type": row[2],
                    "creation_time": row[3],
                    "update_time": row[4],
                }
            except Exception as e:
                logger.error(f"Decryption failed for id {id}: {e}")
                return None
        else:
            logger.info(f"No secret found with id: {id}")
            return None

    def get_secrets_by_label(self, label):
        self.require_fernet()
        results = []
        for row in self.conn.execute(
            "SELECT id, value_encrypted, type, creation_time, update_time FROM secrets WHERE label = ? ORDER BY creation_time DESC",
            (label,),
        ):
            try:
                value = self.fernet.decrypt(row[1].encode()).decode()
            except Exception as e:
                logger.error(f"Decryption failed for id {row[0]}: {e}")
                value = None
            results.append(
                {
                    "id": row[0],
                    "secret": value,
                    "type": row[2],
                    "creation_time": row[3],
                    "update_time": row[4],
                }
            )
        return results

    def verify_master_password(self, password):
        try:
            salt = get_salt()
            self._derive_fernet(password, salt)
            return True
        except Exception as e:
            logger.error(f"Master password verification failed: {e}")
            return False
