import os
import shutil
import tempfile
import pytest
from pacli.store import SecretStore


@pytest.fixture(scope="function")
def temp_db_env(monkeypatch):
    # Setup a temp config dir and db for isolation
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "sqlite3.db")
    salt_path = os.path.join(temp_dir, "salt.bin")
    salt_set_path = salt_path + ".set"
    monkeypatch.setattr("pacli.store.SALT_PATH", salt_path)
    yield db_path, salt_path, salt_set_path
    shutil.rmtree(temp_dir)


def test_master_password_set_and_verify(temp_db_env, monkeypatch):
    db_path, salt_path, salt_set_path = temp_db_env
    store = SecretStore(db_path=db_path)
    monkeypatch.setattr("builtins.input", lambda _: "testpass")
    monkeypatch.setattr("getpass.getpass", lambda _: "testpass")
    store.set_master_password()
    assert os.path.exists(salt_path)
    assert os.path.exists(salt_set_path)
    assert store.verify_master_password("testpass")
    assert not store.verify_master_password("wrongpass")


def test_add_and_get_secret(temp_db_env, monkeypatch):
    db_path, salt_path, salt_set_path = temp_db_env
    store = SecretStore(db_path=db_path)
    monkeypatch.setattr("getpass.getpass", lambda _: "testpass")
    store.set_master_password()
    store.save_secret("label1", "mytoken", "token")
    value, stype = store.get_secret("label1")
    assert value == "mytoken"
    assert stype == "token"


def test_change_master_password(temp_db_env, monkeypatch):
    db_path, salt_path, salt_set_path = temp_db_env
    store = SecretStore(db_path=db_path)
    monkeypatch.setattr("getpass.getpass", lambda _: "oldpass")
    store.set_master_password()
    store.save_secret("label2", "secret2", "token")
    # Simulate change master password
    store.require_fernet()
    all_secrets = []
    for row in store.conn.execute("SELECT id, value_encrypted FROM secrets"):
        decrypted = store.fernet.decrypt(row[1].encode()).decode()
        all_secrets.append((row[0], decrypted))
    # Set new password
    monkeypatch.setattr("getpass.getpass", lambda _: "newpass")
    store.set_master_password()
    store.require_fernet()
    for sid, plain in all_secrets:
        encrypted = store.fernet.encrypt(plain.encode()).decode()
        store.conn.execute(
            "UPDATE secrets SET value_encrypted = ? WHERE id = ?", (encrypted, sid)
        )
    store.conn.commit()
    # Verify secret is still accessible
    value, stype = store.get_secret("label2")
    assert value == "secret2"
    assert stype == "token"
