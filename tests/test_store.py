import os


def _configure_store_paths(monkeypatch, tmp_path):
    import pacli.store as store

    monkeypatch.setattr(store, "SALT_PATH", str(tmp_path / "salt.bin"))
    monkeypatch.setattr(store, "PASSWORD_HASH_PATH", str(tmp_path / "password_hash.bin"))
    return store


def _mark_master_set(store_module):
    with open(store_module.SALT_PATH + ".set", "w", encoding="utf-8") as f:
        f.write("set")


def _build_store(store_module, tmp_path, password="master-pass"):
    _mark_master_set(store_module)
    store = store_module.SecretStore(db_path=str(tmp_path / "secrets.db"))
    store.fernet = store._derive_fernet(password, store_module.get_salt())
    return store


def test_get_salt_is_created_and_reused(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)

    first = store_module.get_salt()
    second = store_module.get_salt()

    assert len(first) == 16
    assert first == second


def test_secret_store_crud_and_queries(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    store = _build_store(store_module, tmp_path)

    store.save_secret("github", "tok-1", "token")

    value, secret_type = store.get_secret("github")
    assert value == "tok-1"
    assert secret_type == "token"

    rows = store.list_secrets()
    assert len(rows) == 1
    secret_id = rows[0][0]

    store.update_secret(secret_id, "tok-2")
    by_id = store.get_secret_by_id(secret_id)
    assert by_id is not None
    assert by_id["secret"] == "tok-2"

    by_label = store.get_secrets_by_label("github")
    assert len(by_label) == 1
    assert by_label[0]["secret"] == "tok-2"

    store.delete_secret(secret_id)
    assert store.get_secret_by_id(secret_id) is None


def test_verify_master_password_via_hash(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    store = _build_store(store_module, tmp_path)

    store.update_master_password("new-password")

    assert store.verify_master_password("new-password") is True
    assert store.verify_master_password("wrong") is False


def test_require_fernet_non_interactive_without_loaded_key(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    _mark_master_set(store_module)
    store = store_module.SecretStore(db_path=str(tmp_path / "x.db"))

    monkeypatch.delenv("PACLI_MASTER_PASSWORD", raising=False)

    import pytest

    with pytest.raises(RuntimeError, match="Master key is not loaded"):
        store.require_fernet(interactive=False)


def test_require_fernet_uses_env_password(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    _mark_master_set(store_module)
    store = store_module.SecretStore(db_path=str(tmp_path / "env.db"))

    monkeypatch.setenv("PACLI_MASTER_PASSWORD", "env-pass")
    store.require_fernet()

    assert store.fernet is not None


def test_export_import_encrypted_backup_and_merge_modes(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)

    source = _build_store(store_module, tmp_path, password="source-master")
    source.save_secret("alpha", "value-a", "token")
    source.save_secret("beta", "value-b", "password")

    blob = source.export_encrypted_backup("backup-pass")
    assert isinstance(blob, bytes)
    assert blob

    target = _build_store(store_module, tmp_path / "target", password="target-master")
    stats_first = target.import_encrypted_backup(blob, "backup-pass", merge=True)
    assert stats_first == {"imported": 2, "skipped": 0, "errors": 0}

    stats_merge = target.import_encrypted_backup(blob, "backup-pass", merge=True)
    assert stats_merge == {"imported": 0, "skipped": 2, "errors": 0}

    stats_overwrite = target.import_encrypted_backup(blob, "backup-pass", merge=False)
    assert stats_overwrite == {"imported": 2, "skipped": 0, "errors": 0}


def test_import_encrypted_backup_wrong_password(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)

    source = _build_store(store_module, tmp_path / "src", password="m1")
    source.save_secret("alpha", "value-a", "token")
    blob = source.export_encrypted_backup("correct-backup-password")

    target = _build_store(store_module, tmp_path / "dst", password="m2")

    import pytest

    with pytest.raises(ValueError, match="Wrong backup password"):
        target.import_encrypted_backup(blob, "wrong-password", merge=True)


def test_get_secret_handles_decrypt_error(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    store = _build_store(store_module, tmp_path)

    now = 1000
    store.conn.execute(
        "INSERT INTO secrets (id, label, value_encrypted, type, creation_time, update_time) VALUES (?, ?, ?, ?, ?, ?)",
        ("deadbeef", "bad", "not-encrypted", "token", now, now),
    )
    store.conn.commit()

    assert store.get_secret("bad") == (None, None)


def test_get_secret_by_id_and_by_label_decrypt_error_paths(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    store = _build_store(store_module, tmp_path)

    now = 1000
    store.conn.execute(
        "INSERT INTO secrets (id, label, value_encrypted, type, creation_time, update_time) VALUES (?, ?, ?, ?, ?, ?)",
        ("cafebabe", "dup", "broken", "token", now, now),
    )
    store.conn.commit()

    assert store.get_secret_by_id("cafebabe") is None
    rows = store.get_secrets_by_label("dup")
    assert len(rows) == 1
    assert rows[0]["secret"] is None


def test_verify_master_password_fallback_path(monkeypatch, tmp_path):
    store_module = _configure_store_paths(monkeypatch, tmp_path)
    store = _build_store(store_module, tmp_path, password="master")
    store.save_secret("api", "v", "token")

    if os.path.exists(store_module.PASSWORD_HASH_PATH):
        os.remove(store_module.PASSWORD_HASH_PATH)

    assert store.verify_master_password("master") is True
    assert store.verify_master_password("not-master") is False
