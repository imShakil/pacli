import shutil


def test_pacli_installed():
    assert shutil.which("pacli") is not None, "'pacli' is not installed or not in PATH"  # nosec
