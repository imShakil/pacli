import os
import shutil
import tempfile
import pytest
from pacli.store import SecretStore
import subprocess
import sys
from click.testing import CliRunner
from pacli.cli import cli


def test_pacli_version_cli():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "Version:" in result.output


def test_pacli_help_cli():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
