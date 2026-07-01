"""Tests for .env loading boundaries."""

import os

from asset_review import config


def test_dotenv_stops_at_repo_root(tmp_path, monkeypatch):
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    nested = repo / "sub"
    nested.mkdir()
    (tmp_path / ".env").write_text("STOLEN=1\n")
    (repo / ".env").write_text("EXPECTED=1\n")

    monkeypatch.delenv("STOLEN", raising=False)
    monkeypatch.delenv("EXPECTED", raising=False)
    config.load_dotenv(nested)
    assert "STOLEN" not in os.environ
    assert os.environ.get("EXPECTED") == "1"


def test_dotenv_no_file_in_repo_does_not_walk_past_root(tmp_path, monkeypatch):
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / ".git").mkdir()
    nested = repo / "sub"
    nested.mkdir()
    (tmp_path / ".env").write_text("STOLEN=1\n")

    monkeypatch.delenv("STOLEN", raising=False)
    config.load_dotenv(nested)
    assert "STOLEN" not in os.environ
