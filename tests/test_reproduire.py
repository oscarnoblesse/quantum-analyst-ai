"""scripts/reproduire.py : arrêt clair quand openssl manque (sinon QR-015 n'est pas détecté)."""

import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("reproduire", RACINE / "scripts" / "reproduire.py")
reproduire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reproduire)


def _which(presents):
    return lambda nom: f"/usr/bin/{nom}" if nom in presents else None


def test_openssl_present(monkeypatch):
    monkeypatch.setattr(reproduire.shutil, "which", _which({"openssl"}))
    assert reproduire.openssl_manquant() is None


def test_openssl_absent_hors_windows(monkeypatch):
    monkeypatch.setattr(reproduire.shutil, "which", _which(set()))
    monkeypatch.setattr(reproduire.os, "name", "posix")
    message = reproduire.openssl_manquant()
    assert "openssl est introuvable" in message and "QR-015" in message and "Installez OpenSSL" in message


def test_openssl_absent_sous_windows_indique_celui_de_git(monkeypatch, tmp_path):
    openssl = tmp_path / "Git" / "usr" / "bin" / "openssl.exe"
    openssl.parent.mkdir(parents=True)
    openssl.touch()
    git = tmp_path / "Git" / "cmd" / "git.exe"
    git.parent.mkdir(parents=True)
    git.touch()
    monkeypatch.setattr(reproduire.shutil, "which", lambda nom: str(git) if nom == "git" else None)
    monkeypatch.setattr(reproduire.os, "name", "nt")
    message = reproduire.openssl_manquant()
    assert str(openssl.parent) in message and "$env:Path" in message


def test_openssl_de_git_sans_git(monkeypatch):
    monkeypatch.setattr(reproduire.shutil, "which", _which(set()))
    assert reproduire.openssl_de_git() is None


def test_main_s_arrete_avant_toute_etape(monkeypatch, capsys):
    monkeypatch.setattr(reproduire.shutil, "which", _which({"uv"}))
    monkeypatch.setattr(reproduire.sys, "argv", ["reproduire.py"])
    lancees = []
    monkeypatch.setattr(reproduire.subprocess, "run", lambda *a, **k: lancees.append(a))
    assert reproduire.main() == 2
    assert lancees == [] and "openssl est introuvable" in capsys.readouterr().err
