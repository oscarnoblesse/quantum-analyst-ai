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
    message = reproduire.openssl_manquant(windows=False)
    assert "openssl est introuvable" in message and "QR-015" in message and "Installez OpenSSL" in message


def test_openssl_absent_sous_windows_indique_celui_de_git(monkeypatch, tmp_path):
    openssl = tmp_path / "Git" / "usr" / "bin" / "openssl.exe"
    openssl.parent.mkdir(parents=True)
    openssl.touch()
    git = tmp_path / "Git" / "cmd" / "git.exe"
    git.parent.mkdir(parents=True)
    git.touch()
    monkeypatch.setattr(reproduire.shutil, "which", lambda nom: str(git) if nom == "git" else None)
    message = reproduire.openssl_manquant(windows=True)
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


def test_option_si_v2_genere_puis_controle():
    libelles = [libelle for libelle, _ in reproduire.etapes_si_v2()]
    assert libelles[-2:] == ["Générer le SI fictif v2", "Vérifier le SI v2 contre sa vérité terrain"]
    commandes = [" ".join(c) for _, c in reproduire.etapes_si_v2()]
    assert any("--variante v2" in c for c in commandes)
    assert any("controles_v2" in c and "leurres_v2.csv" in c for c in commandes)


def test_reproduction_complete_inclut_le_si_v2():
    complete = [libelle for libelle, _ in reproduire.etapes(petite=False)]
    assert "Générer le SI fictif v2" in complete
    assert "Générer le SI fictif v2" not in [libelle for libelle, _ in reproduire.etapes(petite=True)]
