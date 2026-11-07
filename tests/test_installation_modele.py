"""Installation du modèle : lecture de la configuration, parsing de `ollama list`, choix de l'installeur."""

import pytest

from quantum_ready import installation_modele as inst

LISTE = """NAME                             ID              SIZE      MODIFIED
qwen3:4b-instruct-2507-q4_K_M    0edcdef34593    2.5 GB    2 days ago
qwen3:4b                         359d7dd4bcda    2.5 GB    2 weeks ago
"""


def test_lire_modele_prend_nom_et_empreinte_de_la_configuration():
    nom, empreinte, hote = inst.lire_modele()
    assert nom == "qwen3:4b-instruct-2507-q4_K_M"
    assert empreinte == "0edcdef34593"
    assert hote == "http://localhost:11434"


def test_lire_empreinte_trouve_le_bon_modele():
    assert inst.lire_empreinte(LISTE, "qwen3:4b-instruct-2507-q4_K_M") == "0edcdef34593"
    assert inst.lire_empreinte(LISTE, "qwen3:4b") == "359d7dd4bcda"


def test_lire_empreinte_absent():
    assert inst.lire_empreinte(LISTE, "llama3.1:8b") is None
    assert inst.lire_empreinte("NAME ID SIZE MODIFIED\n", "qwen3:4b") is None


@pytest.mark.parametrize(
    ("systeme", "outil_present", "attendu"),
    [
        ("Darwin", "brew", ["brew", "install", "ollama"]),
        ("Windows", "winget", ["winget", "install", "--id", "Ollama.Ollama", "-e",
                               "--accept-package-agreements", "--accept-source-agreements"]),
    ],
)
def test_installeur_choisi_selon_le_systeme(monkeypatch, systeme, outil_present, attendu):
    commandes = []
    monkeypatch.setattr(inst.shutil, "which", lambda nom: f"/usr/bin/{nom}" if nom == outil_present else None)
    monkeypatch.setattr(inst.subprocess, "run", lambda cmd, **kw: commandes.append(cmd) or _ok())
    inst.installer_ollama(systeme)
    assert commandes == [attendu]


def test_sans_gestionnaire_on_indique_la_procedure_manuelle(monkeypatch):
    monkeypatch.setattr(inst.shutil, "which", lambda nom: None)
    with pytest.raises(inst.ErreurInstallation, match="ollama.com/download"):
        inst.installer_ollama("Darwin")


def _ok():
    class Resultat:
        returncode = 0
    return Resultat()
