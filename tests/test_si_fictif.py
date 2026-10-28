"""Tests du générateur du SI fictif."""

import json
import stat

import pytest

from quantum_ready.si_fictif import generer
from quantum_ready.si_fictif.__main__ import main
from quantum_ready.si_fictif.generateur import Contexte, ErreurGenerateur, remplir


@pytest.fixture(scope="module")
def si(tmp_path_factory):
    """Un SI fictif généré une seule fois pour tout le module de tests."""
    racine = tmp_path_factory.mktemp("si") / "v1"
    return generer(racine, racine.parent / "hors_si")


# --- Mécanique du générateur ---


def test_remplir_remplace_les_variables():
    assert remplir("a={{A}} $garde", {"A": "1"}) == "a=1 $garde"


def test_remplir_refuse_une_variable_oubliee():
    with pytest.raises(ErreurGenerateur, match="{{B}}"):
        remplir("{{A}} {{B}}", {"A": "1"})


def test_ecrire_prive_met_les_droits_600(tmp_path):
    ctx = Contexte(racine_si=tmp_path / "si", racine_hors_si=tmp_path / "hors")
    cible = ctx.ecrire("dossier/cle.key", b"x", prive=True)
    assert stat.S_IMODE(cible.stat().st_mode) == 0o600
    assert ctx.fichiers == ["dossier/cle.key"]


def test_refuse_d_ecraser_sans_option(tmp_path):
    (tmp_path / "v1").mkdir()
    with pytest.raises(ErreurGenerateur, match="existe déjà"):
        generer(tmp_path / "v1")


def test_secrets_hors_si(si):
    secrets = json.loads((si.racine_hors_si / "secrets.json").read_text(encoding="utf-8"))
    assert {"MOT_DE_PASSE_BASE", "MOT_DE_PASSE_CONTENEUR_FACTURES"} <= set(secrets)
    assert si.racine_hors_si not in si.racine_si.parents


def test_ligne_de_commande(tmp_path, capsys):
    sortie = tmp_path / "v1"
    assert main(["--sortie", str(sortie), "--hors-si", str(tmp_path / "h")]) == 0
    assert "SI v1 généré" in capsys.readouterr().out
    assert main(["--sortie", str(sortie), "--hors-si", str(tmp_path / "h")]) == 1
