"""Lecture de la sortie `ssh -v` par le script du démonstrateur (sans Docker)."""

import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("demonstrateur", RACINE / "scripts" / "demonstrateur.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


def test_kex_hybride_lue_dans_la_sortie_ssh_v():
    sortie = "debug1: Local version string SSH-2.0-OpenSSH_10.0\ndebug1: kex: algorithm: mlkem768x25519-sha256\ndebug1: kex: host key algorithm: ssh-ed25519\n"
    assert demo.kex_negociee(sortie) == "mlkem768x25519-sha256"


def test_pas_de_kex_quand_l_echange_echoue():
    sortie = "Unable to negotiate with 127.0.0.1 port 2222: no matching key exchange method found.\n"
    assert demo.kex_negociee(sortie) is None
