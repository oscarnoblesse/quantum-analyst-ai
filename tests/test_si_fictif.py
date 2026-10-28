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


# --- Clés SSH (QR-023 à QR-026, QR-032, QR-034, QR-035) ---

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa  # noqa: E402

from quantum_ready.si_fictif.ssh import publique_dsa_openssh  # noqa: E402


def _cle_ssh(si, chemin):
    return serialization.load_ssh_private_key((si.racine_si / chemin).read_bytes(), password=None)


def _ligne_publique(cle):
    return cle.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()


@pytest.mark.parametrize(
    "nom, type_attendu, taille",
    [("ed25519", ed25519.Ed25519PrivateKey, None),
     ("rsa", rsa.RSAPrivateKey, 3072),
     ("ecdsa", ec.EllipticCurvePrivateKey, 256)],
)
def test_cles_hote(si, nom, type_attendu, taille):
    chemin = f"ssh/server/ssh_host_{nom}_key"
    cle = _cle_ssh(si, chemin)
    assert isinstance(cle, type_attendu)
    if taille:
        assert cle.key_size == taille
    assert stat.S_IMODE((si.racine_si / chemin).stat().st_mode) == 0o600
    publique = (si.racine_si / (chemin + ".pub")).read_text(encoding="utf-8")
    assert publique.startswith(_ligne_publique(cle))


def test_ancienne_cle_dsa(si):
    privee = (si.racine_si / "ssh/server/old/ssh_host_dsa_key").read_bytes()
    assert privee.startswith(b"-----BEGIN DSA PRIVATE KEY-----")
    cle = serialization.load_pem_private_key(privee, password=None)
    assert isinstance(cle, dsa.DSAPrivateKey) and cle.key_size == 1024
    publique = (si.racine_si / "ssh/server/old/ssh_host_dsa_key.pub").read_text(encoding="utf-8")
    assert publique == publique_dsa_openssh(cle, "root@ssh-lab")


def test_cle_admin_et_authorized_keys(si):
    cle = _cle_ssh(si, "clients/admin/.ssh/id_ed25519")  # chargée sans mot de passe : non chiffrée
    assert isinstance(cle, ed25519.Ed25519PrivateKey)
    autorisees = (si.racine_si / "ssh/server/home/admin/.ssh/authorized_keys").read_text(encoding="utf-8")
    assert autorisees.startswith(_ligne_publique(cle))


def test_known_hosts(si):
    hote = _cle_ssh(si, "ssh/server/ssh_host_ed25519_key")
    ligne = (si.racine_si / "clients/admin/.ssh/known_hosts").read_text(encoding="utf-8").strip()
    assert ligne == "ssh.lab.local " + _ligne_publique(hote)
