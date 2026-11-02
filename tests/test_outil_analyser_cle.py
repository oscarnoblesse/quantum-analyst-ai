"""analyser_cle : formats de clés, chiffrement, empreintes identiques à ssh-keygen -l."""

import base64
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from quantum_ready.outils.analyser_cle import analyser_cle
from quantum_ready.outils.analyser_x509 import analyser_x509


def _unique(resultat):
    assert resultat.erreurs == [] and len(resultat.trouvailles) == 1
    return resultat.trouvailles[0]


@pytest.mark.parametrize(
    ("fichier", "nom", "chiffree"),
    [
        ("nginx/ssl/server.key", "RSA-2048", False),
        ("deploy/old/backup_2024/inter.key", "ECDSA P-384", False),
        ("ssh/server/old/ssh_host_dsa_key", "DSA-1024", False),
        ("ssh/server/ssh_host_rsa_key", "RSA-3072", False),
        ("clients/admin/.ssh/id_ed25519", "Ed25519", False),
    ],
)
def test_cles_privees(racine_si, fichier, nom, chiffree):
    cle = _unique(analyser_cle(fichier, racine=racine_si))
    assert (cle.nom, cle.proprietes["chiffree"], cle.exposition) == (nom, chiffree, "shor")
    assert "NON chiffrée" in cle.description


def test_la_cle_privee_se_relie_a_son_certificat(racine_si):
    cle = _unique(analyser_cle("nginx/ssl/server.key", racine=racine_si))
    cle_du_certificat = analyser_x509("nginx/ssl/server.crt", racine=racine_si).trouvailles[1]
    assert cle.proprietes["empreinte_spki_sha256"] == cle_du_certificat.proprietes["empreinte_spki_sha256"]


def test_pkcs8_chiffree_type_masque_et_piste(racine_si):
    resultat = analyser_cle("clients/admin/admin.key", racine=racine_si)
    cle = _unique(resultat)
    assert cle.exposition == "inconnue" and cle.proprietes["chiffree"] is True
    assert "PBKDF2" in cle.proprietes["chiffrement"] and "AES-256" in cle.proprietes["chiffrement"]
    assert resultat.pistes[0].vers == "clients/admin/"


def test_known_hosts_et_authorized_keys(racine_si):
    hote = _unique(analyser_cle("clients/admin/.ssh/known_hosts", racine=racine_si))
    assert hote.proprietes["hotes"] == ["ssh.lab.local"]
    cle_hote = _unique(analyser_cle("ssh/server/ssh_host_ed25519_key.pub", racine=racine_si))
    assert hote.proprietes["empreinte"] == cle_hote.proprietes["empreinte"]
    autorisee = _unique(analyser_cle("ssh/server/home/admin/.ssh/authorized_keys", racine=racine_si))
    privee = _unique(analyser_cle("clients/admin/.ssh/id_ed25519", racine=racine_si))
    assert autorisee.proprietes["empreinte"] == privee.proprietes["empreinte"]
    assert autorisee.proprietes["commentaire"] == "admin@poste-admin"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen absent")
@pytest.mark.parametrize("nom", ["ssh_host_ed25519_key.pub", "ssh_host_rsa_key.pub", "ssh_host_ecdsa_key.pub", "old/ssh_host_dsa_key.pub"])
def test_empreinte_identique_a_ssh_keygen(racine_si, nom):
    chemin = racine_si / "ssh/server" / nom
    sortie = subprocess.run(["ssh-keygen", "-lf", str(chemin)], capture_output=True, text=True, check=True).stdout
    taille, empreinte = sortie.split()[:2]
    cle = _unique(analyser_cle(f"ssh/server/{nom}", racine=racine_si))
    assert cle.proprietes["empreinte"] == empreinte
    assert cle.nom.endswith(taille) or taille == "256"


def test_cle_openpgp(racine_si):
    cle = _unique(analyser_cle("scripts/keys/backup_pub.asc", racine=racine_si))
    assert cle.nom == "RSA-3072" and cle.proprietes["identites"] == ["Sauvegardes Lab <backup@lab.local>"]


def test_parametres_dh(racine_si):
    dh = _unique(analyser_cle("nginx/ssl/dhparam.pem", racine=racine_si))
    assert (dh.type_actif, dh.nom, dh.proprietes["groupe_standard"]) == ("algorithm", "DH-2048", True)


def _chaine(donnees: bytes) -> bytes:
    return len(donnees).to_bytes(4, "big") + donnees


def test_cle_openssh_chiffree(tmp_path):
    """En-tête d'une clé chiffrée par ssh-keygen (la partie chiffrée n'est jamais lue par l'outil)."""
    publique = ed25519.Ed25519PrivateKey.generate().public_key()
    blob = base64.b64decode(publique.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1])
    structure = (
        b"openssh-key-v1\x00" + _chaine(b"aes256-ctr") + _chaine(b"bcrypt") + _chaine(b"options")
        + (1).to_bytes(4, "big") + _chaine(blob) + _chaine(b"partie chiffree")
    )
    corps = base64.b64encode(structure).decode()
    (tmp_path / "k").write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{corps}\n-----END OPENSSH PRIVATE KEY-----\n")
    trouvaille = _unique(analyser_cle("k", racine=tmp_path))
    assert trouvaille.nom == "Ed25519" and trouvaille.proprietes["chiffree"] is True
    assert trouvaille.proprietes["chiffrement"] == "aes256-ctr (dérivation bcrypt)"


def test_cle_traditionnelle_chiffree(tmp_path):
    cle = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "k.pem").write_bytes(cle.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.BestAvailableEncryption(b"x")
    ))
    trouvaille = _unique(analyser_cle("k.pem", racine=tmp_path))
    assert trouvaille.nom.startswith("ECDSA") and trouvaille.proprietes["chiffree"] is True


def test_rsa_1024_ssh_faible(tmp_path):
    cle = rsa.generate_private_key(65537, 1024)
    ligne = cle.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (tmp_path / "authorized_keys").write_bytes(b'from="10.0.0.1" ' + ligne + b" vieux\n# commentaire\n\n")
    trouvaille = _unique(analyser_cle("authorized_keys", racine=tmp_path))
    assert trouvaille.nom == "RSA-1024" and "faiblesse_classique" in trouvaille.proprietes
    assert trouvaille.proprietes["options"] == 'from="10.0.0.1"'


def test_fichier_sans_cle(racine_si):
    assert "Aucune clé" in analyser_cle("db/pg_hba.conf", racine=racine_si).erreurs[0]


def test_certificat_dans_un_fichier_de_cle(racine_si):
    resultat = analyser_cle("nginx/ssl/server.crt", racine=racine_si)
    assert "analyser_x509" in resultat.pistes[0].raison


def test_la_cle_dsa_pem_a_la_meme_empreinte_que_son_pub(racine_si):
    privee = _unique(analyser_cle("ssh/server/old/ssh_host_dsa_key", racine=racine_si))
    publique = _unique(analyser_cle("ssh/server/old/ssh_host_dsa_key.pub", racine=racine_si))
    assert privee.proprietes["empreinte"] == publique.proprietes["empreinte"]
