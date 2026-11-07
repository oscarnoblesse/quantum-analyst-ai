"""Clés SSH du SI fictif : serveur SSH et poste de l'admin.

Actifs couverts : QR-023 à QR-026 (clés d'hôte), QR-032 (authorized_keys),
QR-034 (clé privée de l'admin) et QR-035 (known_hosts).
"""

from __future__ import annotations

import base64
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from quantum_ready.si_fictif.generateur import Contexte

HOTE_SSH = "ssh.lab.local"
SANS_CHIFFREMENT = serialization.NoEncryption()


def _privee_openssh(cle) -> bytes:
    """Clé privée au format OpenSSH, non chiffrée (comme celles créées par ssh-keygen -A)."""
    return cle.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, SANS_CHIFFREMENT
    )


def _publique_openssh(cle, commentaire: str) -> str:
    ligne = cle.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return f"{ligne} {commentaire}\n"


def _chaine(donnees: bytes) -> bytes:
    """Champ « string » du format SSH : longueur sur 4 octets puis données."""
    return struct.pack(">I", len(donnees)) + donnees


def _mpint(nombre: int) -> bytes:
    """Champ « mpint » du format SSH (entier positif, octet nul ajouté si le bit de poids fort est à 1)."""
    octets = nombre.to_bytes((nombre.bit_length() + 7) // 8, "big")
    if octets[0] & 0x80:
        octets = b"\x00" + octets
    return _chaine(octets)


def publique_dsa_openssh(cle: dsa.DSAPrivateKey, commentaire: str) -> str:
    """Ligne « ssh-dss » construite à la main.

    La sérialisation OpenSSH des clés DSA est dépréciée dans `cryptography` ; on
    construit donc le blob (« ssh-dss », p, q, g, y) nous-mêmes pour ne pas dépendre
    d'une fonction amenée à disparaître.
    """
    nombres = cle.public_key().public_numbers()
    parametres = nombres.parameter_numbers
    blob = (
        _chaine(b"ssh-dss")
        + _mpint(parametres.p)
        + _mpint(parametres.q)
        + _mpint(parametres.g)
        + _mpint(nombres.y)
    )
    return f"ssh-dss {base64.b64encode(blob).decode()} {commentaire}\n"


def generer_cles_hote(ctx: Contexte) -> dict[str, str]:
    """QR-023 à QR-025 : clés d'hôte actives du serveur SSH. Renvoie les lignes publiques."""
    cles = {
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "rsa": rsa.generate_private_key(65537, 3072),
        "ecdsa": ec.generate_private_key(ec.SECP256R1()),
    }
    publiques = {}
    for nom, cle in cles.items():
        base = f"ssh/server/ssh_host_{nom}_key"
        ctx.ecrire(base, _privee_openssh(cle), prive=True)
        publiques[nom] = _publique_openssh(cle, "root@ssh-lab")
        ctx.ecrire(base + ".pub", publiques[nom])
    return publiques


def generer_ancienne_cle_dsa(ctx: Contexte) -> None:
    """QR-026 : ancienne clé d'hôte DSA 1024 bits, oubliée et non référencée par sshd_config.

    Format PEM « traditionnel », celui qu'écrivaient les anciennes versions de ssh-keygen.
    """
    cle = dsa.generate_private_key(1024)
    privee = cle.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, SANS_CHIFFREMENT
    )
    ctx.ecrire("ssh/server/old/ssh_host_dsa_key", privee, prive=True)
    ctx.ecrire("ssh/server/old/ssh_host_dsa_key.pub", publique_dsa_openssh(cle, "root@ssh-lab"))


def generer_cle_admin(ctx: Contexte) -> str:
    """QR-034 : clé privée SSH de l'admin, sans phrase de passe, sur son poste. Renvoie sa ligne publique."""
    cle = ed25519.Ed25519PrivateKey.generate()
    ctx.ecrire("clients/admin/.ssh/id_ed25519", _privee_openssh(cle), prive=True)
    return _publique_openssh(cle, "admin@poste-admin")


def generer_ssh(ctx: Contexte) -> None:
    """Étape SSH du générateur."""
    publiques_hote = generer_cles_hote(ctx)
    generer_ancienne_cle_dsa(ctx)
    publique_admin = generer_cle_admin(ctx)
    # QR-032 : le serveur autorise la clé de l'admin.
    ctx.ecrire("ssh/server/home/admin/.ssh/authorized_keys", publique_admin)
    # QR-035 : le poste de l'admin a mémorisé la clé Ed25519 du serveur.
    type_cle, valeur, _ = publiques_hote["ed25519"].split()
    ctx.ecrire("clients/admin/.ssh/known_hosts", f"{HOTE_SSH} {type_cle} {valeur}\n")
