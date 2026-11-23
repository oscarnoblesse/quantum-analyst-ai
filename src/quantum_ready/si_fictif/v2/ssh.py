"""Clés SSH de Fret Lab : bastion, poste du chef de quai, dépôt (V2-035 à V2-043).

Les fichiers de configuration (sshd_config, sshd_config.d/, ssh_config) sont des modèles,
rendus par ``fichiers``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from quantum_ready.si_fictif.generateur import Contexte
from quantum_ready.si_fictif.v2.valeurs import DOMAINE


def privee_openssh(cle) -> str:
    return cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode()


def publique_openssh(cle, commentaire: str) -> str:
    ligne = cle.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return f"{ligne.decode()} {commentaire}\n"


def generer_ssh(ctx: Contexte) -> None:
    # V2-035 à V2-037 : clés d'hôte du bastion, non chiffrées (droits 600).
    cles_hote = {
        "ecdsa": ec.generate_private_key(ec.SECP256R1()),
        "rsa": rsa.generate_private_key(public_exponent=65537, key_size=3072),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
    }
    for type_, cle in cles_hote.items():
        chemin = f"bastion/ssh/ssh_host_{type_}_key"
        ctx.ecrire(chemin, privee_openssh(cle), prive=True)
        ctx.ecrire(chemin + ".pub", publique_openssh(cle, f"root@bastion.{DOMAINE}"))

    # V2-038 : clé RSA-1024 du compte « exploitation », dans authorized_keys.d/%u.
    cle_exploitation = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ctx.ecrire("bastion/ssh/authorized_keys.d/exploitation",
               publique_openssh(cle_exploitation, "exploitation@poste-nuit"))

    # V2-040 : le poste du chef de quai mémorise la clé ECDSA du bastion.
    ligne_hote = publique_openssh(cles_hote["ecdsa"], "").split()
    ctx.ecrire("postes/chef-quai/.ssh/known_hosts",
               f"bastion.{DOMAINE},10.20.0.5 {ligne_hote[0]} {ligne_hote[1]}\n")

    # V2-041 : clé du chef de quai, ECDSA P-384, sans phrase de passe.
    cle_quai = ec.generate_private_key(ec.SECP384R1())
    ctx.ecrire("postes/chef-quai/.ssh/id_ecdsa", privee_openssh(cle_quai), prive=True)
    ctx.ecrire("postes/chef-quai/.ssh/id_ecdsa.pub", publique_openssh(cle_quai, "chef-quai@poste-quai"))

    # V2-043 : clé DSA 1024 du vieux routeur, au format PEM traditionnel (OpenSSH < 6.5).
    cle_routeur = dsa.generate_private_key(key_size=1024)
    ctx.ecrire("depot/ssh/id_dsa_routeur",
               cle_routeur.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()).decode(), prive=True)
