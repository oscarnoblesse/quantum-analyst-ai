"""Fichiers de configuration du SI fictif, écrits à partir des modèles de modeles/.

Chaque fonction couvre un service. Les valeurs cryptographiques sont dans les modèles,
telles qu'un administrateur les aurait écrites ; seuls les secrets sont injectés.
"""

from __future__ import annotations

import base64

from quantum_ready.si_fictif.generateur import Contexte


def generer_config_ssh(ctx: Contexte) -> None:
    """Serveur SSH : QR-027 à QR-031 (sshd_config) et QR-033 (version d'OpenSSH).

    QR-031 est un actif implicite : PubkeyAcceptedAlgorithms n'apparaît volontairement
    pas dans sshd_config, ce sont les valeurs par défaut d'OpenSSH qui s'appliquent.
    """
    ctx.ecrire_modele("ssh/server/sshd_config")
    ctx.ecrire_modele("ssh/Dockerfile")


# Groupe Diffie-Hellman 14 de la RFC 3526 (MODP 2048 bits, générateur 2).
# C'est un groupe public et standard : on le reprend plutôt que de générer des
# paramètres, ce qui prendrait plusieurs minutes à chaque `make si`.
PREMIER_DH_GROUPE_14 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)


def _entier_der(nombre: int) -> bytes:
    """Encodage DER d'un INTEGER positif (octet nul ajouté si le bit de poids fort est à 1)."""
    octets = nombre.to_bytes((nombre.bit_length() + 7) // 8 or 1, "big")
    if octets[0] & 0x80:
        octets = b"\x00" + octets
    return b"\x02" + _longueur_der(len(octets)) + octets


def _longueur_der(longueur: int) -> bytes:
    if longueur < 0x80:
        return bytes([longueur])
    octets = longueur.to_bytes((longueur.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def parametres_dh_groupe_14() -> bytes:
    """Paramètres DH au format PEM (PKCS#3), identiques à ceux de `openssl dhparam`.

    Le fichier est une simple structure DER : SEQUENCE { INTEGER p, INTEGER g }.
    On l'encode nous-mêmes : la prise en charge de Diffie-Hellman « classique »
    est dépréciée dans `cryptography` et doit en disparaître.
    """
    contenu = _entier_der(PREMIER_DH_GROUPE_14) + _entier_der(2)
    der = b"\x30" + _longueur_der(len(contenu)) + contenu
    corps = base64.encodebytes(der).decode().replace("\n", "")
    lignes = [corps[i : i + 64] for i in range(0, len(corps), 64)]
    return ("-----BEGIN DH PARAMETERS-----\n" + "\n".join(lignes) + "\n-----END DH PARAMETERS-----\n").encode()


def generer_config_nginx(ctx: Contexte) -> None:
    """Frontal nginx : QR-013 à QR-019.

    - QR-015 (caché) : la macro HIGH inclut des suites TLS 1.2 à échange de clés RSA ;
    - QR-017 : ssl_dhparam pointe vers des paramètres DH 2048 bits ;
    - QR-019 (implicite) : aucune directive ne fixe les suites TLS 1.3, ce sont
      les valeurs par défaut d'OpenSSL qui s'appliquent.
    Les certificats référencés (fullchain.pem, server.key, ca_clients.crt) sont
    écrits par l'étape PKI.
    """
    ctx.ecrire_modele("nginx/nginx.conf")
    ctx.ecrire("nginx/ssl/dhparam.pem", parametres_dh_groupe_14())
