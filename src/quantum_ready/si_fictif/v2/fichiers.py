"""Configurations, code, scripts et fichiers hors périmètre de Fret Lab.

Chaque fichier de ``modeles/v2/<chemin>.tmpl`` est rendu à ``<chemin>`` dans le SI, après
remplacement des variables {{NOM}} (secrets du contexte, valeurs publiques de la PKI,
clés WireGuard, OpenVPN et OpenPGP tirées ici).
"""

from __future__ import annotations

import secrets
import warnings
from importlib import resources

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, ed25519, rsa

from quantum_ready.si_fictif.generateur import EXTENSION_MODELE, PAQUET, Contexte, remplir
from quantum_ready.si_fictif.openpgp import cle_publique_rsa
from quantum_ready.si_fictif.v2 import formats
from quantum_ready.si_fictif.v2.pki import publiques
from quantum_ready.si_fictif.v2.valeurs import DOMAINE, MAINTENANT

# Groupe ffdhe2048 (RFC 7919, annexe A.1) : paramètres DH publics et standard, ceux que
# recommande le guide de configuration TLS de Mozilla pour ssl_dhparam.
FFDHE2048 = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2F"
    "E363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70"
    "E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7"
    "F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF"
    "8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFF"
    "FFFFFFFFFFFF",
    16,
)

# Fichiers sensibles : droits 600, comme sur un vrai serveur.
PRIVES = ("vpn/ipsec.secrets", "vpn/wg0.conf", "vpn/agences.ovpn", "suivi/.env", "edi/.env",
          "portail/tls/tickets.key")


def modeles_v2():
    """(chemin relatif, contenu) de chaque modèle de la variante 2, dans un ordre stable."""
    racine = resources.files(PAQUET).joinpath("modeles", "v2")
    pile = [(racine, "")]
    trouves = []
    while pile:
        dossier, prefixe = pile.pop()
        for entree in dossier.iterdir():
            chemin = f"{prefixe}{entree.name}"
            if entree.is_dir():
                pile.append((entree, chemin + "/"))
            elif entree.name.endswith(EXTENSION_MODELE):
                trouves.append((chemin.removesuffix(EXTENSION_MODELE), entree.read_text(encoding="utf-8")))
    return sorted(trouves)


def generer_fichiers(ctx: Contexte) -> None:
    variables = dict(ctx.valeurs)
    variables.update(publiques(ctx))
    variables["DOMAINE"] = DOMAINE

    # V2-094 : clé privée WireGuard de la passerelle, et clé publique d'un pair.
    variables["WG_CLE_PRIVEE"], _ = formats.cle_wireguard()
    _, variables["WG_CLE_PAIR"] = formats.cle_wireguard()
    # V2-096 : clé statique tls-auth d'OpenVPN, intégrée au profil.
    variables["OPENVPN_TLS_AUTH"] = formats.cle_statique_openvpn()

    for chemin, modele in modeles_v2():
        ctx.ecrire(chemin, remplir(modele, variables), prive=chemin in PRIVES)

    # V2-023 : paramètres Diffie-Hellman de 2048 bits (ssl_dhparam).
    with warnings.catch_warnings():  # FFDH est déprécié par cryptography : c'est justement l'actif
        warnings.simplefilter("ignore")
        parametres = dh.DHParameterNumbers(FFDHE2048, 2).parameters()
    ctx.ecrire("portail/tls/dhparam-2048.pem",
               parametres.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))

    # V2-022 : clé des tickets de session nginx, 48 octets (AES-128 + HMAC-SHA256).
    ctx.ecrire("portail/tls/tickets.key", secrets.token_bytes(48), prive=True)

    # V2-073 et V2-074 : clés publiques OpenPGP (sauvegardes RSA-3072, douane EdDSA).
    creation = int(MAINTENANT.timestamp()) - 400 * 86400
    ctx.ecrire("exploitation/gpg/sauvegarde_pub.asc",
               cle_publique_rsa(rsa.generate_private_key(public_exponent=65537, key_size=3072),
                                f"Sauvegardes Fret Lab <sauvegardes@{DOMAINE}>", creation))
    ctx.ecrire("exploitation/gpg/partenaires/douane.asc",
               formats.cle_publique_eddsa(ed25519.Ed25519PrivateKey.generate(),
                                          "Douane EDI <edi@douane.example>", creation))
