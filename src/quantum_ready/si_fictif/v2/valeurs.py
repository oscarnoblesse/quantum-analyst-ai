"""Valeurs communes de la variante 2 : graine, noms, dates et secrets.

Tout ce qui n'est pas une clé ni un secret est déterministe : la graine fixe les numéros
de série et les autres choix non cryptographiques. Les clés et les secrets sont tirés à
chaque génération (module ``secrets``) et ne sont jamais écrits dans le dépôt ; la vérité
terrain ne décrit que leur forme (algorithme, taille, protection).
"""

from __future__ import annotations

import base64
import datetime as dt
import random
import secrets

from quantum_ready.si_fictif.generateur import Contexte

GRAINE = 20261120
ORGANISATION = "Fret Lab"
DOMAINE = "fret.lab.local"

# Les dates sont relatives au moment de la génération : la vérité terrain parle de durées
# (« validité 20 ans »), jamais de dates absolues.
MAINTENANT = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def alea() -> random.Random:
    """Générateur pseudo-aléatoire NON cryptographique, à graine fixe (numéros de série...)."""
    return random.Random(GRAINE)


def generer_valeurs(ctx: Contexte) -> None:
    """Secrets partagés entre plusieurs fichiers ; ils sont aussi recopiés hors du SI."""
    ctx.valeurs.update(
        {
            # V2-079 : secret JWT court (16 caractères).
            "SECRET_JWT": secrets.token_urlsafe(12)[:16],
            # V2-051 : clé Fernet (32 octets en base64 URL).
            "CLE_ADRESSES": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            # V2-069 : mot de passe du PKCS#12 de l'EDI.
            "EDI_CONTENEUR_SECRET": secrets.token_urlsafe(15),
            # V2-071 : phrase de passe de la clé de signature des e-CMR (hors SI seulement).
            "PHRASE_CLE_CMR": secrets.token_urlsafe(18),
            # V2-082 : mot de passe du keystore JKS.
            "MOT_DE_PASSE_KEYSTORE": secrets.token_urlsafe(12),
            # V2-093 : clé pré-partagée IPsec.
            "PSK_IPSEC": secrets.token_urlsafe(24),
        }
    )
