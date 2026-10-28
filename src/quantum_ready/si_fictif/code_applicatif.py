"""Code applicatif du SI fictif : l'API Python, son .env et le module de factures.

Le code est copié depuis modeles/ ; seul le fichier .env reçoit des secrets.
"""

from __future__ import annotations

import secrets

from cryptography.fernet import Fernet

from quantum_ready.si_fictif.generateur import Contexte

FICHIERS_API = (
    "api/__init__.py",
    "api/app.py",
    "api/auth.py",          # QR-050 : Argon2id
    "api/legacy_auth.py",   # QR-051 : code mort, SHA-256 sans sel
    "api/tokens.py",        # QR-052 : JWT, algorithme lu dans le .env
    "api/reset.py",         # QR-054 : random.choice pour un secret
    "api/utils/__init__.py",
    "api/utils/codes.py",   # QR-055 : random.SystemRandom (piège de précision)
    "api/webhooks.py",      # QR-056 : HMAC comparé avec ==
    "api/files.py",         # QR-058 : SHA-256 d'intégrité
    "api/cache.py",         # QR-059 : MD5 comme clé de cache (piège de précision)
    "api/crypto_fields.py", # QR-041 : Fernet
)


def generer_api(ctx: Contexte) -> None:
    """API : code piégé et fichier .env (QR-040 à QR-042, QR-050 à QR-059).

    Le .env contient aussi le mot de passe de la base (dans DATABASE_URL) et celui
    du conteneur PKCS#12 des factures (KEYSTORE_PASS, QR-022), tirés par generer_secrets.
    """
    ctx.valeurs["SECRET_WEBHOOK"] = secrets.token_hex(32)  # QR-057 : 256 bits
    ctx.valeurs["CLE_CHIFFREMENT_COLONNES"] = Fernet.generate_key().decode()  # QR-042
    for chemin in FICHIERS_API:
        ctx.ecrire_modele(chemin)
    ctx.ecrire_modele(
        "api/env",
        sortie="api/.env",
        MOT_DE_PASSE_BASE=ctx.valeurs["MOT_DE_PASSE_BASE"],
        SECRET_WEBHOOK=ctx.valeurs["SECRET_WEBHOOK"],
        CLE_CHIFFREMENT_COLONNES=ctx.valeurs["CLE_CHIFFREMENT_COLONNES"],
        MOT_DE_PASSE_CONTENEUR_FACTURES=ctx.valeurs["MOT_DE_PASSE_CONTENEUR_FACTURES"],
    )


def generer_factures(ctx: Contexte) -> None:
    """Module de signature des factures : algorithme ECDSA P-256 avec SHA-256.

    Le module lit sa clé dans factures/keys/factures.p12 (QR-020, QR-021, écrit par
    l'étape PKI) avec le mot de passe KEYSTORE_PASS du .env de l'API (QR-022).
    """
    ctx.ecrire_modele("factures/__init__.py")
    ctx.ecrire_modele("factures/signer.py")
