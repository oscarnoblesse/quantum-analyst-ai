"""Code applicatif du SI fictif : l'API Python, son .env et le module de factures.

Le code est copié depuis modeles/ ; seul le fichier .env reçoit des secrets.
"""

from __future__ import annotations

import os
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


def generer_dependances(ctx: Contexte) -> None:
    """Dépendances Python de l'API : QR-060 à QR-064, et bibliothèque paramiko.

    - pyproject.toml déclare cryptography, pyjwt, argon2-cffi, paramiko et un vieux
      pycryptodome que plus aucun fichier n'importe (QR-063, dépendance morte) ;
    - uv.lock est un vrai fichier résolu depuis PyPI : il contient en plus pynacl et
      bcrypt, tirés par paramiko (QR-064, dépendances transitives) ;
    - scripts/deploy.py est le seul utilisateur de paramiko.
    """
    ctx.ecrire_modele("api/pyproject.toml")
    ctx.ecrire_modele("api/uv.lock")
    ctx.ecrire_modele("scripts/deploy.py")


IDENTITE_SAUVEGARDES = "Sauvegardes Lab <backup@lab.local>"


def generer_sauvegardes(ctx: Contexte) -> None:
    """Sauvegardes chiffrées de la base : QR-043 (script) et QR-044 (clé publique RSA-3072).

    La clé privée correspondante reste hors du SI (stockée hors ligne dans une vraie
    organisation) : elle est écrite dans le dossier hors_si.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from quantum_ready.si_fictif.openpgp import cle_publique_rsa

    cle = rsa.generate_private_key(65537, 3072)
    ctx.ecrire("scripts/keys/backup_pub.asc", cle_publique_rsa(cle, IDENTITE_SAUVEGARDES))
    ctx.ecrire_modele("scripts/backup.sh")
    os.chmod(ctx.racine_si / "scripts/backup.sh", 0o755)
    ctx.ecrire_hors_si(
        "sauvegardes/backup_priv.pem",
        cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
