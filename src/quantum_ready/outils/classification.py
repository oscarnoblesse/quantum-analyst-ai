"""Exposition quantique d'un algorithme, d'après son nom.

C'est une table de connaissances, pas un calcul : elle est volontairement simple
et lisible pour être relue et auditée. L'ordre des tests compte :
1. les algorithmes post-quantiques d'abord, pour qu'un hybride comme
   X25519MLKEM768 soit classé « resistant » (il tient tant que ML-KEM tient) ;
2. puis l'asymétrique classique (Shor), pour qu'une signature
   « sha256WithRSAEncryption » soit classée « shor » et non « grover » ;
3. enfin le symétrique et les fonctions de hachage (Grover).
"""

from __future__ import annotations

import re

from quantum_ready.outils.commun import Exposition

POST_QUANTIQUES = ("ml-kem", "mlkem", "ml-dsa", "mldsa", "slh-dsa", "slhdsa", "sntrup", "kyber", "dilithium", "sphincs", "falcon")
ASYMETRIQUES = (
    "rsa", "dsa", "dss", "diffie", "dh", "ecdh", "ecdsa", "ed25519", "ed448", "x25519", "x448",
    "curve25519", "secp", "nistp", "prime256", "p-256", "p-384", "p-521", "elgamal", "openpgp", "eddsa",
)
# Noms JOSE des JWT (RS256, ES384...) : cherchés comme mots entiers, sinon « es256 » se trouverait dans « aes256 ».
_JOSE_ASYMETRIQUES = re.compile(r"(?<![a-z])(rs|ps|es)(256|384|512)(?![0-9])")
SYMETRIQUES = (
    "aes", "chacha", "3des", "des-", "tripledes", "camellia", "sha", "md5", "hmac", "poly1305",
    "argon", "scrypt", "pbkdf", "bcrypt", "fernet", "blake", "hs256", "hs384", "hs512", "rc2", "rc4",
)


def exposition(nom: str) -> Exposition:
    """Classe un nom d'algorithme (ou une liste séparée par des virgules)."""
    texte = nom.lower().replace("_", "-")
    if any(motif in texte for motif in POST_QUANTIQUES):
        return "resistant"
    if any(motif in texte for motif in ASYMETRIQUES) or _JOSE_ASYMETRIQUES.search(texte):
        return "shor"
    if any(motif in texte for motif in SYMETRIQUES):
        return "grover"
    return "inconnue"


def exposition_la_pire(noms: list[str]) -> Exposition:
    """Pour une liste d'algorithmes négociables : le maillon le plus faible l'emporte."""
    ordre = ["shor", "grover", "inconnue", "resistant", "aucune"]
    classes = [exposition(nom) for nom in noms] or ["inconnue"]
    return min(classes, key=ordre.index)
