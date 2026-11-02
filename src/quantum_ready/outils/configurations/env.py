"""Fichiers de variables d'environnement (.env).

Les valeurs ne sont JAMAIS renvoyées : un secret est décrit (longueur, forme,
caractère prévisible), pas recopié. Trois sortes de trouvailles :
- un secret (nom en SECRET, KEY, PASS, TOKEN...) : clé ou mot de passe en clair ;
- une URL de connexion avec mot de passe, et son mode TLS (sslmode) ;
- un nom d'algorithme (HS256, AES...) : pas un actif en soi, mais une piste vers
  le code qui lit la variable.
"""

from __future__ import annotations

import base64
import re
import string
from urllib.parse import parse_qs, urlsplit

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import Piste, Trouvaille, decrire_secret, lire_env

NOM = "analyser_configuration"
_NOM_SECRET = re.compile(r"(SECRET|KEY|PASS|PWD|TOKEN|SALT|PRIVATE)", re.I)
MOTS_PREVISIBLES = ("secret", "password", "motdepasse", "changeme", "admin", "test", "dev", "demo", "1234", "azerty", "qwerty", "default")
SSLMODES = {
    "disable": "aucun chiffrement",
    "allow": "chiffrement seulement si le serveur l'exige, sans vérification",
    "prefer": "chiffrement si possible, sans vérification du serveur",
    "require": "chiffrement, mais le certificat du serveur n'est PAS vérifié",
    "verify-ca": "chiffrement et vérification de l'AC, sans vérifier le nom",
    "verify-full": "chiffrement, vérification de l'AC et du nom du serveur",
}


def forme_du_secret(valeur: str) -> tuple[str, dict]:
    """Nature probable d'un secret, d'après sa forme seulement."""
    props: dict = {"forme": decrire_secret(valeur)}
    try:
        brut = base64.urlsafe_b64decode(valeur.encode())
        if len(valeur) == 44 and len(brut) == 32:
            props["format"] = "clé Fernet (base64, 32 octets : 128 bits AES + 128 bits HMAC)"
            return "Clé Fernet 256 bits", props
    except (ValueError, base64.binascii.Error):
        pass
    if len(valeur) >= 32 and all(c in string.hexdigits for c in valeur):
        bits = len(valeur) * 4
        props["format"] = f"hexadécimal, {bits} bits"
        return f"Secret aléatoire de {bits} bits", props
    if any(mot in valeur.lower() for mot in MOTS_PREVISIBLES) or len(valeur) < 12:
        props["faiblesse_classique"] = "secret court ou prévisible (mot du dictionnaire, année...)"
        return "Secret faible", props
    return "Secret en clair", props


def analyser(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    trouvailles, pistes = [], []
    for ligne, nom, valeur in lire_env(texte):
        if "://" in valeur:
            adresse = urlsplit(valeur)
            if adresse.password:
                nom_secret, props = forme_du_secret(adresse.password)
                props |= {"variable": nom, "utilisateur": adresse.username or "", "hote": adresse.hostname or ""}
                trouvailles.append(Trouvaille(
                    outil=NOM, fichier=fichier, ligne=ligne, type_actif="related-crypto-material",
                    nom=f"Mot de passe de connexion ({nom_secret.lower()})",
                    description=f"Mot de passe de « {adresse.username} » vers {adresse.hostname}, en clair dans l'URL {nom}",
                    exposition="grover", proprietes=props, preuve=f"{nom}={adresse.scheme}://{adresse.username}:<masqué>@{adresse.hostname}",
                ))
            options = {k: v[0] for k, v in parse_qs(adresse.query).items()}
            if "sslmode" in options:
                mode = options["sslmode"]
                props = {"variable": nom, "effet": SSLMODES.get(mode, "inconnu")}
                if mode not in ("verify-ca", "verify-full"):
                    props["faiblesse_classique"] = "certificat du serveur non vérifié : homme du milieu possible"
                trouvailles.append(Trouvaille(
                    outil=NOM, fichier=fichier, ligne=ligne, type_actif="protocol", nom=f"sslmode={mode}",
                    description=f"Mode TLS de la connexion {adresse.scheme} vers {adresse.hostname}", exposition="shor",
                    proprietes=props, preuve=f"{nom}=...?sslmode={mode}",
                ))
                if "sslrootcert" in options:
                    pistes.append(Piste(vers=options["sslrootcert"], raison=f"magasin d'AC de la connexion {nom} (sslrootcert)"))
        elif _NOM_SECRET.search(nom) and valeur:
            nom_secret, props = forme_du_secret(valeur)
            props["variable"] = nom
            trouvailles.append(Trouvaille(
                outil=NOM, fichier=fichier, ligne=ligne, type_actif="related-crypto-material",
                nom=f"{nom_secret} ({nom})", description=f"Secret {nom} stocké en clair dans un fichier de variables d'environnement",
                exposition="grover", proprietes=props, preuve=f"{nom}=<masqué>",
            ))
            pistes.append(Piste(vers=nom, raison=f"chercher le code qui lit {nom} pour savoir ce que ce secret protège"))
        elif exposition(valeur) != "inconnue" and len(valeur) <= 32:
            pistes.append(Piste(vers=nom, raison=f"{nom}={valeur} est un nom d'algorithme : chercher le code qui lit {nom}"))
    return trouvailles, pistes
