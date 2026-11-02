"""Outil analyser_dependances : bibliothèques cryptographiques d'un projet Python.

Trois sources, croisées :
- pyproject.toml : ce que le projet DÉCLARE ;
- uv.lock : ce qui est réellement INSTALLÉ, versions figées, y compris les
  dépendances transitives (tirées par une autre bibliothèque, jamais déclarées) ;
- le code du SI : qui IMPORTE vraiment chaque bibliothèque. Une bibliothèque
  déclarée mais importée nulle part est une dépendance morte : elle alourdit la
  surface d'attaque sans rien apporter.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, Trouvaille, outil, relatif, resoudre

NOM = "analyser_dependances"

# paquet PyPI -> (module importé, rôle cryptographique)
BIBLIOTHEQUES = {
    "cryptography": ("cryptography", "primitives et X.509 ; embarque sa propre copie d'OpenSSL dans les wheels"),
    "pyjwt": ("jwt", "signature et vérification des jetons JWT"),
    "argon2-cffi": ("argon2", "hachage de mots de passe Argon2"),
    "argon2-cffi-bindings": ("_argon2_cffi_bindings", "liaison C de la bibliothèque de référence Argon2"),
    "paramiko": ("paramiko", "client et serveur SSH en Python pur"),
    "pycryptodome": ("Crypto", "primitives cryptographiques (successeur de PyCrypto)"),
    "pycryptodomex": ("Cryptodome", "primitives cryptographiques (espace de noms séparé)"),
    "pynacl": ("nacl", "liaison de libsodium (Curve25519, Ed25519, XSalsa20)"),
    "bcrypt": ("bcrypt", "hachage de mots de passe bcrypt"),
    "pyopenssl": ("OpenSSL", "liaison d'OpenSSL"),
    "passlib": ("passlib", "hachage de mots de passe"),
    "python-jose": ("jose", "JOSE : JWT, JWS, JWE"),
    "jwcrypto": ("jwcrypto", "JOSE : JWT, JWS, JWE"),
    "rsa": ("rsa", "RSA en Python pur"),
    "ecdsa": ("ecdsa", "ECDSA en Python pur"),
    "python-gnupg": ("gnupg", "pilotage de GnuPG"),
    "itsdangerous": ("itsdangerous", "signature HMAC de données"),
}
# Vulnérabilités connues : version corrigée minimale (à vérifier sur la base OSV pour une version donnée).
VULNERABILITES = {
    "pycryptodome": ((3, 19, 1), "CVE-2023-52323 : fuite par canal auxiliaire dans le déchiffrement OAEP"),
    "pyjwt": ((2, 4, 0), "CVE-2022-29217 : confusion d'algorithmes"),
    "paramiko": ((3, 4, 0), "CVE-2023-48795 (Terrapin) : troncature de la négociation SSH"),
    "cryptography": ((42, 0, 4), "CVE-2024-26130 : déréférencement nul lors de la lecture d'un PKCS#12"),
}


def normaliser(nom: str) -> str:
    return re.sub(r"[-_.]+", "-", nom).lower()


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:3])


def imports_du_si(racine: Path) -> dict[str, list[str]]:
    """Module de premier niveau importé -> fichiers du SI qui l'importent."""
    trouves: dict[str, list[str]] = {}
    for fichier in sorted(racine.rglob("*.py")):
        try:
            arbre = ast.parse(fichier.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for noeud in ast.walk(arbre):
            modules = []
            if isinstance(noeud, ast.Import):
                modules = [a.name for a in noeud.names]
            elif isinstance(noeud, ast.ImportFrom) and noeud.module and noeud.level == 0:
                modules = [noeud.module]
            for module in modules:
                liste = trouves.setdefault(module.split(".")[0], [])
                if relatif(fichier, racine) not in liste:
                    liste.append(relatif(fichier, racine))
    return trouves


@outil(NOM)
def analyser_dependances(cible: str, racine: Path) -> Resultat:
    """Bibliothèques cryptographiques d'un projet : déclarées, verrouillées, transitives, importées."""
    chemin = resoudre(cible or ".", racine)
    dossier = chemin if chemin.is_dir() else chemin.parent
    pyproject, verrou = dossier / "pyproject.toml", dossier / "uv.lock"
    if not pyproject.is_file() and not verrou.is_file():
        raise ErreurOutil(f"Ni pyproject.toml ni uv.lock dans {relatif(dossier, racine) or '.'}")
    resultat = Resultat(outil=NOM, cible=relatif(dossier, racine) or ".")

    declarees: dict[str, str] = {}
    if pyproject.is_file():
        projet = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
        for exigence in projet.get("dependencies", []):
            nom = re.match(r"[A-Za-z0-9_.\-]+", exigence).group(0)
            declarees[normaliser(nom)] = exigence[len(nom):].strip() or "toute version"
    else:
        resultat.pistes.append(Piste(vers=relatif(dossier, racine), raison="pas de pyproject.toml : impossible de savoir ce qui est déclaré"))

    verrouillees: dict[str, str] = {}
    tirees_par: dict[str, list[str]] = {}
    if verrou.is_file():
        for paquet in tomllib.loads(verrou.read_text(encoding="utf-8")).get("package", []):
            nom = normaliser(paquet["name"])
            verrouillees[nom] = paquet.get("version", "?")
            for dependance in paquet.get("dependencies", []):
                tirees_par.setdefault(normaliser(dependance["name"]), []).append(nom)
    else:
        resultat.pistes.append(Piste(vers=relatif(dossier, racine), raison="pas de uv.lock : versions installées inconnues (non reproductible)"))

    imports = imports_du_si(racine)
    fichier_source = relatif(verrou if verrou.is_file() else pyproject, racine)
    for nom in sorted(set(declarees) | set(verrouillees)):
        if nom not in BIBLIOTHEQUES:
            continue
        module, role = BIBLIOTHEQUES[nom]
        version = verrouillees.get(nom)
        declaree = nom in declarees
        props: dict = {"role": role, "declaree": declaree, "module": module, "importee_dans": imports.get(module, [])}
        if declaree:
            props["contrainte"] = declarees[nom]
        if version:
            props["version_verrouillee"] = version
        if not declaree:
            props["tiree_par"] = sorted(set(tirees_par.get(nom, [])))
        faiblesses = []
        if declaree and not props["importee_dans"]:
            faiblesses.append("déclarée mais importée nulle part : dépendance morte")
        if nom in VULNERABILITES:
            minimum, cve = VULNERABILITES[nom]
            version_reelle = version or re.sub(r"[^\d.]", "", declarees.get(nom, "")) or None
            if version_reelle and version_tuple(version_reelle) < minimum:
                faiblesses.append(f"version {version_reelle} antérieure à {'.'.join(map(str, minimum))} — {cve}")
        if faiblesses:
            props["faiblesse_classique"] = " ; ".join(faiblesses)
        origine = "déclarée" if declaree else f"transitive, tirée par {', '.join(props['tiree_par']) or '?'}"
        resultat.trouvailles.append(Trouvaille(
            outil=NOM, fichier=relatif(pyproject, racine) if declaree and pyproject.is_file() else fichier_source,
            type_actif="library", nom=f"{nom} {version or declarees.get(nom, '')}".strip(),
            description=f"Bibliothèque {nom} ({role}), {origine}", exposition="aucune", proprietes=props,
            preuve=f"{nom}{declarees.get(nom, '')}" + (f" ; uv.lock : {version}" if version else ""),
        ))
    return resultat
