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
    if not verrou.is_file() and (dossier / "poetry.lock").is_file():
        verrou = dossier / "poetry.lock"
    exigences = sorted(dossier.glob("requirements*.txt")) if chemin.is_dir() or chemin.name == "pyproject.toml" else ([chemin] if chemin.name.startswith("requirements") or chemin.suffix == ".txt" else [])
    if not pyproject.is_file() and not verrou.is_file() and not exigences:
        raise ErreurOutil(f"Aucun fichier de dépendances Python (pyproject.toml, uv.lock, poetry.lock, requirements*.txt) dans {relatif(dossier, racine) or '.'}")
    resultat = Resultat(outil=NOM, cible=relatif(dossier, racine) or ".")

    declarees: dict[str, str] = {}
    source_declaree: dict[str, str] = {}
    epinglees: dict[str, str] = {}
    for fichier_exigences in exigences:
        for ligne in fichier_exigences.read_text(encoding="utf-8", errors="replace").splitlines():
            ligne = ligne.split("#")[0].split(";")[0].strip()
            if not ligne or ligne.startswith(("-", "git+", "http")):
                continue
            if (exigence := re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)", ligne)):
                nom = normaliser(exigence.group(1))
                declarees[nom] = exigence.group(3).strip() or "toute version"
                source_declaree[nom] = relatif(fichier_exigences, racine)
                if (fige := re.match(r"===?\s*([\w.]+)$", exigence.group(3).strip())):
                    epinglees[nom] = fige.group(1)
    if pyproject.is_file():
        donnees = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        for exigence in donnees.get("project", {}).get("dependencies", []):
            nom = re.match(r"[A-Za-z0-9_.\-]+", exigence).group(0)
            declarees[normaliser(nom)] = exigence[len(nom):].strip() or "toute version"
            source_declaree[normaliser(nom)] = relatif(pyproject, racine)
        for nom, contrainte in donnees.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if nom.lower() != "python":
                declarees[normaliser(nom)] = contrainte if isinstance(contrainte, str) else str(contrainte.get("version", "toute version"))
                source_declaree[normaliser(nom)] = relatif(pyproject, racine)
    elif not exigences:
        resultat.pistes.append(Piste(vers=relatif(dossier, racine), raison="pas de pyproject.toml : impossible de savoir ce qui est déclaré"))

    verrouillees: dict[str, str] = {}
    tirees_par: dict[str, list[str]] = {}
    if verrou.is_file():
        for paquet in tomllib.loads(verrou.read_text(encoding="utf-8")).get("package", []):
            nom = normaliser(paquet["name"])
            verrouillees[nom] = paquet.get("version", "?")
            dependances = paquet.get("dependencies", [])
            noms = [d["name"] for d in dependances] if isinstance(dependances, list) else list(dependances)  # uv : liste ; poetry : table
            for dependance in noms:
                tirees_par.setdefault(normaliser(dependance), []).append(nom)
    elif epinglees:
        verrouillees.update(epinglees)
    else:
        resultat.pistes.append(Piste(vers=relatif(dossier, racine), raison="pas de fichier verrou (uv.lock, poetry.lock) ni de versions figées : versions installées inconnues"))

    imports = imports_du_si(racine)
    fichier_source = relatif(verrou if verrou.is_file() else (pyproject if pyproject.is_file() else exigences[0]), racine)
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
            outil=NOM, fichier=source_declaree.get(nom, fichier_source) if declaree else fichier_source,
            type_actif="library", nom=f"{nom} {version or declarees.get(nom, '')}".strip(),
            description=f"Bibliothèque {nom} ({role}), {origine}", exposition="aucune", proprietes=props,
            preuve=f"{nom}{declarees.get(nom, '')}" + (f" ; uv.lock : {version}" if version else ""),
        ))
    return resultat
