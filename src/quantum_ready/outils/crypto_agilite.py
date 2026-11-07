"""Indicateur de crypto-agilité par actif (sujet §5.3), déterministe.

Principe : plus le changement d'algorithme est léger, plus le SI est agile. On lit l'emplacement de
chaque actif dans le CBOM (chemin du fichier où il apparaît) et on en déduit ce qu'il faudrait
changer. Un actif qui apparaît à plusieurs emplacements prend le niveau le PLUS RIGIDE.

PROPOSITION DE MÉTHODE, à valider par l'auteur : le découpage en catégories et en niveaux est un
choix. Il est écrit ici pour être discuté, pas comme une vérité.
"""

from __future__ import annotations

from pathlib import PurePosixPath

NIVEAUX = {"élevée": 3, "moyenne": 2, "faible": 1}
# Ordre de rigidité : du plus agile au plus rigide.
CATEGORIES = {
    "configuration": ("élevée", "changer une valeur de configuration"),
    "dépendance": ("moyenne", "mettre à jour une bibliothèque ou un paquet"),
    "logiciel": ("moyenne", "mettre à jour le logiciel qui fournit la valeur par défaut"),
    "code": ("faible", "modifier et redéployer le code"),
    "matériel": ("faible", "réémettre un certificat ou une clé, et les distribuer"),
}
_EXTENSIONS_CONFIG = {".conf", ".cfg", ".ini", ".yaml", ".yml", ".env", ".toml", ".properties", ".json", ".xml"}
_NOMS_CONFIG = {"sshd_config", "ssh_config", "nginx.conf", "postgresql.conf", "pg_hba.conf", "dockerfile", "docker-compose.yml"}
_NOMS_DEPENDANCES = {"requirements.txt", "pyproject.toml", "poetry.lock", "package.json", "package-lock.json", "pom.xml", "go.mod", "go.sum", "cargo.toml"}
_EXTENSIONS_CODE = {".py", ".java", ".go", ".js", ".ts", ".c", ".h", ".sh", ".rb", ".php", ".cs"}
_EXTENSIONS_MATERIEL = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".pub", ".asc", ".gpg", ".jks"}


def categorie_d_un_emplacement(chemin: str) -> str:
    """Catégorie d'un fichier d'après son nom et son extension."""
    nom = PurePosixPath(chemin).name.lower()
    suffixe = PurePosixPath(chemin).suffix.lower()
    if nom in _NOMS_DEPENDANCES:
        return "dépendance"
    if nom.startswith("id_") or suffixe in _EXTENSIONS_MATERIEL:
        return "matériel"
    if nom in _NOMS_CONFIG or suffixe in _EXTENSIONS_CONFIG or nom == ".env" or nom.startswith(".env."):
        return "configuration"
    if suffixe in _EXTENSIONS_CODE:
        return "code"
    return "code"  # fichier inconnu : traité comme du code, le plus rigide des cas ordinaires


def evaluer_actif(composant: dict) -> dict:
    """Catégorie et niveau d'un composant du CBOM. Un actif implicite dépend du logiciel."""
    occurrences = [o.get("location", "") for o in composant.get("evidence", {}).get("occurrences", []) if o.get("location")]
    if not occurrences:
        categorie = "logiciel"
    else:
        categories = [categorie_d_un_emplacement(c) for c in occurrences]
        categorie = min(categories, key=lambda c: NIVEAUX[CATEGORIES[c][0]])
    niveau = CATEGORIES[categorie][0]
    return {"categorie": categorie, "niveau": niveau, "action": CATEGORIES[categorie][1]}


def resumer(cbom: dict) -> dict:
    """Comptes par niveau et par catégorie, sur tous les composants d'un CBOM."""
    niveaux: dict[str, int] = {n: 0 for n in NIVEAUX}
    categories: dict[str, int] = {c: 0 for c in CATEGORIES}
    for composant in cbom.get("components", []):
        evaluation = evaluer_actif(composant)
        niveaux[evaluation["niveau"]] += 1
        categories[evaluation["categorie"]] += 1
    return {"actifs": sum(niveaux.values()), "niveaux": niveaux, "categories": categories}
