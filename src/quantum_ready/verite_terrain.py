"""Chargement, validation et conversion de la vérité terrain du SI fictif.

La vérité terrain est maintenue dans un fichier CSV versionné
(data/ground_truth/verite_terrain_v1.csv). Ce module :

1. lit le CSV et valide chaque ligne avec un modèle Pydantic
   (valeurs fermées pour les colonnes à choix, format des identifiants) ;
2. vérifie les règles qui portent sur l'ensemble des actifs
   (identifiants uniques, catégorie des actifs cachés, liens des certificats) ;
3. écrit un fichier JSON lisible par le code d'évaluation.

Utilisation :
    python -m quantum_ready.verite_terrain <entrée.csv> <sortie.json>
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Correspondance entre les en-têtes du CSV et les champs du modèle.
COLONNES = {
    "ID": "id",
    "Composant": "composant",
    "Fichier / emplacement": "fichier",
    "Actif": "actif",
    "Algorithme / paramètres": "algorithme",
    "Visible ou caché": "visibilite",
    "Vulnérable au quantique": "vulnerabilite",
    "Type de risque": "type_risque",
    "Notes": "notes",
    "Type CycloneDX": "type_cyclonedx",
}

# Catégories d'actifs cachés, telles que définies dans docs/regles_verite_terrain.md.
CATEGORIES_CACHEES = (
    "configuration indirecte",
    "actif implicite",
    "croisement de fichiers",
    "code mort",
    "dépendance morte",
    "dépendance transitive",
    "emplacement trompeur",
    "usage à interpréter",
)

Composant = Literal[
    "Certificats", "nginx", "SSH", "Base de données", "Factures", "API", "Dépendances"
]
Visibilite = Literal["Visible", "Caché"]
Vulnerabilite = Literal["Oui (Shor)", "Partiellement (Grover)", "Non", "Indirect"]
TypeCycloneDX = Literal[
    "algorithm", "certificate", "protocol", "related-crypto-material", "library"
]

_MOTIF_CATEGORIE = re.compile(r"^Caché, (?P<categorie>[^:]+?)\s*:")
_MOTIF_PARENT = re.compile(r"Composant parent de (QR-\d{3}) et (QR-\d{3})")


class ErreurVeriteTerrain(ValueError):
    """Erreur levée quand la vérité terrain ne respecte pas les règles."""


class Actif(BaseModel):
    """Un actif cryptographique planté dans le SI fictif (une ligne du tableau)."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    id: str = Field(pattern=r"^QR-\d{3}$")
    composant: Composant
    fichier: str = Field(min_length=1)
    actif: str = Field(min_length=1)
    algorithme: str = Field(min_length=1)
    visibilite: Visibilite
    vulnerabilite: Vulnerabilite
    type_risque: str = Field(min_length=1)
    notes: str = ""
    type_cyclonedx: TypeCycloneDX

    @field_validator("notes")
    @classmethod
    def _notes_sans_retour_ligne(cls, valeur: str) -> str:
        return " ".join(valeur.split())

    @property
    def est_cache(self) -> bool:
        return self.visibilite == "Caché"

    @property
    def categorie_cachee(self) -> str | None:
        """Catégorie lue au début des notes (« Caché, <catégorie> : … »)."""
        correspondance = _MOTIF_CATEGORIE.match(self.notes)
        if not correspondance:
            return None
        categorie = correspondance.group("categorie")
        # « code mort (côté config) » → « code mort »
        return re.sub(r"\s*\(.*\)$", "", categorie).strip()

    @property
    def parents(self) -> tuple[str, str] | None:
        """Pour un certificat : identifiants de sa clé publique et de sa signature."""
        correspondance = _MOTIF_PARENT.search(self.notes)
        return correspondance.groups() if correspondance else None

    @model_validator(mode="after")
    def _categorie_obligatoire_si_cache(self) -> Actif:
        if self.est_cache:
            categorie = self.categorie_cachee
            if categorie not in CATEGORIES_CACHEES:
                raise ValueError(
                    f"{self.id} est caché : ses notes doivent commencer par "
                    f"« Caché, <catégorie> : » avec une catégorie parmi "
                    f"{', '.join(CATEGORIES_CACHEES)} (trouvé : {categorie!r})"
                )
        return self

    def vers_dict(self) -> dict:
        donnees = self.model_dump()
        donnees["categorie_cachee"] = self.categorie_cachee
        return donnees


def charger_csv(chemin: str | Path) -> list[Actif]:
    """Lit le CSV et valide chaque ligne. Lève ErreurVeriteTerrain en cas de problème."""
    chemin = Path(chemin)
    with chemin.open(encoding="utf-8", newline="") as fichier:
        lecteur = csv.DictReader(fichier)
        manquantes = set(COLONNES) - set(lecteur.fieldnames or [])
        if manquantes:
            raise ErreurVeriteTerrain(f"Colonnes manquantes : {sorted(manquantes)}")
        actifs = []
        for numero, ligne in enumerate(lecteur, start=2):
            donnees = {champ: (ligne.get(colonne) or "") for colonne, champ in COLONNES.items()}
            try:
                actifs.append(Actif(**donnees))
            except ValueError as erreur:
                raise ErreurVeriteTerrain(f"Ligne {numero} invalide : {erreur}") from erreur
    return actifs


def verifier_ensemble(actifs: list[Actif]) -> None:
    """Vérifie les règles qui portent sur plusieurs actifs à la fois."""
    if not actifs:
        raise ErreurVeriteTerrain("La vérité terrain est vide")

    doublons = [i for i, n in Counter(a.id for a in actifs).items() if n > 1]
    if doublons:
        raise ErreurVeriteTerrain(f"Identifiants en double : {sorted(doublons)}")

    index = {a.id: a for a in actifs}
    for actif in actifs:
        if actif.type_cyclonedx != "certificate" or actif.parents is None:
            continue
        cle, signature = actif.parents
        for reference, type_attendu in ((cle, "related-crypto-material"), (signature, "algorithm")):
            enfant = index.get(reference)
            if enfant is None:
                raise ErreurVeriteTerrain(f"{actif.id} référence {reference}, qui n'existe pas")
            if enfant.type_cyclonedx != type_attendu:
                raise ErreurVeriteTerrain(
                    f"{actif.id} : {reference} devrait être de type {type_attendu}, "
                    f"pas {enfant.type_cyclonedx}"
                )


def resume(actifs: list[Actif]) -> dict:
    """Compteurs utiles pour le rapport et les contrôles de seuils du sujet."""
    return {
        "total": len(actifs),
        "caches": sum(a.est_cache for a in actifs),
        "par_composant": dict(Counter(a.composant for a in actifs)),
        "par_vulnerabilite": dict(Counter(a.vulnerabilite for a in actifs)),
        "par_type_cyclonedx": dict(Counter(a.type_cyclonedx for a in actifs)),
        "par_categorie_cachee": dict(Counter(a.categorie_cachee for a in actifs if a.est_cache)),
    }


def ecrire_json(actifs: list[Actif], chemin: str | Path, version: str = "si_v1") -> None:
    """Écrit la vérité terrain au format JSON (ordre stable, UTF-8 lisible)."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "version": version,
        "resume": resume(actifs),
        "actifs": [a.vers_dict() for a in actifs],
    }
    chemin.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def convertir(entree: str | Path, sortie: str | Path) -> list[Actif]:
    """Chaîne complète : lecture, validation, vérifications d'ensemble, écriture."""
    actifs = charger_csv(entree)
    verifier_ensemble(actifs)
    ecrire_json(actifs, sortie, version=Path(sortie).stem)
    return actifs


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("Utilisation : python -m quantum_ready.verite_terrain <entrée.csv> <sortie.json>")
        return 2
    try:
        actifs = convertir(argv[0], argv[1])
    except ErreurVeriteTerrain as erreur:
        print(f"Erreur : {erreur}", file=sys.stderr)
        return 1
    infos = resume(actifs)
    print(f"{infos['total']} actifs, dont {infos['caches']} cachés → {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
