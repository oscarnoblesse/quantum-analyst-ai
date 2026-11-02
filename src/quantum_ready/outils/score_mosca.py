"""Outil score_mosca : priorité de migration d'un actif, d'après l'inégalité de Mosca.

Les tests sont dans tests/test_outil_score_mosca.py ; ils ont été écrits avant
l'implémentation, à partir de la spécification ci-dessous.

Rappel : un actif est en danger si x + y > z, avec
- x : durée pendant laquelle les données doivent rester protégées (années) ;
- y : durée nécessaire pour migrer cet actif (années) ;
- z : temps restant avant un ordinateur quantique capable de casser l'algorithme (années).

Spécification (c'est elle que les tests vérifient) :

1. Vérifier les entrées : x >= 0, y >= 0, z > 0, et exposition parmi
   « shor », « grover », « resistant », « aucune », « inconnue ».
   Sinon : renvoyer un ResultatMosca avec valide=False et un message dans erreurs
   (ne PAS lever d'exception : l'agent doit pouvoir lire l'erreur).
2. marge = x + y - z ; en_danger = marge > 0.
3. urgence = 1 si en_danger, sinon (x + y) / z  (entre 0 et 1).
4. poids selon l'exposition : shor 1.0, inconnue 1.0 (par prudence),
   grover 0.3, resistant 0.0, aucune 0.0.
5. score = round(100 * poids * urgence), entier entre 0 et 100.
6. priorite : « critique » si score >= 80, « haute » si >= 50,
   « moyenne » si >= 20, sinon « faible ».
7. explication : une phrase en français qui cite x, y, z et la marge
   (c'est ce que l'Analyste risque recopiera dans son rapport).

Pourquoi « inconnue » pèse comme « shor » : un actif dont l'algorithme n'a pas pu
être déterminé est traité comme le pire cas, sinon une lacune de l'inventaire
ferait baisser artificiellement la priorité de migration.

Pourquoi le modèle de langage ne calcule pas ce score : le calcul doit être
reproductible et vérifiable ; le modèle choisit x et y (il les justifie par le
contexte de l'actif), l'outil fait l'arithmétique.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NOM = "score_mosca"
Priorite = Literal["critique", "haute", "moyenne", "faible"]
POIDS = {"shor": 1.0, "inconnue": 1.0, "grover": 0.3, "resistant": 0.0, "aucune": 0.0}
SEUILS: tuple[tuple[int, Priorite], ...] = ((80, "critique"), (50, "haute"), (20, "moyenne"))


class ResultatMosca(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outil: str = NOM
    valide: bool = True
    x: float = 0
    y: float = 0
    z: float = 0
    marge: float = 0
    en_danger: bool = False
    score: int = Field(0, ge=0, le=100)
    priorite: Priorite = "faible"
    explication: str = ""
    erreurs: list[str] = Field(default_factory=list)


def score_mosca(x: float, y: float, z: float, exposition: str) -> ResultatMosca:
    """Score de priorité (0 à 100) d'un actif selon l'inégalité de Mosca x + y > z."""
    erreurs = []
    if x < 0:
        erreurs.append(f"x (durée de confidentialité) doit être positif ou nul : {x}")
    if y < 0:
        erreurs.append(f"y (durée de migration) doit être positif ou nul : {y}")
    if z <= 0:
        erreurs.append(f"z (horizon de la menace) doit être strictement positif : {z}")
    if exposition not in POIDS:
        erreurs.append(f"exposition inconnue « {exposition} » : attendu l'une de {', '.join(POIDS)}")
    if erreurs:
        return ResultatMosca(valide=False, x=max(x, 0), y=max(y, 0), z=max(z, 0), erreurs=erreurs)

    marge = x + y - z
    en_danger = marge > 0
    urgence = 1.0 if en_danger else (x + y) / z
    score = round(100 * POIDS[exposition] * urgence)
    priorite: Priorite = next((nom for seuil, nom in SEUILS if score >= seuil), "faible")
    etat = "dépasse" if en_danger else "ne dépasse pas"
    explication = (
        f"Données à protéger {x:g} an(s) (x) et migration de {y:g} an(s) (y) : x + y = {x + y:g}, "
        f"ce qui {etat} l'horizon de la menace de {z:g} an(s) (z), marge {marge:+g} an(s). "
        f"Exposition « {exposition} » : score {score}/100, priorité {priorite}."
    )
    return ResultatMosca(x=x, y=y, z=z, marge=marge, en_danger=en_danger, score=score, priorite=priorite, explication=explication)
