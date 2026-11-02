"""Outil score_mosca : priorité de migration d'un actif, d'après l'inégalité de Mosca.

>>> À IMPLÉMENTER PAR OSCAR <<<
Les tests sont dans tests/test_outil_score_mosca.py (marqués xfail tant que la
fonction lève NotImplementedError). Quand ta version passe, retire le marqueur.

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

Question à te poser en l'écrivant : pourquoi « inconnue » pèse-t-il comme « shor » ?
Et pourquoi le modèle de langage ne doit-il PAS calculer ce score lui-même ?
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NOM = "score_mosca"
Priorite = Literal["critique", "haute", "moyenne", "faible"]


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
    raise NotImplementedError("À toi de jouer : la spécification est dans la docstring du module")
