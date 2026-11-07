"""Socle commun des outils déterministes.

Trois règles valent pour TOUS les outils, quel que soit l'agent qui les appelle :

1. Périmètre : un outil ne lit que des fichiers situés dans la racine du SI fictif.
   Un chemin qui en sort (« ../../.ssh/id_rsa », lien symbolique...) est refusé.
   C'est la première défense contre une injection de consignes qui pousserait
   un agent à lire autre chose que le SI.
2. Pas d'exception vers l'agent : une erreur devient un champ `erreurs` du
   résultat. Un agent qui reçoit une trace Python ne sait pas quoi en faire ;
   un message clair, il peut le comprendre et réessayer autrement.
3. Pas de secret vers le modèle : un mot de passe ou une clé trouvés dans le SI
   sont décrits (longueur, forme) mais jamais recopiés dans le résultat.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Les types d'actifs de CycloneDX 1.6 (champ assetType), plus « library » pour
# les dépendances, qui deviennent des composants de type library dans le CBOM.
TypeActif = Literal["algorithm", "certificate", "protocol", "related-crypto-material", "library"]

# Ce que l'ordinateur quantique change pour cet actif :
# - shor : cassé (RSA, DH, courbes elliptiques) ;
# - grover : affaibli, la sécurité est divisée par deux en bits (AES, SHA-2...) ;
# - resistant : conçu pour résister (ML-KEM, ML-DSA, SLH-DSA) ;
# - aucune : rien de cryptographique à attaquer (choix de configuration, version) ;
# - inconnue : l'outil n'a pas su déterminer l'algorithme.
Exposition = Literal["shor", "grover", "resistant", "aucune", "inconnue"]

VARIABLE_RACINE = "QR_RACINE_SI"


class ErreurOutil(Exception):
    """Erreur prévue, dont le message est destiné à l'agent."""


class Trouvaille(BaseModel):
    """Un actif cryptographique trouvé par un outil. C'est la brique du futur CBOM."""

    model_config = ConfigDict(extra="forbid")

    outil: str
    fichier: str = Field(description="Chemin relatif à la racine du SI ; vide pour un actif implicite")
    ligne: int | None = None
    type_actif: TypeActif
    nom: str = Field(description="Nom court et lisible, par exemple « RSA-2048 » ou « TLSv1.2 »")
    description: str = Field(description="Ce qu'est l'actif dans le SI, en une phrase")
    exposition: Exposition
    implicite: bool = Field(False, description="Valeur par défaut, écrite nulle part dans le SI")
    proprietes: dict[str, str | int | bool | list[str]] = Field(default_factory=dict)
    preuve: str = Field("", description="Extrait court du fichier qui justifie la trouvaille (sans secret)")


class Piste(BaseModel):
    """Un lien vers un autre fichier ou une autre information, que l'agent peut décider de suivre."""

    model_config = ConfigDict(extra="forbid")

    vers: str = Field(description="Fichier, variable d'environnement ou élément à examiner")
    raison: str


class FichierSI(BaseModel):
    """Un fichier du SI, tel que le voit lister_fichiers."""

    model_config = ConfigDict(extra="forbid")

    chemin: str
    taille: int
    droits: str = Field(description="Droits Unix en octal, par exemple « 600 »")
    nature: str = Field(description="Nature reconnue d'après le contenu, pas d'après le nom")
    outil_conseille: str | None = None
    remarque: str | None = Field(None, description="Limite connue de l'analyse de ce fichier")


class Resultat(BaseModel):
    """Ce que renvoie chaque outil."""

    model_config = ConfigDict(extra="forbid")

    outil: str
    cible: str
    trouvailles: list[Trouvaille] = Field(default_factory=list)
    pistes: list[Piste] = Field(default_factory=list)
    fichiers: list[FichierSI] = Field(default_factory=list)
    erreurs: list[str] = Field(default_factory=list)


def racine_si(racine: str | Path | None = None) -> Path:
    """Racine du SI : argument explicite, sinon variable d'environnement QR_RACINE_SI."""
    valeur = racine if racine is not None else os.environ.get(VARIABLE_RACINE)
    if not valeur:
        raise ErreurOutil(f"Racine du SI inconnue : définir {VARIABLE_RACINE}")
    chemin = Path(valeur).resolve()
    if not chemin.is_dir():
        raise ErreurOutil(f"La racine du SI n'est pas un dossier : {valeur}")
    return chemin


def resoudre(chemin: str, racine: Path) -> Path:
    """Chemin absolu d'un fichier du SI ; refuse tout ce qui sort du périmètre."""
    if not chemin or "\x00" in chemin:
        raise ErreurOutil("Chemin vide ou invalide")
    cible = (racine / chemin).resolve()  # resolve() suit aussi les liens symboliques
    if not cible.is_relative_to(racine):
        raise ErreurOutil(f"Chemin hors du périmètre du SI, refusé : {chemin}")
    if not cible.exists():
        raise ErreurOutil(f"Fichier introuvable dans le SI : {chemin}")
    return cible


def relatif(chemin: Path, racine: Path) -> str:
    return chemin.relative_to(racine).as_posix()


def outil(nom: str) -> Callable:
    """Décorateur : transforme les erreurs en résultat lisible par l'agent.

    La fonction décorée reçoit (cible, racine: Path, **options) et renvoie un Resultat.
    L'agent l'appelle avec (cible, racine=None, **options).
    """

    def decorer(fonction: Callable[..., Resultat]) -> Callable[..., Resultat]:
        @functools.wraps(fonction)
        def enveloppe(cible: str = ".", racine: str | Path | None = None, **options) -> Resultat:
            try:
                return fonction(cible, racine_si(racine), **options)
            except ErreurOutil as erreur:
                return Resultat(outil=nom, cible=cible, erreurs=[str(erreur)])
            except Exception as erreur:  # robustesse : un fichier inattendu ne fait pas tomber l'agent
                return Resultat(
                    outil=nom, cible=cible, erreurs=[f"Erreur inattendue ({type(erreur).__name__}) : {erreur}"]
                )

        enveloppe.nom_outil = nom
        return enveloppe

    return decorer


def decrire_secret(valeur: str) -> str:
    """Description d'un secret sans le révéler : longueur et alphabet utilisé."""
    alphabets = []
    if any(c.islower() for c in valeur):
        alphabets.append("minuscules")
    if any(c.isupper() for c in valeur):
        alphabets.append("majuscules")
    if any(c.isdigit() for c in valeur):
        alphabets.append("chiffres")
    if any(not c.isalnum() for c in valeur):
        alphabets.append("symboles")
    return f"{len(valeur)} caractères ({', '.join(alphabets) or 'vide'})"


def lire_env(texte: str) -> list[tuple[int, str, str]]:
    """Lignes « NOM=valeur » d'un fichier .env : (numéro de ligne, nom, valeur sans guillemets)."""
    variables = []
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        nom, valeur = ligne.removeprefix("export ").split("=", 1)
        valeur = valeur.strip()
        if len(valeur) >= 2 and valeur[0] == valeur[-1] and valeur[0] in "\"'":
            valeur = valeur[1:-1]
        variables.append((numero, nom.strip(), valeur))
    return variables


def secret_depuis_env(fichier_env: str, variable: str, racine: Path) -> str:
    """Valeur d'une variable d'un .env du SI. Réservé aux outils : ne jamais la renvoyer à l'agent."""
    try:
        texte = resoudre(fichier_env, racine).read_text(encoding="utf-8")
    except ErreurOutil as erreur:
        candidats = sorted(p.relative_to(racine).as_posix() for p in racine.rglob("*") if p.is_file() and (p.name.startswith(".env") or p.suffix == ".env"))
        raise ErreurOutil(f"{erreur}. Fichiers de variables du SI : {', '.join(candidats) or 'aucun'}") from erreur
    for _, nom, valeur in lire_env(texte):
        if nom == variable:
            return valeur
    raise ErreurOutil(f"Variable {variable} absente de {fichier_env}")
