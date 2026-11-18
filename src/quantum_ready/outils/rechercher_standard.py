"""Outil rechercher_standard : recherche documentaire dans le corpus de normes (data/standards).

Le « R » d'un RAG, sans modèle d'embeddings : un classement BM25 des paragraphes,
déterministe et explicable, suffisant pour un corpus de quelques dizaines de
paragraphes. L'agent formule la requête ; l'outil renvoie les passages et l'identifiant
de leur fiche, que l'agent doit citer dans son plan.
"""

from __future__ import annotations

import math
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

NOM = "rechercher_standard"
VARIABLE_CORPUS = "QR_CORPUS_STANDARDS"
K1, B = 1.5, 0.75
MOTS_VIDES = set("le la les un une des de du d l et ou a au aux en dans pour par sur avec sans que qui ne pas est sont ce cette ces se sa son ses plus the of and to in for is on".split())


@dataclass(frozen=True)
class Passage:
    fiche: str
    titre: str
    source: str
    texte: str


class Extrait(BaseModel):
    fiche: str
    titre: str
    source: str
    texte: str
    score: float


class ResultatRecherche(BaseModel):
    outil: str = NOM
    requete: str
    extraits: list[Extrait] = Field(default_factory=list)
    erreurs: list[str] = Field(default_factory=list)


def dossier_corpus() -> Path:
    return Path(os.environ.get(VARIABLE_CORPUS) or Path(__file__).resolve().parents[3] / "data" / "standards")


def termes(texte: str) -> list[str]:
    sans_accents = unicodedata.normalize("NFKD", texte.lower()).encode("ascii", "ignore").decode()
    return [t for t in re.findall(r"[a-z0-9]+", sans_accents) if t not in MOTS_VIDES and len(t) > 1]


@lru_cache(maxsize=4)
def charger(dossier: str) -> tuple[Passage, ...]:
    passages = []
    for fichier in sorted(Path(dossier).glob("*.md")):
        texte = fichier.read_text(encoding="utf-8")
        entete = dict(re.findall(r"^(id|titre|source|date): (.+)$", texte, re.M))
        if "id" not in entete:
            continue  # README et autres fichiers sans en-tête
        corps = texte.split("\n\n", 1)[1] if "\n\n" in texte else ""
        for paragraphe in (p.strip() for p in corps.split("\n\n")):
            if paragraphe:
                passages.append(Passage(entete["id"], entete.get("titre", ""), entete.get("source", ""), paragraphe))
    return tuple(passages)


def rechercher_standard(requete: str, nombre: int = 3, dossier: str | Path | None = None) -> ResultatRecherche:
    """Les passages du corpus les plus pertinents pour une requête (BM25)."""
    resultat = ResultatRecherche(requete=requete)
    passages = charger(str(dossier or dossier_corpus()))
    if not passages:
        resultat.erreurs.append("Corpus de normes vide ou introuvable")
        return resultat
    demandes = termes(requete)
    if not demandes:
        resultat.erreurs.append("Requête vide : donner des mots-clés (algorithme, protocole, usage)")
        return resultat
    documents = [Counter(termes(f"{p.titre} {p.texte}")) for p in passages]
    longueur_moyenne = sum(sum(d.values()) for d in documents) / len(documents)
    frequences = Counter(t for d in documents for t in d)
    scores = []
    for passage, document in zip(passages, documents):
        longueur = sum(document.values())
        score = 0.0
        for terme in demandes:
            if terme in document:
                idf = math.log(1 + (len(documents) - frequences[terme] + 0.5) / (frequences[terme] + 0.5))
                tf = document[terme]
                score += idf * tf * (K1 + 1) / (tf + K1 * (1 - B + B * longueur / longueur_moyenne))
        if score > 0:
            scores.append((score, passage))
    scores.sort(key=lambda s: -s[0])
    resultat.extraits = [Extrait(fiche=p.fiche, titre=p.titre, source=p.source, texte=p.texte, score=round(s, 3)) for s, p in scores[: max(1, min(nombre, 5))]]
    if not resultat.extraits:
        resultat.erreurs.append("Aucun passage pertinent : reformuler avec d'autres mots-clés")
    return resultat


def fiches_connues(dossier: str | Path | None = None) -> set[str]:
    return {p.fiche for p in charger(str(dossier or dossier_corpus()))}
