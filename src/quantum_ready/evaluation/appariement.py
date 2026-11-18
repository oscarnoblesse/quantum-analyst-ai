"""Appariement entre les composants d'un CBOM et les actifs de la vérité terrain.

Un composant correspond à un actif de la vérité terrain si :
1. ils ont le même type CycloneDX (algorithm, certificate, protocol,
   related-crypto-material, library) ;
2. ils sont au même endroit : un emplacement du composant est l'un des fichiers
   cités par l'actif (ou les deux sont implicites, sans fichier).
Parmi les candidats, on préfère celui dont le nom et la description partagent le
plus de mots avec l'actif et ses paramètres. L'appariement est un-à-un, glouton,
par score décroissant.

Un composant non apparié qui AURAIT pu correspondre à un actif déjà apparié est
un « doublon » (le même actif vu deux fois) ; sinon il est « en trop ». Les deux
précisions sont publiées, pour que ce choix soit transparent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CHEMIN = re.compile(r"[\w.\-]+(?:/[\w.\-]+)+|\.env\b|uv\.lock\b")
_MOT = re.compile(r"[a-z0-9]+")


def mots(texte: str) -> set[str]:
    return {m for m in _MOT.findall(texte.lower().replace("-", " ").replace("_", " ")) if len(m) >= 2}


@dataclass
class Composant:
    reference: str
    type_actif: str
    nom: str
    texte: str
    emplacements: list[str]
    exposition: str | None = None

    @property
    def implicite(self) -> bool:
        return all(e.startswith("implicite") for e in self.emplacements)

    @classmethod
    def depuis_cbom(cls, composant: dict) -> "Composant":
        proprietes = {p["name"].split(":")[-1]: p["value"] for p in composant.get("properties", [])}
        return cls(
            reference=composant.get("bom-ref", composant.get("name", "?")),
            type_actif=composant.get("cryptoProperties", {}).get("assetType", "library" if composant.get("type") == "library" else "?"),
            nom=composant.get("name", ""),
            texte=f"{composant.get('name', '')} {composant.get('version', '')} {composant.get('description', '')}",
            emplacements=[o.get("location", "") for o in composant.get("evidence", {}).get("occurrences", [])] or ["?"],
            exposition=proprietes.get("exposition-quantique"),
        )


@dataclass
class Appariement:
    paires: dict[str, str] = field(default_factory=dict)        # id vérité terrain -> référence composant
    doublons: list[str] = field(default_factory=list)            # références
    en_trop: list[str] = field(default_factory=list)             # références


def chemins(actif: dict) -> list[str]:
    return _CHEMIN.findall(actif["fichier"])


def candidat(actif: dict, composant: Composant) -> bool:
    if composant.type_actif != actif["type_cyclonedx"]:
        return False
    if actif["fichier"].lower().startswith("aucun"):
        return composant.implicite
    return any(e == c or e.endswith("/" + c) or c.endswith("/" + e) for c in chemins(actif) for e in composant.emplacements)


def score(actif: dict, composant: Composant) -> float:
    attendus = mots(f"{actif['actif']} {actif['algorithme']}")
    trouves = mots(composant.texte)
    commun = len(attendus & trouves) / max(1, min(len(attendus), len(trouves)))
    principal = chemins(actif)[:1]
    bonus = 0.1 if principal and any(e == principal[0] or e.endswith("/" + principal[0]) for e in composant.emplacements[:1]) else 0
    return commun + bonus


def apparier(actifs: list[dict], composants: list[Composant]) -> Appariement:
    couples = sorted(((score(a, c), a["id"], c.reference) for a in actifs for c in composants if candidat(a, c)), reverse=True)
    resultat = Appariement()
    pris = set()
    for _, identifiant, reference in couples:
        if identifiant not in resultat.paires and reference not in pris:
            resultat.paires[identifiant] = reference
            pris.add(reference)
    apparies = set(resultat.paires)
    for composant in composants:
        if composant.reference in pris:
            continue
        if any(candidat(a, composant) for a in actifs if a["id"] in apparies):
            resultat.doublons.append(composant.reference)
        else:
            resultat.en_trop.append(composant.reference)
    return resultat
