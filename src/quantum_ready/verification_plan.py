"""Vérification du plan par démonstration (décision de méthode n° 2, docs/decisions_methode.md).

Chaque étape du plan est classée :
- « démontrée » : sa cible est démontrable au laboratoire et la démonstration réussit ;
- « échec » : sa cible est démontrable et la démonstration échoue (motif donné) ;
- « non vérifiée » : sa cible n'est pas démontrable au laboratoire. Jamais « validée ».

Le vérificateur (fonction qui lance la démonstration) est passé en paramètre : le classement
est testable sans Docker. Les vérificateurs réels sont dans `outils/laboratoire.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# Cible du plan (normalisée) -> clé de démonstration du laboratoire.
DEMONSTRABLES: dict[str, str] = {
    "x25519mlkem768": "tls-hybride",
    "ml-dsa-65": "certificat-mldsa65",
    "mlkem768x25519-sha256": "ssh-hybride",
}


@dataclass(frozen=True)
class Verdict:
    ordre: int
    cible: str
    statut: str  # « démontrée », « échec » ou « non vérifiée »
    motif: str = ""


def cle_de_demonstration(cible: str) -> str | None:
    """Clé de démonstration d'une cible du plan, None si elle n'est pas démontrable au laboratoire.

    La cible peut être décrite en langage libre (« X25519MLKEM768, TLS 1.3 ») : on cherche le nom
    de l'algorithme dans le texte. Un nom absent donne None : jamais une correspondance devinée.
    """
    texte = cible.strip().lower()
    return next((cle for nom, cle in DEMONSTRABLES.items() if nom in texte), None)


def classer(plan: dict | None, verifier: Callable[[str], tuple[bool, str]]) -> list[Verdict]:
    """Un verdict par étape. `verifier(clé)` renvoie (réussi, motif) ; il n'est appelé qu'une fois par clé."""
    verdicts: list[Verdict] = []
    resultats: dict[str, tuple[bool, str]] = {}
    for etape in (plan or {}).get("etapes", []):
        cible = str(etape.get("cible", ""))
        cle = cle_de_demonstration(cible)
        if cle is None:
            verdicts.append(Verdict(etape.get("ordre", 0), cible, "non vérifiée",
                                    "cible non démontrable au laboratoire (GnuPG, PKI hors laboratoire, etc.)"))
            continue
        if cle not in resultats:
            resultats[cle] = verifier(cle)
        reussi, motif = resultats[cle]
        verdicts.append(Verdict(etape.get("ordre", 0), cible, "démontrée" if reussi else "échec", "" if reussi else motif))
    return verdicts


def erreurs_pour_l_architecte(verdicts: list[Verdict]) -> list[str]:
    """Motifs des étapes en échec, à renvoyer à l'Architecte. Une étape non vérifiée n'est pas une erreur."""
    return [f"étape {v.ordre} ({v.cible}) : démonstration échouée : {v.motif}" for v in verdicts if v.statut == "échec"]
