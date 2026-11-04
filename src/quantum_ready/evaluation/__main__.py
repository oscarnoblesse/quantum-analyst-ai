"""Évalue une ou plusieurs sessions et affiche un tableau comparatif.

    python -m quantum_ready.evaluation traces/A traces/B [--verite data/ground_truth/si_v1.json]

Chaque session reçoit un fichier evaluation.json ; le tableau est écrit sur la sortie standard (Markdown).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from quantum_ready.evaluation.mesures import VERITE_TERRAIN, evaluer
from quantum_ready.serveur_mcp.session import ecrire_json

LIGNES = [
    ("CBOM valide", lambda r: "oui" if r.get("cbom_valide") else "non"),
    ("Rappel", lambda r: f"{r['qualite']['rappel']:.1%}"),
    ("Rappel des actifs cachés", lambda r: f"{r['qualite']['rappel_caches']:.1%}"),
    ("Précision stricte", lambda r: f"{r['qualite']['precision_stricte']:.1%}"),
    ("Précision hors doublons", lambda r: f"{r['qualite']['precision_hors_doublons']:.1%}"),
    ("F1", lambda r: f"{r['qualite']['f1']:.3f}"),
    ("Composants / appariés / doublons / en trop", lambda r: f"{r['qualite']['composants']} / {r['qualite']['apparies']} / {r['qualite']['doublons']} / {r['qualite']['en_trop']}"),
    ("Actifs Shor bien classés", lambda r: r["qualite"]["shor_bien_classes"]),
    ("Appels d'outils (refusés, en erreur)", lambda r: f"{r['couts']['appels_outils']} ({r['couts']['appels_refuses']}, {r['couts']['erreurs_outils']})"),
    ("Tours de modèle", lambda r: str(r["couts"]["tours_de_modele"])),
    ("Jetons entrée / sortie", lambda r: f"{r['couts']['jetons_entree']} / {r['couts']['jetons_sortie']}"),
    ("Durée totale (s)", lambda r: str(r["couts"]["duree_totale_s"])),
]


def tableau(resultats: list[dict]) -> str:
    entete = "| Mesure | " + " | ".join(Path(r["session"]).name for r in resultats) + " |"
    lignes = [entete, "|---" * (len(resultats) + 1) + "|"]
    for titre, valeur in LIGNES:
        cellules = []
        for r in resultats:
            try:
                cellules.append(valeur(r))
            except (KeyError, TypeError):
                cellules.append("—")
        lignes.append(f"| {titre} | " + " | ".join(cellules) + " |")
    return "\n".join(lignes)


def main(argv: list[str] | None = None) -> None:
    analyseur = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    analyseur.add_argument("sessions", nargs="+")
    analyseur.add_argument("--verite", default=str(VERITE_TERRAIN))
    options = analyseur.parse_args(argv)
    resultats = []
    for session in options.sessions:
        resultat = evaluer(session, options.verite)
        ecrire_json(Path(session) / "evaluation.json", resultat)
        resultats.append(resultat)
    print(tableau(resultats))
    for r in resultats:
        if "qualite" in r and r["qualite"]["manques"]:
            print(f"\n{Path(r['session']).name} — actifs manqués : {', '.join(r['qualite']['manques'])}")


if __name__ == "__main__":
    main()
