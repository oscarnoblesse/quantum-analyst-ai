"""Reproduction de bout en bout avec un très petit modèle (qwen3:0.6b), pour la CI.

Ce que la CI vérifie : la chaîne complète tourne avec un modèle de langage, le journal est écrit
à chaque étape, et les appels d'outils purs se rejouent à l'identique. Ce que la CI NE vérifie
PAS : la qualité de l'inventaire. Un modèle de 0,6 milliard de paramètres n'est pas capable de
la faire ; un arrêt propre (« sortie_invalide », « inventaire_vide ») est un résultat attendu.

Usage : uv run python scripts/reproduce_petit_modele.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
CONFIGURATION = "config/experiment_petit.yaml"
SESSION = "traces/ci_petit_modele"
ARRETS_PROPRES = {"termine", "sortie_invalide", "inventaire_vide", "limite_etapes", "erreur_modele", "cbom_invalide"}


def lancer(libelle: str, *commande: str) -> int:
    print(f"== {libelle}", flush=True)
    print("   $ " + " ".join(commande), flush=True)
    return subprocess.run(commande, cwd=RACINE).returncode


def verifier_journaux(session: Path) -> list[str]:
    problemes = []
    for fichier in ("journal_agents.jsonl", "journal_outils.jsonl", "configuration.yaml"):
        if not (session / fichier).is_file():
            problemes.append(f"{fichier} absent de la session")
    if (session / "journal_agents.jsonl").is_file():
        fins = [json.loads(l) for l in (session / "journal_agents.jsonl").read_text(encoding="utf-8").splitlines()
                if '"evenement": "fin"' in l]
        if not fins:
            problemes.append("aucun agent n'a fini proprement (pas d'événement « fin »)")
        for fin in fins:
            if fin["arret"] not in ARRETS_PROPRES:
                problemes.append(f"arrêt inattendu : {fin['arret']}")
    return problemes


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    code = lancer("Installation du petit modèle", "uv", "run", "python", "-m", "quantum_ready.installation_modele",
                  "--configuration", CONFIGURATION)
    if code != 0:
        print("Installation du modèle échouée", file=sys.stderr)
        return code
    code = lancer("Exécution du système multi-agents avec le petit modèle", "uv", "run", "python", "-m", "quantum_ready.orchestrateur",
                  "--racine", "si/generated/v1", "--modele", "ollama", "--configuration", CONFIGURATION,
                  "--validation", "accepter", "--session", SESSION)
    if code != 0:
        print("L'orchestrateur a échoué", file=sys.stderr)
        return code
    problemes = verifier_journaux(RACINE / SESSION)
    code = lancer("Rejeu des appels d'outils purs", "uv", "run", "python", "-m", "quantum_ready.rejeu", SESSION,
                  "--racine", "si/generated/v1")
    if code != 0:
        problemes.append("le rejeu a trouvé un appel dont la sortie diffère de l'enregistrement")
    if problemes:
        print("Problèmes :\n  - " + "\n  - ".join(problemes), file=sys.stderr)
        return 1
    print("Chaîne complète vérifiée avec le petit modèle (aucune qualité d'inventaire n'est visée ici).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
