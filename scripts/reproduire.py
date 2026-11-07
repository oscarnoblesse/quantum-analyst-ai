"""Reproduction du projet, identique sous macOS, Linux et Windows.

Usage (depuis la racine du dépôt, après avoir installé uv) :

    uv run python scripts/reproduire.py            # reproduction complète
    uv run python scripts/reproduire.py --petite   # environnement + tests (CI rapide)

Ce script n'utilise que la bibliothèque standard : il ne dépend ni de make,
ni de bash, ni d'un shell particulier. Chaque étape est lancée sans shell
(liste d'arguments), donc les chemins avec espaces ou accents passent.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
VERITE_CSV = Path("data/ground_truth/verite_terrain_v1.csv")
VERITE_JSON = Path("data/ground_truth/si_v1.json")
SI = Path("si/generated/v1")
SEUIL_COUVERTURE = 70


def etapes(petite: bool) -> list[tuple[str, list[str]]]:
    """Liste ordonnée des étapes : (libellé, commande)."""
    uv = ["uv", "run", "python"]
    liste: list[tuple[str, list[str]]] = [
        ("Installer l'environnement figé", ["uv", "sync", "--locked"]),
    ]
    if not petite:
        liste += [
            ("Valider la vérité terrain", [*uv, "-m", "quantum_ready.verite_terrain", str(VERITE_CSV), str(VERITE_JSON)]),
            ("Générer le SI fictif v1", [*uv, "-m", "quantum_ready.si_fictif", "--variante", "v1", "--ecraser"]),
            ("Vérifier le SI contre la vérité terrain", [*uv, "-m", "quantum_ready.si_fictif.controles", str(SI), str(VERITE_CSV)]),
        ]
    liste.append((
        f"Lancer les tests (couverture ≥ {SEUIL_COUVERTURE} %)",
        ["uv", "run", "pytest", "--cov=quantum_ready", "--cov-report=term-missing", f"--cov-fail-under={SEUIL_COUVERTURE}"],
    ))
    return liste


def main() -> int:
    parseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parseur.add_argument("--petite", action="store_true", help="installer et tester sans régénérer le SI")
    args = parseur.parse_args()

    if shutil.which("uv") is None:
        print("uv est introuvable. Installez-le : https://docs.astral.sh/uv/getting-started/installation/", file=sys.stderr)
        return 2

    debut = time.monotonic()
    for numero, (libelle, commande) in enumerate(etapes(args.petite), start=1):
        print(f"\n== Étape {numero} : {libelle}", flush=True)
        print("   $ " + " ".join(commande), flush=True)
        resultat = subprocess.run(commande, cwd=RACINE)
        if resultat.returncode != 0:
            print(f"\nÉchec à l'étape {numero} (code {resultat.returncode}).", file=sys.stderr)
            return resultat.returncode

    print(f"\nReproduction terminée avec succès en {time.monotonic() - debut:.0f} s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
