"""Reproduction du projet, identique sous macOS, Linux et Windows.

Usage (depuis la racine du dépôt, après avoir installé uv) :

    uv run python scripts/reproduire.py            # reproduction complète
    uv run python scripts/reproduire.py --petite   # environnement + tests (CI rapide)
    uv run python scripts/reproduire.py --si-v2    # SI d'évaluation v2 seul : génération et contrôles
    uv run python scripts/reproduire.py --verifier-si-v2   # contrôles du SI v2 déjà généré

Ce script n'utilise que la bibliothèque standard : il ne dépend ni de make,
ni de bash, ni d'un shell particulier. Chaque étape est lancée sans shell
(liste d'arguments), donc les chemins avec espaces ou accents passent.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
VERITE_CSV = Path("data/ground_truth/verite_terrain_v1.csv")
VERITE_JSON = Path("data/ground_truth/si_v1.json")
SI = Path("si/generated/v1")
VERITE_CSV_V2 = Path("data/ground_truth/verite_terrain_v2.csv")
VERITE_JSON_V2 = Path("data/ground_truth/si_v2.json")
LEURRES_V2 = Path("data/ground_truth/leurres_v2.csv")
CBOM_ATTENDU_V2 = Path("data/ground_truth/cbom_attendu_v2.json")
SI_V2 = Path("si/generated/v2")
SEUIL_COUVERTURE = 70


def etapes_verifier_si_v2() -> list[tuple[str, list[str]]]:
    """Contrôles du SI v2 déjà généré (équivalent de « make verifier-si-v2 »)."""
    uv = ["uv", "run", "python"]
    return [
        ("Vérifier le SI v2 contre sa vérité terrain",
         [*uv, "-m", "quantum_ready.si_fictif.controles_v2", str(SI_V2), str(VERITE_CSV_V2), str(LEURRES_V2)]),
    ]


def etapes_si_v2() -> list[tuple[str, list[str]]]:
    """SI d'évaluation v2 : vérité terrain, CBOM attendu, génération, contrôles (« make si-v2 » puis contrôles)."""
    uv = ["uv", "run", "python"]
    return [
        ("Valider la vérité terrain v2",
         [*uv, "-m", "quantum_ready.verite_terrain", str(VERITE_CSV_V2), str(VERITE_JSON_V2)]),
        ("Construire et valider le CBOM attendu v2",
         [*uv, "scripts/cbom_attendu.py", str(VERITE_CSV_V2), str(CBOM_ATTENDU_V2)]),
        ("Générer le SI fictif v2", [*uv, "-m", "quantum_ready.si_fictif", "--variante", "v2", "--ecraser"]),
        *etapes_verifier_si_v2(),
    ]


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
            *etapes_si_v2(),
        ]
    liste.append((
        f"Lancer les tests (couverture ≥ {SEUIL_COUVERTURE} %)",
        ["uv", "run", "pytest", "--cov=quantum_ready", "--cov-report=term-missing", f"--cov-fail-under={SEUIL_COUVERTURE}"],
    ))
    return liste


def openssl_de_git() -> Path | None:
    """openssl.exe livré avec Git for Windows (Git\\usr\\bin), absent du PATH par défaut."""
    git = shutil.which("git")
    if git is None:
        return None
    candidat = Path(git).resolve().parent.parent / "usr" / "bin" / "openssl.exe"
    return candidat if candidat.is_file() else None


def openssl_manquant(windows: bool | None = None) -> str | None:
    """Message d'erreur si openssl est introuvable, None sinon.

    Sans openssl, la macro HIGH de nginx n'est pas développée : l'actif caché QR-015
    (suite TLS 1.2 à échange RSA) n'est pas détecté et les tests qui l'attendent
    échouent. On s'arrête donc avant de lancer quoi que ce soit.
    """
    if shutil.which("openssl") is not None:
        return None
    message = ("openssl est introuvable. Il sert à développer la macro TLS « HIGH » de nginx ; "
               "sans lui, l'actif caché QR-015 n'est pas détecté et des tests échouent.")
    if windows is None:
        windows = os.name == "nt"
    git = openssl_de_git() if windows else None
    if git is not None:
        message += (f"\nGit for Windows en fournit un. Ajoutez son dossier au PATH, puis relancez :"
                    f'\n    $env:Path += ";{git.parent}"')
    else:
        message += "\nInstallez OpenSSL 3 (paquet « openssl » sous Linux, Homebrew sous macOS, Git for Windows sous Windows)."
    return message


def main() -> int:
    # Sous Windows, la sortie standard est en cp1252 : on la passe en UTF-8 pour ce processus aussi.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    choix = parseur.add_mutually_exclusive_group()
    choix.add_argument("--petite", action="store_true", help="installer et tester sans régénérer le SI")
    choix.add_argument("--si-v2", action="store_true", help="générer et contrôler le SI d'évaluation v2 seulement")
    choix.add_argument("--verifier-si-v2", action="store_true", help="contrôler le SI v2 déjà généré")
    args = parseur.parse_args()

    if shutil.which("uv") is None:
        print("uv est introuvable. Installez-le : https://docs.astral.sh/uv/getting-started/installation/", file=sys.stderr)
        return 2
    if (erreur := openssl_manquant()) is not None:
        print(erreur, file=sys.stderr)
        return 2

    # Mode UTF-8 pour tous les processus Python lancés : sous Windows, la sortie
    # standard est en cp1252 par défaut et ne sait pas écrire « → » ni « ≥ ».
    environnement = {**os.environ, "PYTHONUTF8": "1"}

    debut = time.monotonic()
    if args.si_v2:
        liste = etapes_si_v2()
    elif args.verifier_si_v2:
        liste = etapes_verifier_si_v2()
    else:
        liste = etapes(args.petite)
    for numero, (libelle, commande) in enumerate(liste, start=1):
        print(f"\n== Étape {numero} : {libelle}", flush=True)
        print("   $ " + " ".join(commande), flush=True)
        resultat = subprocess.run(commande, cwd=RACINE, env=environnement)
        if resultat.returncode != 0:
            print(f"\nÉchec à l'étape {numero} (code {resultat.returncode}).", file=sys.stderr)
            return resultat.returncode

    print(f"\nReproduction terminée avec succès en {time.monotonic() - debut:.0f} s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
