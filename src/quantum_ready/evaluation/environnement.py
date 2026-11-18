"""Écrit results/ENVIRONMENT.json : versions des outils et empreinte du modèle utilisés pour produire les résultats.

Rien n'est saisi à la main, sauf la version d'Ollama, que config/experiment.yaml consigne. Un outil absent
est noté « absent », jamais inventé.

Usage : uv run python -m quantum_ready.evaluation.environnement
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parents[3]
SORTIE = RACINE / "results" / "ENVIRONMENT.json"
CONFIGURATION = RACINE / "config" / "experiment.yaml"


def _version(commande: list[str]) -> str:
    if shutil.which(commande[0]) is None:
        return "absent"
    try:
        resultat = subprocess.run(commande, capture_output=True, text=True, timeout=20, cwd=RACINE)
    except (OSError, subprocess.SubprocessError):
        return "erreur"
    sortie = (resultat.stdout or resultat.stderr).strip().splitlines()
    return sortie[0] if sortie else "inconnue"


def _commit() -> str:
    if shutil.which("git") is None:
        return "absent"
    resultat = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=RACINE)
    return resultat.stdout.strip() or "inconnu"


def construire() -> dict:
    texte = CONFIGURATION.read_bytes()
    parametres = yaml.safe_load(texte.decode("utf-8"))
    modele = parametres["modele"]
    return {
        "genere_le": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "systeme": platform.platform(),
        "python": sys.version.split()[0],
        "uv": _version(["uv", "--version"]),
        "docker": _version(["docker", "--version"]),
        "openssl_hote": _version(["openssl", "version"]),
        "openssl_laboratoire": "voir results/raw/demonstrateur_verification.json (version dans le conteneur)",
        "ollama": {"version": modele.get("version_ollama", "non consignée"), "modele": modele["nom"],
                   "empreinte": modele["empreinte"]},
        "configuration_sha256": hashlib.sha256(texte).hexdigest(),
        "commit": _commit(),
    }


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(construire(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Environnement écrit dans {SORTIE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
