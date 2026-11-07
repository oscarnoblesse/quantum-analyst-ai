"""Installation du modèle local : Ollama, puis le modèle figé dans config/experiment.yaml.

Usage (depuis la racine du dépôt) :

    uv run python -m quantum_ready.installation_modele

Le script est idempotent : il ne réinstalle que ce qui manque. Il vérifie à la fin
que le modèle installé a bien l'empreinte figée dans la configuration, et qu'il
déclare la capacité « tools ». Sans ces deux vérifications, les résultats ne sont
pas reproductibles.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parents[2]
CONFIG = RACINE / "config" / "experiment.yaml"
URL_OLLAMA = "https://ollama.com/download"
URL_INSTALLEUR_LINUX = "https://ollama.com/install.sh"
DELAI_DEMARRAGE_SECONDES = 60


class ErreurInstallation(RuntimeError):
    """Une étape n'a pas pu aboutir ; le message indique quoi faire à la main."""


def lire_modele(config: Path = CONFIG) -> tuple[str, str, str]:
    """(nom, empreinte, hôte) du modèle, lus dans la configuration du projet."""
    modele = yaml.safe_load(config.read_text(encoding="utf-8"))["modele"]
    return modele["nom"], str(modele["empreinte"]), modele.get("hote", "http://localhost:11434")


def lire_empreinte(sortie_ollama_list: str, nom: str) -> str | None:
    """ID affiché par `ollama list` pour ce nom, ou None si le modèle n'est pas installé."""
    for ligne in sortie_ollama_list.splitlines()[1:]:  # la première ligne est l'en-tête
        colonnes = ligne.split()
        if len(colonnes) >= 2 and colonnes[0] == nom:
            return colonnes[1]
    return None


def serveur_actif(hote: str) -> bool:
    try:
        with urllib.request.urlopen(f"{hote}/api/tags", timeout=3):
            return True
    except (urllib.error.URLError, OSError):
        return False


def demarrer_serveur(hote: str) -> None:
    """Lance `ollama serve` détaché du terminal, puis attend qu'il réponde."""
    options: dict = {"start_new_session": True}
    if os.name == "nt":
        options = {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
    subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
    limite = time.monotonic() + DELAI_DEMARRAGE_SECONDES
    while time.monotonic() < limite:
        if serveur_actif(hote):
            return
        time.sleep(1)
    raise ErreurInstallation(f"le serveur Ollama ne répond pas sur {hote} après {DELAI_DEMARRAGE_SECONDES} s")


def installer_ollama(systeme: str) -> None:
    """Installe Ollama avec le gestionnaire du système, ou indique la procédure manuelle."""
    if systeme == "Darwin" and shutil.which("brew"):
        commande = ["brew", "install", "ollama"]
    elif systeme == "Windows" and shutil.which("winget"):
        commande = ["winget", "install", "--id", "Ollama.Ollama", "-e",
                    "--accept-package-agreements", "--accept-source-agreements"]
    elif systeme == "Linux":
        # Script officiel d'Ollama : téléchargé dans un fichier temporaire, puis exécuté.
        # Il demande le mot de passe administrateur (sudo) s'il en a besoin.
        with tempfile.TemporaryDirectory() as dossier:
            script = Path(dossier) / "install.sh"
            with urllib.request.urlopen(URL_INSTALLEUR_LINUX, timeout=60) as reponse:
                script.write_bytes(reponse.read())
            commande = ["sh", str(script)]
            print("   $ sh install.sh  (script officiel d'Ollama)", flush=True)
            if subprocess.run(commande).returncode != 0:
                raise ErreurInstallation(f"le script d'installation a échoué ; procédure manuelle : {URL_OLLAMA}")
        return
    else:
        raise ErreurInstallation(f"aucun gestionnaire d'installation trouvé ; installez Ollama à la main : {URL_OLLAMA}")

    print("   $ " + " ".join(commande), flush=True)
    if subprocess.run(commande).returncode != 0:
        raise ErreurInstallation(f"l'installation a échoué ; procédure manuelle : {URL_OLLAMA}")


def ollama_list() -> str:
    return subprocess.run(["ollama", "list"], capture_output=True, text=True, encoding="utf-8", check=True).stdout


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args(argv)

    nom, empreinte, hote = lire_modele()
    systeme = platform.system()
    try:
        print("== Étape 1 : Ollama")
        if shutil.which("ollama") is None:
            installer_ollama(systeme)
            if shutil.which("ollama") is None:
                raise ErreurInstallation("Ollama installé mais introuvable : rouvrez le terminal, puis relancez ce script")
        print(f"   {subprocess.run(['ollama', '--version'], capture_output=True, text=True).stdout.strip()}")

        print("== Étape 2 : serveur Ollama")
        if not serveur_actif(hote):
            demarrer_serveur(hote)
        print(f"   actif sur {hote}")

        print(f"== Étape 3 : modèle {nom}")
        installe = lire_empreinte(ollama_list(), nom)
        if installe is None:
            print("   téléchargement (environ 2,5 Go)…", flush=True)
            if subprocess.run(["ollama", "pull", nom]).returncode != 0:
                raise ErreurInstallation(f"le téléchargement de {nom} a échoué")
            installe = lire_empreinte(ollama_list(), nom)
        if installe is None or not installe.startswith(empreinte):
            raise ErreurInstallation(
                f"{nom} est installé avec l'ID {installe}, alors que la configuration attend {empreinte} : "
                "le même nom désigne un autre modèle ; supprimez-le avec `ollama rm` puis relancez"
            )
        print(f"   ID {installe} : conforme à la configuration")

        print("== Étape 4 : capacité « tools »")
        if "tools" not in subprocess.run(["ollama", "show", nom], capture_output=True, text=True, encoding="utf-8").stdout:
            raise ErreurInstallation(f"{nom} ne déclare pas la capacité « tools », requise par les agents")
        print("   déclarée")
    except (ErreurInstallation, subprocess.CalledProcessError, OSError) as erreur:
        print(f"\nÉchec : {erreur}", file=sys.stderr)
        return 1

    print("\nModèle prêt. Lancer les agents : make agents  (ou uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele ollama)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
