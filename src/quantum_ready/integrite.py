"""Intégrité des artefacts publiés : fichier SHA256SUMS (sujet, « résultats signés »).

    uv run python -m quantum_ready.integrite generer    # écrit SHA256SUMS à la racine
    uv run python -m quantum_ready.integrite verifier   # vérifie chaque empreinte

SHA256SUMS liste l'empreinte SHA-256 de chaque artefact publié : métriques et mesures brutes
(results/), traces complètes des exécutions (traces/) et vérité terrain (data/ground_truth/).
Le code n'y figure pas : son intégrité est assurée par le commit git et l'archive Zenodo.

Le format est celui de `sha256sum` (« <empreinte>  <chemin> », chemins en « / », triés,
fin de ligne LF) : `sha256sum -c SHA256SUMS` le vérifie aussi sous Linux, et le fichier est
identique octet pour octet sous macOS, Linux et Windows (.gitattributes impose LF).

Ce fichier assure l'intégrité, pas l'authenticité : quiconque modifie un résultat peut aussi
recalculer SHA256SUMS. L'authenticité vient de la signature minisign de SHA256SUMS
(SHA256SUMS.minisig), vérifiable avec la clé publique du dépôt (voir AUDIT.md). La signature
est faite par l'auteur, sur sa machine, au moment de la release : jamais par `make reproduce`,
ni par la CI.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
NOM_FICHIER = "SHA256SUMS"
DOSSIERS_PUBLIES = ("results", "traces", "data/ground_truth")
IGNORES = {".gitkeep", ".DS_Store"}


def artefacts(racine: Path) -> list[str]:
    """Chemins relatifs (en « / », triés) des artefacts publiés présents sous la racine."""
    chemins = []
    for dossier in DOSSIERS_PUBLIES:
        base = racine / dossier
        if not base.is_dir():
            continue
        for fichier in base.rglob("*"):
            if fichier.is_file() and fichier.name not in IGNORES and "__pycache__" not in fichier.parts:
                chemins.append(fichier.relative_to(racine).as_posix())
    return sorted(chemins)


def empreinte(fichier: Path) -> str:
    h = hashlib.sha256()
    with fichier.open("rb") as flux:
        for bloc in iter(lambda: flux.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def contenu(racine: Path) -> str:
    """Texte de SHA256SUMS pour l'état actuel des artefacts."""
    return "".join(f"{empreinte(racine / chemin)}  {chemin}\n" for chemin in artefacts(racine))


def generer(racine: Path = RACINE) -> Path:
    sortie = racine / NOM_FICHIER
    sortie.write_bytes(contenu(racine).encode("utf-8"))
    return sortie


def lire(fichier: Path) -> dict[str, str]:
    """{chemin: empreinte} d'un fichier au format sha256sum."""
    attendues = {}
    for numero, ligne in enumerate(fichier.read_text(encoding="utf-8").splitlines(), start=1):
        if not ligne.strip():
            continue
        # « <empreinte>  <chemin> » (mode texte) ou « <empreinte> *<chemin> » (mode binaire).
        valeur, _, reste = ligne.partition(" ")
        if len(valeur) != 64 or reste[:1] not in (" ", "*") or not reste[1:]:
            raise ValueError(f"{fichier.name}, ligne {numero} : format invalide")
        attendues[reste[1:]] = valeur.lower()
    return attendues


@dataclass
class Bilan:
    verifies: int = 0
    differents: list[str] = field(default_factory=list)
    manquants: list[str] = field(default_factory=list)
    non_listes: list[str] = field(default_factory=list)

    @property
    def conforme(self) -> bool:
        """Les fichiers non listés (ex. une évaluation relancée par l'auditeur) ne sont qu'un avertissement."""
        return not self.differents and not self.manquants


def verifier(racine: Path = RACINE) -> Bilan:
    attendues = lire(racine / NOM_FICHIER)
    bilan = Bilan()
    for chemin, valeur in attendues.items():
        fichier = racine / chemin
        if not fichier.is_file():
            bilan.manquants.append(chemin)
        elif empreinte(fichier) != valeur:
            bilan.differents.append(chemin)
        else:
            bilan.verifies += 1
    bilan.non_listes = [c for c in artefacts(racine) if c not in attendues]
    return bilan


def main(argv: list[str] | None = None) -> int:
    parseur = argparse.ArgumentParser(description="Génère ou vérifie SHA256SUMS (artefacts publiés).")
    parseur.add_argument("action", choices=["generer", "verifier"])
    parseur.add_argument("--racine", type=Path, default=RACINE)
    args = parseur.parse_args(argv)

    if args.action == "generer":
        sortie = generer(args.racine)
        nombre = len(lire(sortie))
        print(f"{sortie.name} écrit : {nombre} artefacts. Pensez à le signer (make signer) avant la release.")
        return 0

    if not (args.racine / NOM_FICHIER).is_file():
        print(f"{NOM_FICHIER} introuvable : lancez d'abord « make sommes ».", file=sys.stderr)
        return 2
    bilan = verifier(args.racine)
    for chemin in bilan.differents:
        print(f"DIFFÉRENT  {chemin}")
    for chemin in bilan.manquants:
        print(f"MANQUANT   {chemin}")
    for chemin in bilan.non_listes:
        print(f"NON LISTÉ  {chemin} (avertissement)")
    print(f"{bilan.verifies} artefacts vérifiés, {len(bilan.differents)} différents, "
          f"{len(bilan.manquants)} manquants, {len(bilan.non_listes)} non listés.")
    return 0 if bilan.conforme else 1


if __name__ == "__main__":
    sys.exit(main())
