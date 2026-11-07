"""Ligne de commande : python -m quantum_ready.si_fictif [--sortie DOSSIER] [--ecraser]"""

from __future__ import annotations

import argparse
import sys

from quantum_ready.si_fictif.generateur import ErreurGenerateur, generer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Génère le SI fictif de Quantum-Ready.")
    parser.add_argument("--variante", default="v1")
    parser.add_argument("--sortie", help="Dossier du SI (défaut : si/generated/<variante>)")
    parser.add_argument("--hors-si", help="Dossier hors périmètre (défaut : si/generated/hors_si/<variante>)")
    parser.add_argument("--ecraser", action="store_true", help="Remplace un SI déjà généré")
    args = parser.parse_args(argv)
    sortie = args.sortie or f"si/generated/{args.variante}"
    try:
        ctx = generer(sortie, args.hors_si, variante=args.variante, ecraser=args.ecraser)
    except ErreurGenerateur as erreur:
        print(f"Erreur : {erreur}", file=sys.stderr)
        return 1
    print(f"SI {args.variante} généré dans {ctx.racine_si} : {len(ctx.fichiers)} fichiers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
