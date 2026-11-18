"""Figures SVG générées depuis results/metrics.json (bibliothèque standard seulement).

Chaque barre est une valeur versionnée ; l'écart type, quand il existe, est tracé en trait. Les libellés
sont échappés. Usage : uv run python -m quantum_ready.evaluation.figures
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
METRIQUES = RACINE / "results" / "metrics.json"
DOSSIER = RACINE / "results" / "figures"
LARGEUR_BARRE = 420
HAUTEUR_LIGNE = 34
MARGE_GAUCHE = 300


def barres_svg(titre: str, lignes: list[tuple[str, float, float | None]], unite: str) -> str:
    """Barres horizontales ; lignes = (libellé, moyenne, écart type ou None)."""
    valeurs = [v + (e or 0) for _, v, e in lignes] or [1]
    echelle = LARGEUR_BARRE / max(valeurs)
    hauteur = 60 + HAUTEUR_LIGNE * len(lignes)
    parties = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {MARGE_GAUCHE + LARGEUR_BARRE + 80} {hauteur}" '
        f'role="img" aria-label="{html.escape(titre)}" font-family="system-ui,sans-serif" font-size="13">',
        f'<text x="8" y="22" font-size="15" font-weight="600">{html.escape(titre)}</text>',
    ]
    for i, (libelle, moyenne, ecart) in enumerate(lignes):
        y = 44 + i * HAUTEUR_LIGNE
        largeur = moyenne * echelle
        parties.append(f'<text x="8" y="{y + 14}">{html.escape(libelle)}</text>')
        parties.append(f'<rect x="{MARGE_GAUCHE}" y="{y}" width="{largeur:.1f}" height="20" fill="#2a5d8f" rx="2"/>')
        if ecart:
            debut, fin = (moyenne - ecart) * echelle, (moyenne + ecart) * echelle
            parties.append(f'<line x1="{MARGE_GAUCHE + max(debut, 0):.1f}" y1="{y + 10}" x2="{MARGE_GAUCHE + fin:.1f}" '
                           f'y2="{y + 10}" stroke="#1d1d1b" stroke-width="2"/>')
        suffixe = f" ± {ecart:g}" if ecart else ""
        parties.append(f'<text x="{MARGE_GAUCHE + largeur + 8:.1f}" y="{y + 14}">{moyenne:g}{suffixe} {html.escape(unite)}</text>')
    parties.append("</svg>")
    return "\n".join(parties) + "\n"


def construire(metriques: dict) -> dict[str, str]:
    figures = {}
    latence = metriques["demonstrateur"].get("latence_bench_pqc")
    if latence:
        lignes = [(nom, c["mediane_us"], c.get("mediane_ecart_type_us")) for nom, c in latence["configurations"].items()
                  if c.get("mediane_us") is not None]
        figures["latence.svg"] = barres_svg("Latence médiane du handshake TLS 1.3", lignes, "µs")
    signatures = metriques["demonstrateur"].get("signatures")
    if signatures:
        lignes = [(nom, a["signature"]["moyenne_us"], a["signature"]["ecart_type_us"])
                  for nom, a in signatures["algorithmes"].items() if a["signature"]["moyenne_us"] is not None]
        figures["signatures.svg"] = barres_svg("Temps de signature", lignes, "µs")
    return figures


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    figures = construire(json.loads(METRIQUES.read_text(encoding="utf-8")))
    DOSSIER.mkdir(parents=True, exist_ok=True)
    for nom, svg in figures.items():
        (DOSSIER / nom).write_text(svg, encoding="utf-8", newline="\n")
    print(f"{len(figures)} figure(s) écrite(s) dans {DOSSIER}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
