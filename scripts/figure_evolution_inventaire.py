"""Figure : évolution de l'inventaire multi-agents au fil des versions des prompts.

Recalcule chaque exécution de traces/ avec l'évaluateur du projet (aucune valeur saisie à la main),
puis trace deux panneaux à axe des x commun : F1 (avec la référence « outils seuls ») et nombre
d'appels d'outils en erreur. Écrit results/figures/evolution_inventaire.svg et .png.

    uv run --with matplotlib python scripts/figure_evolution_inventaire.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from quantum_ready.evaluation.mesures import evaluer  # noqa: E402

RACINE = Path(__file__).resolve().parents[1]
TRACES = RACINE / "traces"
SORTIE = RACINE / "results" / "figures" / "evolution_inventaire"

# Exécutions dans l'ordre chronologique ; correspondance avec docs/journal_des_prompts.md.
EXECUTIONS = [
    ("20261104T174709Z_ollama", "v1\n04/11"),
    ("20261104T182150Z_ollama", "v2\n04/11"),
    ("20261104T193349Z_ollama", "v3\n04/11"),
    ("20261104T203840Z_ollama", "v4\n04/11"),
    ("20261104T213437Z_ollama", "v5\n04/11"),
    ("20261107T214549Z_ollama", "v5\n07/11"),
    ("20261108T084744Z_ollama", "v6 int.\n08/11"),
    ("mesure_v6_run1", "v6 r1\nMac"),
    ("mesure_v6_run2", "v6 r2\nMac"),
    ("mesure_v6_run3", "v6 r3\nMac"),
    ("test_windows_20261117", "v6\nWin"),
    ("scan_develop_98ce8af", "v6\nWin"),
]
REFERENCE = "reference_outils_seuls"

BLEU = "#2a78d6"
SURFACE = "#fcfcfb"
ENCRE = "#0b0b0b"
ENCRE_2 = "#52514e"
GRILLE = "#e4e3df"


def fr(valeur: float) -> str:
    return f"{valeur:.3f}".replace(".", ",")


def main() -> None:
    resultats = [(etiquette, evaluer(TRACES / nom)) for nom, etiquette in EXECUTIONS]
    f1_reference = evaluer(TRACES / REFERENCE)["qualite"]["f1"]
    x = list(range(len(resultats)))
    f1 = [r["qualite"]["f1"] for _, r in resultats]
    erreurs = [r["couts"]["erreurs_outils"] for _, r in resultats]
    conforme = [bool(r.get("plan") and r["plan"]["conforme"]) for _, r in resultats]

    plt.rcParams["svg.hashsalt"] = "quantum-ready"  # identifiants SVG stables : fichier identique à chaque exécution
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "text.color": ENCRE,
                         "axes.labelcolor": ENCRE_2, "xtick.color": ENCRE_2, "ytick.color": ENCRE_2})
    fig, (haut, bas) = plt.subplots(2, 1, figsize=(8.6, 5.6), sharex=True,
                                    gridspec_kw={"height_ratios": [3, 2], "hspace": 0.12})
    fig.patch.set_facecolor(SURFACE)
    for ax in (haut, bas):
        ax.set_facecolor(SURFACE)
        ax.grid(axis="y", color=GRILLE, linewidth=0.8)
        ax.set_axisbelow(True)
        for cote in ("top", "right", "left"):
            ax.spines[cote].set_visible(False)
        ax.spines["bottom"].set_color(ENCRE_2)
        ax.tick_params(length=0)
        ax.axvline(6.5, color=GRILLE, linewidth=1.2)  # séparation : mesures finales v6
        ax.axvline(9.5, color=GRILLE, linewidth=1.2)  # séparation : Mac / Windows

    # Panneau 1 : F1, marqueur plein = plan conforme, creux = plan non conforme.
    haut.axhline(f1_reference, color=ENCRE_2, linewidth=1, linestyle=(0, (4, 3)))
    haut.text(len(x) - 0.4, f1_reference - 0.035, f"outils seuls, sans LLM : {fr(f1_reference)}",
              ha="right", va="top", color=ENCRE_2, fontsize=8)
    haut.plot(x, f1, color=BLEU, linewidth=2, zorder=2)
    for xi, yi, ok in zip(x, f1, conforme):
        haut.plot(xi, yi, marker="o", markersize=7, zorder=3, markeredgewidth=2,
                  markerfacecolor=BLEU if ok else SURFACE, markeredgecolor=BLEU)
    haut.annotate(fr(f1[0]), (0, f1[0]), textcoords="offset points", xytext=(8, -2), color=ENCRE, fontsize=8)
    meilleur = max(range(len(f1)), key=lambda i: f1[i])
    haut.annotate(fr(f1[meilleur]), (meilleur, f1[meilleur]), textcoords="offset points",
                  xytext=(0, 9), ha="center", color=ENCRE, fontsize=8)
    haut.annotate(fr(f1[-1]), (x[-1], f1[-1]), textcoords="offset points",
                  xytext=(0, 9), ha="center", color=ENCRE, fontsize=8)
    haut.set_ylim(0, 1.08)
    haut.yaxis.set_major_formatter(lambda v, _: f"{v:.1f}".replace(".", ","))
    haut.set_ylabel("F1 de l'inventaire")
    haut.set_title("Inventaire multi-agents (qwen3 4B) : qualité et erreurs d'outils par exécution",
                   loc="left", fontsize=11, color=ENCRE, pad=26)
    haut.legend(handles=[
        Line2D([], [], marker="o", color=BLEU, markerfacecolor=BLEU, markersize=7, linewidth=2, label="plan conforme"),
        Line2D([], [], marker="o", color=BLEU, markerfacecolor=SURFACE, markeredgewidth=2, markersize=7,
               linewidth=2, label="plan non conforme"),
    ], loc="lower right", bbox_to_anchor=(1, 1.0), ncol=2, frameon=False, fontsize=8, borderaxespad=0.2)

    # Panneau 2 : appels d'outils en erreur.
    barres = bas.bar(x, erreurs, width=0.55, color=BLEU, zorder=2)
    for barre, n in zip(barres, erreurs):
        bas.text(barre.get_x() + barre.get_width() / 2, n + 0.2, str(n), ha="center", va="bottom",
                 color=ENCRE, fontsize=8)
    bas.set_ylim(0, max(erreurs) + 2)
    bas.set_ylabel("Appels d'outils\nen erreur")
    bas.set_xticks(x, [e for e, _ in resultats], fontsize=8)

    fig.text(0.01, 0.005, "Source : traces/ du dépôt, recalculées avec quantum_ready.evaluation "
             "(vérité terrain data/ground_truth/si_v1.json, 73 actifs).", color=ENCRE_2, fontsize=7)
    fig.subplots_adjust(left=0.1, right=0.98, top=0.88, bottom=0.14)
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(SORTIE.with_suffix(".svg"), facecolor=SURFACE, metadata={"Date": None})
    fig.savefig(SORTIE.with_suffix(".png"), dpi=200, facecolor=SURFACE)
    print(f"Écrit : {SORTIE.with_suffix('.svg').relative_to(RACINE)} et .png")


if __name__ == "__main__":
    main()
