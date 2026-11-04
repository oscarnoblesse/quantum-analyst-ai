"""Mesures d'une session : qualité de l'inventaire et coûts du système."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from quantum_ready.evaluation.appariement import Composant, apparier

VERITE_TERRAIN = Path("data/ground_truth/si_v1.json")


def _evenements(chemin: Path) -> list[dict]:
    if not chemin.is_file():
        return []
    return [json.loads(l) for l in chemin.read_text(encoding="utf-8").splitlines() if l.strip()]


def qualite(cbom: dict, actifs: list[dict]) -> dict:
    composants = [Composant.depuis_cbom(c) for c in cbom.get("components", [])]
    appariement = apparier(actifs, composants)
    par_reference = {c.reference: c for c in composants}
    trouves = set(appariement.paires)
    caches = [a for a in actifs if a["visibilite"] == "Caché"]
    shor = [a for a in actifs if a["vulnerabilite"].startswith("Oui")]
    shor_bien_classes = [a for a in shor if a["id"] in trouves and par_reference[appariement.paires[a["id"]]].exposition == "shor"]
    categories = Counter(a.get("categorie_cachee") or "?" for a in caches)
    categories_trouvees = Counter(a.get("categorie_cachee") or "?" for a in caches if a["id"] in trouves)
    n, apparies = len(composants), len(appariement.paires)
    rappel = apparies / len(actifs) if actifs else 0
    precision = apparies / n if n else 0
    return {
        "actifs_attendus": len(actifs),
        "composants": n,
        "apparies": apparies,
        "doublons": len(appariement.doublons),
        "en_trop": len(appariement.en_trop),
        "rappel": round(rappel, 4),
        "rappel_visibles": round(sum(a["id"] in trouves for a in actifs if a["visibilite"] != "Caché") / max(1, len(actifs) - len(caches)), 4),
        "rappel_caches": round(sum(a["id"] in trouves for a in caches) / max(1, len(caches)), 4),
        "rappel_par_categorie_cachee": {k: f"{categories_trouvees[k]}/{v}" for k, v in sorted(categories.items())},
        "precision_stricte": round(precision, 4),
        "precision_hors_doublons": round(apparies / max(1, n - len(appariement.doublons)), 4),
        "f1": round(2 * rappel * precision / (rappel + precision), 4) if rappel + precision else 0,
        "shor_bien_classes": f"{len(shor_bien_classes)}/{len(shor)}",
        "manques": sorted(set(a["id"] for a in actifs) - trouves),
        "composants_en_trop": [f"{r} {par_reference[r].nom[:60]}" for r in appariement.en_trop],
        "appariement": appariement.paires,
    }


def couts(dossier: Path) -> dict:
    outils = _evenements(dossier / "journal_outils.jsonl")
    agents = _evenements(dossier / "journal_agents.jsonl")
    fins = [e for e in agents if e.get("evenement") == "fin"]
    tours = [e for e in agents if e.get("evenement") == "tour"]
    return {
        "appels_outils": sum(e.get("statut") in ("ok", "erreur", "exception") for e in outils),
        "appels_refuses": sum(e.get("statut") == "refus" for e in outils),
        "erreurs_outils": sum(e.get("statut") in ("erreur", "exception") for e in outils),
        "tours_de_modele": len(tours),
        "jetons_entree": sum(e.get("jetons_entree") or 0 for e in tours),
        "jetons_sortie": sum(e.get("jetons_sortie") or 0 for e in tours),
        "duree_modele_s": round(sum(e.get("duree_ms") or 0 for e in tours) / 1000, 1),
        "duree_totale_s": round(sum(e.get("duree_ms") or 0 for e in fins) / 1000, 1),
        "arrets": {e["agent"]: e.get("arret") for e in fins},
    }


def evaluer(dossier: str | Path, verite_terrain: str | Path = VERITE_TERRAIN) -> dict:
    dossier = Path(dossier)
    cbom_chemin = dossier / "cbom.json"
    actifs = json.loads(Path(verite_terrain).read_text(encoding="utf-8"))["actifs"]
    resultat = {"session": str(dossier), "verite_terrain": str(verite_terrain)}
    if not cbom_chemin.is_file():
        return resultat | {"erreur": "aucun cbom.json dans la session", "couts": couts(dossier)}
    cbom = json.loads(cbom_chemin.read_text(encoding="utf-8"))
    from quantum_ready.outils.valider_schema import valider_schema

    validation = valider_schema(cbom)
    return resultat | {"cbom_valide": validation.valide, "qualite": qualite(cbom, actifs), "couts": couts(dossier)}
