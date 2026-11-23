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
        "rappel_par_perimetre": rappel_par_perimetre(actifs, trouves),
        "precision_stricte": round(precision, 4),
        "precision_hors_doublons": round(apparies / max(1, n - len(appariement.doublons)), 4),
        "f1": round(2 * rappel * precision / (rappel + precision), 4) if rappel + precision else 0,
        "shor_bien_classes": f"{len(shor_bien_classes)}/{len(shor)}",
        "manques": sorted(set(a["id"] for a in actifs) - trouves),
        "composants_en_trop": [f"{r} {par_reference[r].nom[:60]}" for r in appariement.en_trop],
        "appariement": appariement.paires,
    }


def rappel_par_perimetre(actifs: list[dict], trouves: set[str]) -> dict:
    """Rappel séparé par périmètre (vérité terrain v2 : « connu » ou « hors périmètre »).

    Les technologies hors périmètre n'ont aucun analyseur dédié (docs/perimetre_et_validation_des_outils.md) :
    les mélanger aux actifs connus rendrait le rappel global illisible. Vide pour une vérité terrain sans périmètre (v1).
    """
    groupes: dict[str, list[dict]] = {}
    for actif in actifs:
        if actif.get("perimetre"):
            groupes.setdefault(actif["perimetre"], []).append(actif)
    return {
        perimetre: {"trouves": sum(a["id"] in trouves for a in groupe), "attendus": len(groupe),
                    "rappel": round(sum(a["id"] in trouves for a in groupe) / len(groupe), 4)}
        for perimetre, groupe in sorted(groupes.items())
    }


def fichier_de(emplacement: str) -> str:
    """Chemin du fichier d'un emplacement CBOM (sans numéro de ligne éventuel)."""
    return emplacement.split(":", 1)[0] if not emplacement.startswith("implicite") else emplacement


def leurres_touches(cbom: dict, appariement_paires: dict[str, str], doublons: list[str], leurres: list[dict]) -> list[dict]:
    """Faux positifs certains : composants NI appariés NI doublons, situés dans le fichier d'un leurre.

    Un leurre ressemble à de la cryptographie sans en être (MD5 d'une clé de cache, certificat de test…).
    Un composant apparié à un vrai actif du même fichier n'est jamais compté : un fichier peut contenir à la
    fois un leurre et de vrais actifs (exemple : une ligne en commentaire à côté des vraies directives).
    """
    retenus = set(appariement_paires.values()) | set(doublons)
    fichiers = {l["Fichier / emplacement"]: l["ID"] for l in leurres}
    touches = []
    for composant in cbom.get("components", []):
        reference = composant.get("bom-ref", composant.get("name", "?"))
        if reference in retenus:
            continue
        for occurrence in composant.get("evidence", {}).get("occurrences", []):
            fichier = fichier_de(occurrence.get("location", ""))
            if fichier in fichiers:
                touches.append({"leurre": fichiers[fichier], "composant": reference, "nom": composant.get("name", "")[:60]})
                break
    return touches


def lire_leurres(chemin: str | Path | None) -> list[dict] | None:
    if not chemin:
        return None
    import csv

    with Path(chemin).open(encoding="utf-8", newline="") as flux:
        return list(csv.DictReader(flux))


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


def evaluer(dossier: str | Path, verite_terrain: str | Path = VERITE_TERRAIN, leurres: str | Path | None = None) -> dict:
    dossier = Path(dossier)
    cbom_chemin = dossier / "cbom.json"
    actifs = json.loads(Path(verite_terrain).read_text(encoding="utf-8"))["actifs"]
    resultat = {"session": str(dossier), "verite_terrain": str(verite_terrain)}
    if not cbom_chemin.is_file():
        return resultat | {"erreur": "aucun cbom.json dans la session", "couts": couts(dossier)}
    cbom = json.loads(cbom_chemin.read_text(encoding="utf-8"))
    from quantum_ready.outils.valider_schema import valider_schema

    validation = valider_schema(cbom)
    mesures_qualite = qualite(cbom, actifs)
    liste_leurres = lire_leurres(leurres)
    if liste_leurres is not None:
        composants = [Composant.depuis_cbom(c) for c in cbom.get("components", [])]
        apparie = apparier(actifs, composants)
        touches = leurres_touches(cbom, apparie.paires, apparie.doublons, liste_leurres)
        mesures_qualite["leurres"] = {"fichier": str(leurres), "nombre": len(liste_leurres),
                                      "leurres_touches": sorted({t["leurre"] for t in touches}),
                                      "composants_sur_leurres": touches}
    return resultat | {"cbom_valide": validation.valide, "qualite": mesures_qualite, "plan": plan(dossier), "couts": couts(dossier)}


def plan(dossier: Path) -> dict | None:
    """Plan de migration : nombre d'étapes et conformité, revérifiée ici avec les règles de l'Architecte."""
    chemin = dossier / "plan.json"
    if not chemin.is_file():
        return None
    from quantum_ready.agents.architecte import verifier_plan
    from quantum_ready.serveur_mcp.session import Session

    contenu = json.loads(chemin.read_text(encoding="utf-8"))
    erreurs = verifier_plan(contenu, Session(dossier, dossier))
    return {"etapes": len(contenu.get("etapes", [])), "conforme": not erreurs, "erreurs": erreurs,
            "references": sorted({r for e in contenu.get("etapes", []) for r in e.get("references", [])})}
