"""Politiques simulées : des « modèles » déterministes qui jouent un agent raisonnable.

Elles ne remplacent pas un vrai modèle de langage : elles vérifient que la
mécanique (prompts, mémoire de travail, MCP, sorties) PERMET d'atteindre le but.
Elles servent aussi de référence d'ablation « agent à règles fixes ».
"""

import json
import re

from quantum_ready.llm import Reponse, appel, texte


def _memoire(messages):
    return next((m["content"] for m in messages if m["role"] == "user" and m["content"].startswith("Mémoire de travail")), "")


def _resultats_outils(messages):
    return [m["content"] for m in messages if m["role"] == "tool"]


def inventoriste(messages, outils) -> Reponse:
    memoire = _memoire(messages)
    if "Aucune carte" in memoire:
        return appel("lister_fichiers", cible=".")
    restant = re.search(r"^- (\S+) -> (\w+)$", memoire, re.M)
    if restant:
        chemin, outil = restant.groups()
        if outil == "scanner_code_crypto":
            chemin = chemin.split("/")[0]
        if outil == "analyser_dependances":
            chemin = chemin.rsplit("/", 1)[0]
        return appel(outil, cible=chemin)
    deja = " ".join(json.dumps(c.get("tool_calls", "")) for c in messages if c["role"] == "assistant")
    piste = re.search(r"variable (\w+) : appeler analyser_pkcs12", memoire)
    if piste and "fichier_env" not in deja:
        return appel("analyser_pkcs12", cible="factures/keys/factures.p12", fichier_env="api/.env", variable=piste.group(1))
    return texte({"resume": "Inventaire terminé.", "exclusions": [], "liens": [{"de": "api/.env", "vers": "factures/keys/factures.p12", "explication": "KEYSTORE_PASS ouvre le PKCS#12"}]})


def cartographe(messages, outils) -> Reponse:
    resultats = _resultats_outils(messages)
    if not any("CBOM enregistré" in r for r in resultats):
        exclusions = re.findall(r"^- (T\d{4}) :", messages[1]["content"], re.M)
        return appel("construire_cbom", exclure=exclusions)
    if not any(r.startswith("CBOM VALIDE") for r in resultats):
        return appel("valider_schema")
    composants = int(re.search(r"(\d+) composants", next(r for r in resultats if "CBOM enregistré" in r)).group(1))
    return texte({"cbom_valide": True, "composants": composants, "exclusions": [], "resume": "CBOM construit et validé."})


def analyste(messages, outils) -> Reponse:
    memoire = _memoire(messages)
    if "Tous les actifs sont évalués" in memoire:
        return texte({"evalues": int(re.search(r"(\d+) actifs évalués", memoire).group(1)), "critiques": [], "resume": "Évaluation terminée."})
    lectures = [r for r in _resultats_outils(messages) if r.startswith("Actifs ")]
    references = re.search(r"Prochaines références à évaluer : (.+)", memoire).group(1).split(", ")
    if not lectures or not any(references[0] in r for r in lectures):
        lues = re.search(r"déjà lues : \[([\d, ]*)\]", memoire)
        return appel("lister_actifs", page=len(lues.group(1).split(",")) + 1 if lues else 1)
    lignes = {l.split(" | ")[0]: l for l in lectures[-1].splitlines()[1:]}
    evaluations = []
    for ref in references:
        ligne = lignes.get(ref, "")
        x = 10 if "3650" in ligne or "Factures" in ligne else 5 if "shor" in ligne else 1
        evaluations.append({"ref": ref, "x": x, "y": 2, "justification": "règle simulée"})
    return appel("score_mosca", evaluations=evaluations)
