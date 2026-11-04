"""Politiques à règles fixes : des « modèles » déterministes qui jouent un agent raisonnable.

Elles ne remplacent pas un vrai modèle de langage : elles vérifient que la
mécanique (prompts, mémoire de travail, MCP, sorties) PERMET d'atteindre le but,
et servent de configuration d'ablation « agents à règles fixes, sans LLM ».
Elles lisent la mémoire de travail et les résultats d'outils, comme le ferait le modèle.
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
    evaluations = []
    for ligne in memoire.splitlines():
        if ligne.startswith("crypto-"):
            ref = ligne.split(" | ")[0]
            x = 10 if "3650" in ligne or "factures" in ligne.lower() else 5 if "shor" in ligne else 1
            evaluations.append({"ref": ref, "x": x, "y": 2, "justification": "règle simulée"})
    return appel("score_mosca", evaluations=evaluations)


POLITIQUES = {"inventoriste": inventoriste, "cartographe": cartographe, "analyste_risque": analyste}


THEMES = [  # (motif dans le lieu ou le nom, requête, action, cible, échéance, fiche)
    ("nginx", "échange de clés TLS hybride", "Mettre à jour OpenSSL (3.5 ou plus), proposer X25519MLKEM768, désactiver TLS 1.2 et les suites Kx=RSA",
     "X25519MLKEM768, TLS 1.3", "immédiat", "IETF-TLS-HYBRIDE"),
    ("ssh", "OpenSSH KexAlgorithms hybride", "Retirer la liste KexAlgorithms écrite à la main, passer à OpenSSH 10, retirer la clé DSA",
     "mlkem768x25519-sha256", "immédiat", "OPENSSH-PQ"),
    ("factures", "signature ML-DSA factures", "Signer les factures en ML-DSA (ou hybride), conserver les vérifications des anciennes signatures",
     "ML-DSA-65", "avant 2030", "NIST-FIPS-204"),
    ("scripts", "sauvegardes chiffrement hybride GnuPG", "Rechiffrer les sauvegardes pour une clé hybride ML-KEM", "ML-KEM-768 + courbe elliptique", "immédiat", "GNUPG-PQ"),
    ("", "certificats ML-DSA PKI autorités", "Préparer une PKI ML-DSA (autorités puis certificats serveurs et clients)", "ML-DSA-65 / ML-DSA-87", "avant 2030", "NIST-FIPS-204"),
]


def architecte(messages, outils) -> Reponse:
    resultats = _resultats_outils(messages)
    recherches = re.search(r"Recherches faites \((\d+)\)", _memoire(messages))
    faites = int(recherches.group(1)) if recherches else 0
    if faites < len(THEMES):  # les recherches d'abord : la mémoire de travail en garde la trace
        return appel("rechercher_standard", requete=THEMES[faites][1])
    priorites = next((r for r in resultats if "les plus prioritaires" in r), None)
    if priorites is None:  # puis la liste des priorités, juste avant d'écrire le plan
        return appel("lister_priorites", nombre=500)
    lignes = [l.split(" | ") for l in priorites.splitlines()[1:]]
    etapes = []
    restantes = [l for l in lignes if l[2] == "critique"]
    for ordre, (motif, _, action, cible, echeance, fiche) in enumerate(THEMES, start=1):
        concernes = [l for l in restantes if motif in l[4] or motif in l[3].lower()] if motif else restantes
        restantes = [l for l in restantes if l not in concernes]
        if concernes:
            etapes.append({"ordre": len(etapes) + 1, "actifs": [l[0] for l in concernes], "action": action, "cible": cible,
                           "echeance": echeance, "references": [fiche, "MOSCA"]})
    return texte({"etapes": etapes, "resume": "Plan à règles fixes : échanges de clés d'abord, puis signatures et PKI."})


POLITIQUES["architecte"] = architecte
