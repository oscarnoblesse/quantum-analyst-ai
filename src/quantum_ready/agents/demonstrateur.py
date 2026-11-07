"""Agent Démonstrateur : fait tourner le laboratoire TLS pour chaque groupe et mesure le handshake.

Le modèle choisit l'ordre des appels et rédige la conclusion. Les chiffres viennent
uniquement des outils (journal de la session) : le code vérifie que la réponse finale
les reprend à l'identique, et refuse de terminer tant que les étapes ne sont pas faites.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import NamedTuple

import yaml

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, EtatBoucle
from quantum_ready.agents.communs import lancer, lire_prompt
from quantum_ready.llm import ModeleSimule, depuis_configuration
from quantum_ready.outils import laboratoire
from quantum_ready.serveur_mcp.session import Session

NOM = "demonstrateur"
JOURNAL = "journal_outils.jsonl"
HYBRIDE = "X25519MLKEM768"
CLASSIQUE = "X25519"
CIBLE = "127.0.0.1:8443"


class Etape(NamedTuple):
    outil: str
    groupe: str | None  # None : l'outil ne prend pas de groupe (il agit sur le laboratoire déjà démarré)


PLAN: list[Etape] = [
    Etape("demarrer_laboratoire", HYBRIDE), Etape("scan_tls_lab", HYBRIDE), Etape("mesurer_handshake", HYBRIDE),
    Etape("arreter_laboratoire", HYBRIDE),
    Etape("demarrer_laboratoire", CLASSIQUE), Etape("scan_tls_lab", CLASSIQUE), Etape("mesurer_handshake", CLASSIQUE),
    Etape("arreter_laboratoire", CLASSIQUE),
]


class ResultatGroupe(BaseModel):
    groupe: str
    scan_accepte: bool = Field(description="le groupe est-il accepté par le serveur, d'après scan_tls_lab")
    mediane_us: float | None = None
    p95_us: float | None = None
    client_hello_octets: int | None = None


class SortieDemonstrateur(BaseModel):
    resultats: list[ResultatGroupe]
    resume: str = Field(description="deux ou trois phrases, sans chiffre absent des résultats")


def _evenements_agent(session: Session) -> list[dict]:
    return [e for e in session.evenements(JOURNAL) if e.get("agent") == NOM]


def _correspond(evenement: dict, etape: Etape) -> bool:
    if evenement.get("outil") != etape.outil:
        return False
    return etape.groupe is None or evenement.get("arguments", {}).get("groupe") == etape.groupe


def etapes_faites(session: Session) -> int:
    """Nombre d'étapes du plan réalisées avec succès, dans l'ordre (les appels en trop sont ignorés)."""
    faites = 0
    for evenement in _evenements_agent(session):
        if evenement.get("statut") == "ok" and faites < len(PLAN) and _correspond(evenement, PLAN[faites]):
            faites += 1
    return faites


def resultats_obtenus(session: Session) -> dict[str, dict]:
    """Résultats lus dans les SORTIES des outils (jamais dans la réponse du modèle)."""
    resultats: dict[str, dict] = {}
    groupe_courant = None
    for evenement in _evenements_agent(session):
        if evenement.get("statut") != "ok":
            continue
        if evenement["outil"] == "demarrer_laboratoire":
            groupe_courant = evenement["arguments"].get("groupe")
            resultats.setdefault(groupe_courant, {"groupe": groupe_courant})
        elif evenement["outil"] == "scan_tls_lab" and groupe_courant:
            acceptes = {ligne.split(" | ")[1] for ligne in evenement.get("sortie", "").splitlines() if ligne.startswith("algorithm | ")}
            resultats[groupe_courant]["scan_accepte"] = groupe_courant in acceptes
        elif evenement["outil"] == "mesurer_handshake":
            mesure = json.loads(evenement.get("sortie", "{}") or "{}")
            resultats.setdefault(evenement["arguments"]["groupe"], {"groupe": evenement["arguments"]["groupe"]}).update(
                mediane_us=mesure.get("mediane_us"), p95_us=mesure.get("p95_us"), client_hello_octets=mesure.get("client_hello_octets"))
    return resultats


def memoire(etat: EtatBoucle, session: Session) -> str:
    faites = etapes_faites(session)
    lignes = [f"Étapes faites : {faites} sur {len(PLAN)}."]
    if faites < len(PLAN):
        suivante = PLAN[faites]
        arguments = {"groupe": suivante.groupe} if suivante.groupe else {}
        if suivante.outil == "scan_tls_lab":
            arguments = {"cible": CIBLE, "groupe": suivante.groupe}
        if suivante.outil == "mesurer_handshake":
            arguments["mesures"] = 1000
        lignes.append(f"Étape suivante : {suivante.outil} avec {json.dumps(arguments, ensure_ascii=False)}")
    else:
        lignes.append("Toutes les étapes sont faites : réponds par le JSON final.")
    lignes.append("Résultats obtenus : " + json.dumps(list(resultats_obtenus(session).values()), ensure_ascii=False))
    return "\n".join(lignes)


def verifier_fin(etat: EtatBoucle, session: Session, sortie: BaseModel) -> str | None:
    faites = etapes_faites(session)
    if faites < len(PLAN):
        return f"il reste {len(PLAN) - faites} étape(s) du plan. Appelle l'outil indiqué par la mémoire de travail."
    attendus = resultats_obtenus(session)
    for ligne in sortie.resultats:
        reel = attendus.get(ligne.groupe)
        if reel is None:
            return f"le groupe {ligne.groupe} n'a pas été mesuré : résultats absents de la session"
        if ligne.scan_accepte != reel.get("scan_accepte") or ligne.mediane_us != reel.get("mediane_us") \
                or ligne.client_hello_octets != reel.get("client_hello_octets"):
            return f"les résultats de {ligne.groupe} ne reprennent pas ceux des outils : recopie exactement « Résultats obtenus »"
    if {r.groupe for r in sortie.resultats} != {HYBRIDE, CLASSIQUE}:
        return f"la réponse doit contenir exactement les groupes {HYBRIDE} et {CLASSIQUE}"
    return None


def configuration(max_etapes: int = 30, fenetre: int = 6) -> ConfigurationAgent:
    return ConfigurationAgent(
        nom=NOM, prompt=lire_prompt(NOM), sortie=SortieDemonstrateur, max_etapes=max_etapes, fenetre=fenetre,
        memoire=memoire, verifier_fin=verifier_fin, max_refus_de_fin=8,
        consigne="Mesure le coût du handshake TLS 1.3 hybride X25519MLKEM768 par rapport à X25519, sur le laboratoire local.",
    )


RESULTATS_RAW = Path("results/raw/demonstrateur_agent.json")


def bilan_execution(session: Session, modele_nom: str, arret: str, sortie: dict | None) -> dict:
    """Une ligne du bilan : compteurs lus dans le journal de l'agent, résultats dans la sortie validée."""
    fin = {}
    for ligne in (session.dossier / "journal_agents.jsonl").read_text(encoding="utf-8").splitlines():
        evenement = json.loads(ligne)
        if evenement.get("evenement") == "fin":
            fin = evenement
    return {
        "session": session.dossier.as_posix(), "modele": modele_nom, "arret": arret,
        "etapes": fin.get("etapes"), "appels_outils": fin.get("appels_outils"),
        "appels_refuses": fin.get("appels_refuses"), "appels_en_double": fin.get("appels_en_double"),
        "erreurs_outils": fin.get("erreurs_outils"), "duree_ms": fin.get("duree_ms"),
        "resultats": sortie["resultats"] if sortie else None,
    }


def ajouter_bilan(bilan: dict, fichier: Path = RESULTATS_RAW) -> None:
    """Ajoute une exécution au fichier de résultats versionné (une liste JSON)."""
    fichier.parent.mkdir(parents=True, exist_ok=True)
    existant = json.loads(fichier.read_text(encoding="utf-8")) if fichier.is_file() else []
    existant.append(bilan)
    fichier.write_text(json.dumps(existant, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    analyseur = argparse.ArgumentParser(description="Agent Démonstrateur : mesure le handshake hybride sur le laboratoire local.")
    analyseur.add_argument("--modele", default="ollama", choices=["ollama", "regles"])
    analyseur.add_argument("--session", default=None, help="dossier de trace (par défaut traces/demonstrateur_<modèle>)")
    options = analyseur.parse_args(argv)
    from quantum_ready.agents import politiques

    configuration_projet = yaml.safe_load(Path("config/experiment.yaml").read_text(encoding="utf-8"))
    if options.modele == "ollama":
        modele = depuis_configuration(configuration_projet)
    else:
        modele = ModeleSimule(politiques.demonstrateur, nom="regles")
    dossier = options.session or f"traces/demonstrateur_{options.modele}"
    session = Session(dossier, "si/generated/v1", "Laboratoire TLS")
    try:
        resultat = asyncio.run(lancer(configuration(**configuration_projet.get("agents", {}).get(NOM, {})), modele, session, transport="stdio"))
    finally:
        # Le laboratoire ne doit pas rester allumé si l'agent s'arrête en cours de route.
        for groupe in (HYBRIDE, CLASSIQUE):
            laboratoire.arreter(groupe)
    ajouter_bilan(bilan_execution(session, getattr(modele, "nom", options.modele), resultat.arret, resultat.sortie))
    print(json.dumps({"session": str(session.dossier), "arret": resultat.arret, "sortie": resultat.sortie}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
