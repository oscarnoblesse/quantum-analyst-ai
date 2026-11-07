"""Rejeu et affichage d'une session (sujet §6.8).

    uv run python -m quantum_ready.rejeu traces/<session> [--racine si/generated/v1]

1. Affiche le bilan de chaque agent (arrêt, étapes, appels, refus, doublons, erreurs).
2. Rejoue les appels d'outils PURS sur le SI, dans une copie de la session, et compare
   chaque sortie à celle qui a été enregistrée. Un écart fait échouer la commande.

Ne sont pas rejoués : les outils qui lisent l'état de la session (leur sortie dépend de ce qui
a été fait avant), les outils de laboratoire (non déterministes) et les appels dont les
arguments ne peuvent pas être reconstitués. Ils sont listés, jamais comptés comme identiques.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

from quantum_ready.serveur_mcp.outils_exposes import creer_outils
from quantum_ready.serveur_mcp.session import Session

JOURNAL_OUTILS = "journal_outils.jsonl"
# Identifiants de trouvailles (T0001, T0002...) attribués par compteur dans la session : ils dépendent de
# l'ordre de TOUS les appels de la session, donc pas du contenu d'un appel. Ils sont ignorés à la comparaison.
IDENTIFIANT = re.compile(r"\bT\d{4}\b")


def _contenu(sortie: str | None) -> str:
    return IDENTIFIANT.sub("T----", sortie or "")
JOURNAL_AGENTS = "journal_agents.jsonl"
OUTILS_PURS = {
    "lister_fichiers", "analyser_x509", "analyser_cle", "analyser_pkcs12", "analyser_configuration",
    "scanner_code_crypto", "analyser_dependances", "rechercher_algorithmes", "rechercher_standard",
}


def bilan_agents(session: Session) -> list[dict]:
    """Une ligne par exécution d'agent, tirée de l'événement « fin » de son journal."""
    lignes = []
    for evenement in session.evenements(JOURNAL_AGENTS):
        if evenement.get("evenement") == "fin":
            lignes.append({k: evenement.get(k) for k in ("agent", "arret", "etapes", "appels_outils", "appels_refuses",
                                                       "appels_en_double", "erreurs_outils", "duree_ms")})
    return lignes


def rejouer(dossier: Path, racine: Path) -> dict:
    """Rejoue les appels purs dans une copie du dossier ; ne touche jamais à la session d'origine."""
    copie = Path(tempfile.mkdtemp(prefix="rejeu_"))
    try:
        shutil.copytree(dossier, copie / "session")
        session = Session(copie / "session", racine)
        outils_par_agent: dict[str, dict] = {}
        resultats = []
        for evenement in session.evenements(JOURNAL_OUTILS):
            nom, agent = evenement.get("outil"), evenement.get("agent")
            if evenement.get("statut") not in ("ok", "erreur"):
                continue
            if nom not in OUTILS_PURS:
                resultats.append({"outil": nom, "agent": agent, "etat": "non rejoué (dépend de l'état de la session ou non déterministe)"})
                continue
            outils = outils_par_agent.setdefault(agent, creer_outils(session, agent))
            try:
                sortie = outils[nom](**evenement.get("arguments", {}))
            except Exception as erreur:  # un appel qu'on ne peut pas rejouer est signalé, pas ignoré
                resultats.append({"outil": nom, "agent": agent, "etat": f"impossible à rejouer : {type(erreur).__name__}"})
                continue
            identique = _contenu(sortie) == _contenu(evenement.get("sortie"))
            resultats.append({"outil": nom, "agent": agent, "etat": "identique" if identique else "DIFFERENT"})
        return {
            "appels": len(resultats),
            "identiques": sum(r["etat"] == "identique" for r in resultats),
            "differents": [r for r in resultats if r["etat"] == "DIFFERENT"],
            "non_rejoues": [r for r in resultats if r["etat"].startswith(("non rejoué", "impossible"))],
        }
    finally:
        shutil.rmtree(copie, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    analyseur = argparse.ArgumentParser(description="Affiche une session et rejoue ses appels d'outils purs.")
    analyseur.add_argument("dossier", type=Path)
    analyseur.add_argument("--racine", type=Path, default=Path("si/generated/v1"))
    options = analyseur.parse_args(argv)
    if not (options.dossier / JOURNAL_OUTILS).is_file():
        print(f"Pas de journal d'outils dans {options.dossier}", file=sys.stderr)
        return 2

    session = Session(options.dossier, options.racine)
    print(f"Session {options.dossier}")
    for ligne in bilan_agents(session):
        print(f"  {ligne['agent']:<16} arrêt={ligne['arret']:<16} étapes={ligne['etapes']} appels={ligne['appels_outils']} "
              f"refusés={ligne['appels_refuses']} doubles={ligne['appels_en_double']} erreurs={ligne['erreurs_outils']}")

    rapport = rejouer(options.dossier, options.racine)
    print(f"\nRejeu des appels purs : {rapport['identiques']} identique(s) sur {rapport['appels']} appel(s) enregistré(s)")
    groupes: dict[tuple[str, str, str], int] = {}
    for r in rapport["non_rejoues"]:
        cle = (r["agent"], r["outil"], r["etat"])
        groupes[cle] = groupes.get(cle, 0) + 1
    for (agent, outil, etat), n in sorted(groupes.items()):
        print(f"  non rejoué ×{n} : {agent} / {outil} : {etat}")
    for r in rapport["differents"]:
        print(f"  DIFFÉRENT : {r['agent']} / {r['outil']}", file=sys.stderr)
    return 1 if rapport["differents"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
