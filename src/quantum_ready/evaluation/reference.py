"""Référence d'ablation « outils seuls, sans agent » : chaque fichier passe dans l'outil conseillé.

C'est la borne que les agents doivent dépasser ou justifier : sans modèle de
langage, aucun lien entre fichiers n'est fait (par exemple, le PKCS#12 reste fermé).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from quantum_ready.outils import (
    analyser_cle, analyser_configuration, analyser_dependances, analyser_pkcs12, analyser_x509, lister_fichiers,
    rechercher_algorithmes, scanner_code_crypto,
)
from quantum_ready.outils.commun import Trouvaille
from quantum_ready.outils.construire_cbom import construire_cbom
from quantum_ready.serveur_mcp.session import Session, ecrire_json

OUTILS = {
    "analyser_x509": analyser_x509.analyser_x509, "analyser_cle": analyser_cle.analyser_cle, "analyser_pkcs12": analyser_pkcs12.analyser_pkcs12,
    "analyser_configuration": analyser_configuration.analyser_configuration, "scanner_code_crypto": scanner_code_crypto.scanner_code_crypto,
    "analyser_dependances": analyser_dependances.analyser_dependances, "rechercher_algorithmes": rechercher_algorithmes.rechercher_algorithmes,
}


def executer(racine: str, dossier: str) -> Session:
    session = Session(dossier, racine, f"SI fictif ({Path(racine).name})")
    dossiers_de_dependances = set()
    for fichier in lister_fichiers.lister_fichiers(".", racine=racine).fichiers:
        outil = fichier.outil_conseille
        if not outil:
            continue
        if outil == "analyser_dependances":
            dossier_projet = str(Path(fichier.chemin).parent)
            if dossier_projet in dossiers_de_dependances:
                continue
            dossiers_de_dependances.add(dossier_projet)
        resultat = OUTILS[outil](fichier.chemin, racine=racine)
        identifiants = session.enregistrer(resultat.trouvailles, "outils_seuls")
        session.journaliser("journal_outils.jsonl", {"agent": "outils_seuls", "outil": outil, "arguments": {"cible": fichier.chemin},
                                                     "statut": "erreur" if resultat.erreurs else "ok", "duree_ms": 0, "trouvailles": identifiants})
    retenues = [Trouvaille.model_validate(e["trouvaille"]) for e in session.trouvailles()]
    ecrire_json(session.fichier_cbom, construire_cbom(retenues, session.nom_systeme).cbom)
    return session


def main(argv: list[str] | None = None) -> None:
    analyseur = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    analyseur.add_argument("--racine", default="si/generated/v1")
    analyseur.add_argument("--session", default="traces/reference_outils_seuls")
    options = analyseur.parse_args(argv)
    print(executer(options.racine, options.session).dossier)


if __name__ == "__main__":
    main()
