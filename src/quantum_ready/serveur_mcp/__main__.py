"""Lance le serveur MCP d'un agent sur stdio.

    python -m quantum_ready.serveur_mcp --agent inventoriste --session traces/essai --racine si/generated/v1

Le client MCP (l'agent) lance ce processus et dialogue avec lui en JSON-RPC sur
l'entrée et la sortie standard.
"""

import argparse

from quantum_ready.serveur_mcp.serveur import creer_serveur
from quantum_ready.serveur_mcp.session import Session


def main(argv: list[str] | None = None) -> None:
    analyseur = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    analyseur.add_argument("--agent", required=True)
    analyseur.add_argument("--session", required=True, help="dossier de session (état partagé et journaux)")
    analyseur.add_argument("--racine", required=True, help="racine du SI fictif analysé")
    analyseur.add_argument("--horizon", type=float, default=10, help="z de Mosca, en années")
    analyseur.add_argument("--nom-systeme", default="SI fictif")
    options = analyseur.parse_args(argv)
    session = Session(options.session, options.racine, options.nom_systeme)
    creer_serveur(options.agent, session, options.horizon).run("stdio")


if __name__ == "__main__":
    main()
