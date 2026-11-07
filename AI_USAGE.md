# Usage de l'IA dans le projet Quantum-Ready

Ce document déclare ce qui a été produit avec l'aide d'un outil d'IA, et dans quel cadre.
Il est rédigé par l'auteur du projet, à partir de l'historique du dépôt.

## Outils d'IA utilisés

| Outil | Rôle dans le projet |
| --- | --- |
| **Claude** (Anthropic), via Claude Code | Assistant de développement : écriture de code, de tests, de scripts et de documentation, sous la direction de l'auteur. |
| **qwen3:4b-instruct-2507-q4_K_M** (via Ollama, en local) | **Composant du système évalué** : modèle de langage qui fait fonctionner les agents (Inventoriste, Cartographe, Analyste de risque, Architecte, Démonstrateur). Ce n'est pas un outil de développement. |

## Ce qui a été écrit avec Claude

- **Code des agents et de leur boucle** (`src/quantum_ready/agents/`), du serveur d'outils MCP et des outils déterministes, à partir des spécifications et des décisions de l'auteur.
- **Prompts des agents** (`src/quantum_ready/prompts/`). Chaque version est enregistrée avec son effet mesuré dans `docs/journal_des_prompts.md`.
- **Tests** (`tests/`).
- **Démonstrateur** : conteneurs du laboratoire TLS et SSH, programme de mesure `bench_pqc.c`, mesure des signatures `bench_signatures.c`, scripts de vérification et de mesure, outil de rejeu.
- **Documentation technique** et scripts de reproduction (`scripts/`, `README.md`, `docs/`).

Les décisions de méthode n'ont pas été prises par l'IA : seuils, critères de « critique », horizon de la menace, protocole de mesure, choix des configurations comparées. Elles ont été proposées puis tranchées par l'auteur, et notées dans `CLAUDE.md` et `docs/`.

## Ce qui n'a PAS été écrit avec l'IA

- **Le générateur du SI fictif, module `src/quantum_ready/si_fictif/pki.py`** : écrit entièrement par l'auteur. Il n'a pas été régénéré ni réécrit par un outil d'IA.
- **La vérité terrain** (`data/ground_truth/verite_terrain_v1.csv`) : établie par l'auteur à partir de la conception du SI fictif.
- **Les conclusions du rapport technique** : rédigées par l'auteur.

## Contrôles mis en place

- Le modèle de langage ne fait aucun calcul cryptographique : les opérations sont faites par des outils déterministes (OpenSSL, `bench_pqc`, analyseurs) et vérifiées par du code.
- Les réponses finales des agents sont revalidées par le code (schéma, cohérence avec les résultats des outils) ; un chiffre inventé par le modèle est refusé.
- Le code généré avec l'IA est couvert par des tests automatisés (`make test`), et la reproduction est vérifiée sur macOS, Linux et Windows par la CI.
- Chaque fusion dans `develop` a suivi une CI verte (tests, reproduction sur trois systèmes, gitleaks). La relecture humaine ligne à ligne de chaque diff n'est pas attestée ici : à confirmer par l'auteur.

## À confirmer par l'auteur

- [ ] Liste complète des fichiers écrits avec l'IA, à partir de `git log` (les commits ne portent pas de mention d'IA ; cette liste est à compléter).
- [ ] Niveau de relecture effectivement fait sur chaque module (le rapport doit le préciser).
