# Usage de l'IA générative dans le projet Quantum-Ready

Ce document déclare ce qui a été produit avec un outil d'IA générative, dans quel cadre et
avec quels contrôles, conformément à l'annexe A du sujet. L'auteur reste responsable de
l'intégralité du contenu déposé. Il complète la section 14 du rapport technique
(`docs/rapport.pdf`).

## Outils d'IA utilisés

| Outil | Rôle dans le projet |
| --- | --- |
| **Claude** (Anthropic), via Claude Code et l'application Claude | Assistant de développement et de rédaction : code, tests, scripts, documentation, premier jet du rapport, toujours à la demande et sous la direction de l'auteur. |
| **qwen3:4b-instruct-2507-q4_K_M** (Ollama, en local, empreinte `0edcdef34593`) | **Composant du système évalué** : modèle de langage qui fait fonctionner les agents. Ce n'est pas un outil de développement. |
| **qwen3:0.6b** (Ollama, en local) | Composant évalué lui aussi : très petit modèle de la chaîne de reproduction en intégration continue et de l'ablation. |

## Pourquoi l'IA a été utilisée

Le projet a été mené en parallèle des cours et d'une alternance en entreprise. L'auteur a
choisi de déléguer à un assistant l'écriture d'une grande partie du code et du SI fictif,
qu'il aurait pu écrire lui-même mais pas dans les délais impartis, pour consacrer son temps
aux décisions de méthode, aux expériences et surtout à la vérification de ce qui était
produit.

## Ce qui a été écrit avec l'assistant

- **Agents, boucle d'agent et orchestrateur** (`src/quantum_ready/agents/`,
  `src/quantum_ready/orchestrateur.py`), serveur MCP et outils déterministes d'inventaire
  (`src/quantum_ready/serveur_mcp/`, `src/quantum_ready/outils/`), à partir des
  spécifications et des décisions de l'auteur.
- **Prompts des agents** (`src/quantum_ready/prompts/`) ; chaque version est consignée avec
  son effet mesuré dans `docs/journal_des_prompts.md`.
- **Générateur du SI d'évaluation v2** (`src/quantum_ready/si_fictif/v2/`), sa vérité terrain,
  ses leurres et son CBOM attendu, à partir d'une liste d'actifs proposée par l'assistant
  puis modifiée et validée par l'auteur.
- **Évaluation et métriques** (`src/quantum_ready/evaluation/`), page de résultats, rejeu.
- **Démonstrateur** : conteneurs du laboratoire TLS et SSH, mesures `bench_pqc` et
  `bench_signatures`, scripts de vérification.
- **Tests** (`tests/`), **scripts de reproduction** (`scripts/`, `Makefile`, `Dockerfile`,
  intégration continue).
- **Documentation** : `README.md`, `SYSTEM_CARD.md`, `AUDIT.md`, documents de `docs/`.
- **Rapport technique** : premier jet de la partie technique par l'assistant ; les
  paragraphes d'analyse partent des réponses écrites par l'auteur, reformulées à sa demande
  pour un registre scientifique, sans en changer le sens sauf erreur factuelle signalée.

Les commits produits avec l'assistant portent la mention `Co-Authored-By: Claude`.

## Ce qui a été fait par l'auteur

- **Le module `src/quantum_ready/si_fictif/pki.py`** (PKI du SI v1) et **la vérité terrain du
  SI v1** (`data/ground_truth/verite_terrain_v1.csv`), dont le choix des actifs cachés.
- **Les décisions de méthode** : définition de la priorité « critique » (Shor et en danger de
  Mosca), grille de crypto-agilité, vérification du plan au laboratoire, budget de
  l'expérience a posteriori. Elles sont consignées dans `docs/decisions_methode.md` et
  `docs/evaluation_v2.md`.
- **La validation de la liste des actifs du SI v2**, dont le refus de reprendre les
  cachettes du SI v1.
- **L'exécution de toutes les expériences** sur sa machine, leur lecture et l'écriture de ses
  prédictions avant chaque mesure.
- **La vérification manuelle** de ce qui a été produit : fonctionnement du code, CBOM obtenus,
  traces des agents, résultats annoncés. Cette vérification a représenté la part la plus
  importante du temps consacré au projet.

## Contrôles mis en place

- Le modèle de langage du système ne fait aucun calcul cryptographique : les opérations sont
  faites par des outils déterministes (OpenSSL, analyseurs, `bench_pqc`) et vérifiées par du
  code.
- Les réponses finales des agents sont revalidées par le code (schéma, cohérence avec les
  résultats des outils, conformité du plan) ; une réponse non conforme est refusée.
- Le code produit avec l'assistant est couvert par des tests automatisés (seuil de couverture
  de 70 % vérifié en intégration continue), et la reproduction est vérifiée sous macOS, Linux
  et Windows ainsi que dans une image Docker.
- Chaque fusion dans `develop` a suivi une intégration continue verte (tests, reproduction,
  gitleaks).
- Aucun secret ni aucune clé réelle n'a été transmis à l'assistant ; le SI est fictif et ses
  secrets sont générés localement.

## Limites de cette déclaration

- La relecture de l'auteur a porté sur le fonctionnement et les résultats ; elle n'a pas
  consisté en une relecture ligne à ligne de chaque modification.
- Le SI v2 a été conçu par le même assistant que les outils qu'il sert à évaluer ; ce biais
  est discuté dans `docs/evaluation_v2.md` et dans le rapport.
