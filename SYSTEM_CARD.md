# Fiche du système : Quantum-Ready

Fiche au sens des modèles de fiche de système (« model card » étendue) : ce que fait le
système, avec quels composants, dans quel cadre, avec quelles mesures et quelles limites.

## 1. Présentation

Quantum-Ready est un copilote multi-agents qui aide à planifier la migration post-quantique
d'un système d'information. Il inventorie la cryptographie d'un SI, la classe dans un CBOM
CycloneDX 1.6, mesure le risque selon l'inégalité de Mosca, propose un plan de migration, et
démontre sur un laboratoire local ce que coûtent les algorithmes cibles.

Le système ne modifie aucun SI. Toute proposition passe par une validation humaine.

## 2. Composants

| Composant | Nature | Rôle |
| --- | --- | --- |
| Outils déterministes (`src/quantum_ready/outils/`) | code | Analyse de certificats, clés, PKCS#12, configurations, code, dépendances. Calculs cryptographiques et scores. |
| Serveur d'outils MCP (`serveur_mcp/`) | code | Expose à chaque agent une liste fermée d'outils et journalise chaque appel. |
| Agents (`agents/`) | modèle + code | Inventoriste, Cartographe, Analyste de risque, Architecte, Démonstrateur. Le modèle choisit les appels et rédige ; le code vérifie. |
| Modèle de langage | composant externe | `qwen3:4b-instruct-2507-q4_K_M` via Ollama, en local, température 0, graine 42, contexte 4096. |
| Laboratoire TLS et SSH (`demonstrateur/`) | conteneurs | Serveurs TLS 1.3 et SSH locaux, certificats éphémères, sans donnée réelle. |
| Orchestrateur (`orchestrateur.py`) | graphe LangGraph | Enchaîne Inventoriste, Cartographe, Analyste, Architecte, puis validation humaine. Le Démonstrateur n'y est pas branché. |

## 3. Données

- **SI fictif** (`si/generated/v1`), généré par `make si`, jamais commité. Il contient 52 fichiers de configuration, de certificats et de code, et 73 actifs
  cryptographiques, dont 16 cachés (`data/ground_truth/verite_terrain_v1.csv`).
- **Aucune donnée réelle** : aucun système réel n'est analysé ni scanné. La sonde réseau
  (`scan_tls_lab`) ne contacte que le laboratoire local.
- **Secrets** : aucun secret réel dans le dépôt, les prompts ou les traces ; gitleaks tourne en CI.

## 4. Usage prévu

- Aider une équipe à établir un inventaire cryptographique, à le prioriser et à proposer une
  feuille de route de migration.
- Démontrer, sur un laboratoire local, le coût de l'échange hybride X25519MLKEM768, de la
  signature ML-DSA-65 et de SLH-DSA, par rapport aux algorithmes classiques.

## 5. Usages non prévus

- Analyser ou scanner un système réel sans que son propriétaire l'ait autorisé.
- Remplacer une validation humaine : le plan n'est jamais appliqué automatiquement.
- Décider seul d'une migration : les scores et les priorités sont des propositions argumentées.

## 6. Mesures

Les chiffres ci-dessous viennent de fichiers versionnés (`results/raw/`, `results/metrics.json`) ;
ils ne sont pas saisis à la main.

**Évaluation de l'inventaire** (exécution v5, `traces/20261104T213437Z_ollama`, qwen3:4b) :
rappel 100 % (visibles et cachés, dans chaque catégorie), précision stricte 0,936 (0,987 hors
doublons), F1 0,967 ; 78 actifs évalués sur 78, 7 actifs critiques.
Une seule exécution : pas encore de répétitions ni d'écart type pour cette évaluation.

**Latence du handshake TLS 1.3** (`bench_pqc`, 3 répétitions de 1000 mesures après 100
d'échauffement, sur un ordinateur portable, dans une VM Docker) :

| Échange | Certificat | Médiane (µs) | Message Certificate (octets) |
| --- | --- | --- | --- |
| X25519MLKEM768 | ECDSA P-256 | ≈ 924 | 407 |
| X25519 | ECDSA P-256 | ≈ 685 | 407 |
| X25519MLKEM768 | RSA-2048 | ≈ 1747 | 802 |
| X25519 | RSA-2048 | ≈ 1511 | 802 |
| X25519MLKEM768 | ML-DSA-65 | ≈ 1923 | 5531 |
| X25519 | ML-DSA-65 | ≈ 1760 | 5531 |
| X25519MLKEM768 | Chaîne ML-DSA-65 (2 certificats) | ≈ 2081 | 11114 |
| X25519 | Chaîne ML-DSA-65 (2 certificats) | ≈ 1700 | 11114 |

**Signatures** (`bench_signatures`, moyenne sur 3 répétitions de 100 mesures) : signature
ML-DSA-65 ≈ 1,07 ms, SLH-DSA-SHA2-128s ≈ 509 ms, SLH-DSA-SHA2-128f ≈ 24 ms ; tailles de
signature 3309, 7856 et 17088 octets.

**Agent Démonstrateur** : trois exécutions complètes avec le modèle local, huit appels d'outils
chacune, aucun appel refusé ni en double, aucune erreur d'outil.

## 7. Limites connues

- **Une seule évaluation de l'inventaire** : pas de répétitions ni d'écart type sur le rappel et
  la précision. Les seuils de critique sont un choix de méthode (« en danger de Mosca ET cassé
  par Shor »), argumenté mais pas validé sur un second SI.
- **Un seul SI d'évaluation** : aucune variante non vue pendant le développement n'a encore été
  produite ; la robustesse à un SI nouveau n'est pas mesurée.
- **Un seul modèle** : les résultats sont ceux d'un modèle de 4 milliards de paramètres. Une
  comparaison avec un second modèle est prévue mais pas faite.
- **Temps mesurés sur une seule machine** : les valeurs de latence varient d'environ 20 % d'une
  exécution à l'autre ; elles ne valent pas comme constantes.
- **Laboratoire** : les mesures sont faites en boucle locale, sans latence réseau ni charge.
  Le certificat du laboratoire est auto-signé ou issu d'une chaîne de test.
- **Sécurité du système multi-agents** : les garde-fous existent (listes fermées, vérifications
  de fin, journal), mais l'analyse de menace STRIDE et les tests d'injection de consignes
  piégées ne sont pas encore écrits.
- **Modèle de langage** : il peut écrire un résumé inexact. Les défauts connus sont listés dans
  `CLAUDE.md` et dans `docs/journal_des_prompts.md`.

## 8. Supervision et contrôle

- Chaque appel d'outil, chaque refus et chaque arrêt est journalisé (`journal_outils.jsonl`,
  `journal_agents.jsonl`).
- Une session se rejoue et se vérifie avec `make rejeu SESSION=…` : les appels d'outils purs
  sont rejoués sur le même SI et comparés aux sorties enregistrées.
- Le laboratoire est arrêté à la fin de chaque exécution, même en cas d'échec.
