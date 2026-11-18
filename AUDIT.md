# Procédure d'audit : vérifier les résultats de Quantum-Ready

Ce document permet à un tiers de vérifier les résultats publiés, sans les croire sur parole.
Chaque étape donne la commande, la valeur attendue et la tolérance.

**Ordre conseillé** : commencer par la section 10 (signature et empreintes), sur un clone neuf
ou l'archive Zenodo, avant toute commande qui régénère ou ajoute des fichiers ; puis les sections
1 à 3 (sans Docker ni modèle, environ 5 minutes) ; enfin les sections 4 à 7 (Docker) et 11.

**Règle des tolérances**
- **Exacte** : comptes, tailles en octets des algorithmes à longueur fixe (clés publiques,
  signatures ML-DSA et SLH-DSA), identifiants, résultats de vérification. Un écart est une erreur.
- **± 2 octets** : tailles des certificats générés à chaque démarrage (ECDSA).
- **Deux écarts types** : temps mesurés. La valeur obtenue doit tomber dans
  `moyenne ± 2 × écart type` des valeurs versionnées dans `results/raw/`. Au-delà, l'écart est à
  signaler, pas à corriger en silence.

## 0. Prérequis

| Sections | Il faut |
|---|---|
| 1, 2, 3, 8 | macOS, Linux ou Windows ; `git`, `uv`, OpenSSL 3 (vérifié au démarrage de la reproduction), `ssh-keygen` |
| 4, 5, 7, 11 | Docker (Docker Desktop sous macOS et Windows) |
| nouvelles exécutions d'agents | Ollama et le modèle `qwen3:4b-instruct-2507-q4_K_M` (`make installer-modele` ; empreinte attendue `0edcdef34593`) |
| 10 | `minisign` |

Sous Windows, `make` n'est pas requis : chaque cible a son équivalent `uv run` (README).
Aucune section ne demande de GPU ; les sections 1 à 3 et 8 n'utilisent pas le modèle de langage :
elles vérifient les traces publiées.

## 1. Environnement

```bash
git clone https://github.com/oscarnoblesse/quantum-analyst-ai.git && cd quantum-analyst-ai
uv run python scripts/reproduire.py
```

- **Attendu** : toutes les étapes réussissent et le script se termine par
  `Reproduction terminée avec succès` (environ 70 à 120 s).
- **Attendu (exact)** : 545 tests, aucun échec. Une seule ignorance est admise (comparaison DSA
  refusée par un `ssh-keygen` récent) : 545 réussis sans ignorance, ou 544 réussis et 1 ignoré.
- **Attendu** : couverture ≥ 70 % (seuil exigé, contrôlé par pytest) ; valeur mesurée sous Linux :
  92,67 %. Un écart de quelques dixièmes selon le système est normal (branches propres à Windows).
- La CI refait cette étape sous Ubuntu, macOS et Windows à chaque modification (job
  `Reproduction`).

## 2. Vérité terrain et SI fictif

```bash
make si && make verifier-si
```

- **Attendu (exact)** : `SI v1 généré dans si/generated/v1 : 52 fichiers` ; 73 actifs attendus,
  dont 16 cachés (`data/ground_truth/verite_terrain_v1.csv`) ; `verifier-si` affiche
  `73/73 actifs conformes, 0 fichier(s) en trop`.
- Les secrets, clés et mots de passe du SI sont tirés au hasard à chaque génération : les octets
  diffèrent d'une machine à l'autre, pas les actifs ni leur classement.

## 3. Inventaire multi-agents (évaluation)

Le modèle est non déterministe d'une machine à l'autre (température 0 et graine 42, mais calcul
flottant) : cette étape se vérifie sur les traces publiées, par rejeu des appels d'outils et par
évaluation, pas en relançant le modèle. Les traces sont dans `traces/` (CC BY 4.0) et couvertes
par `SHA256SUMS` (section 10) ; de nouvelles traces se produisent avec `make agents`.

**Rejeu des appels d'outils** (`make rejeu SESSION=traces/mesure_v6_run1`, sessions de référence :
`mesure_v6_run1` à `run3` et `test_windows_20261117`) :
- **Attendu (exact)** : `60 identique(s) sur 84 appel(s) enregistré(s)` ; 23 appels non rejoués
  (outils qui lisent l'état de la session : `score_mosca`, `lister_trouvailles`,
  `construire_cbom`, `valider_schema`, `lister_priorites`).
- **Écart admis, un seul** : `DIFFÉRENT : inventoriste / analyser_configuration` sur
  `nginx/nginx.conf`, si l'OpenSSL de l'auditeur n'est pas de la même branche que celui des
  mesures. L'outil développe la macro `HIGH:!aNULL:!MD5` avec l'OpenSSL de la machine : il trouve
  14 suites à échange de clés RSA avec OpenSSL 3.5 (mesures publiées, `results/ENVIRONMENT.json`)
  et 16 avec OpenSSL 3.0 (Ubuntu 24.04, image Docker). L'actif (QR-015) est trouvé dans les deux
  cas ; seul le nombre de suites du libellé change. `make rejeu` rend alors un code d'erreur : lire
  la ligne `DIFFÉRENT`, qui doit être celle-ci et aucune autre.
- **Sessions antérieures à la v6** (par exemple la v5, `20261104T213437Z_ollama`) : 47 appels
  identiques sur 51 rejoués. Les 4 écarts sont attendus : 3 messages d'erreur enrichis depuis
  (« Fichiers du SI au nom proche »), plus l'écart OpenSSL ci-dessus. Aucune trouvaille ne change.

**Évaluation** (`make evaluer SESSIONS="traces/<session>"`, exact à la quatrième décimale) :

| Session | Rappel | Rappel cachés | Préc. stricte | Préc. hors doublons | F1 | Composants / appariés / doublons / en trop | Shor bien classés | Plan |
|---|---|---|---|---|---|---|---|---|
| `mesure_v6_run1`, `run2`, `run3` (macOS) | 1,0 | 1,0 | 0,9241 | 0,9733 | 0,9605 | 79 / 73 / 4 / 2 | 42/43 | conforme |
| `test_windows_20261117`, `scan_develop_98ce8af` (Windows) | 1,0 | 1,0 | 0,9241 | 0,9865 | 0,9605 | 79 / 73 / 5 / 1 | 42/43 | conforme |
| `20261104T213437Z_ollama` (v5) | 1,0 | 1,0 | 0,9359 | 0,9865 | 0,9669 | 78 / 73 / 4 / 1 | 42/43 | conforme |
| `reference_outils_seuls` (sans modèle) | 0,9863 | 1,0 | 0,9351 | 0,9863 | 0,9600 | 77 / 72 / 4 / 1 | 41/43 | — |

- Les CBOM de toutes ces sessions sont valides (CycloneDX 1.6). Les valeurs arrondies des autres
  documents (0,936, 0,967, 0,961) viennent de ce tableau.
- `ci_petit_modele` et `petit_test` (qwen3:0.6b) : **attendu** `aucun cbom.json dans la session`.
  C'est un résultat de l'ablation, pas une erreur de l'auditeur.
- La figure `results/figures/evolution_inventaire.svg` se régénère depuis les traces, sans valeur
  saisie à la main : `uv run --with matplotlib python scripts/figure_evolution_inventaire.py`.
- `make evaluer` écrit un `evaluation.json` dans chaque session évaluée : ces fichiers apparaissent
  ensuite comme « non listés » à la section 10 (avertissement, pas une erreur).

## 4. Démonstrateur : vérification du laboratoire

```bash
make demonstrateur
```

- **Attendu (exact)** : groupe négocié `X25519MLKEM768` ; client X25519 seul refusé ; échange SSH
  négocié `mlkem768x25519-sha256` ; client classique SSH refusé. Le fichier
  `results/raw/demonstrateur_verification.json` contient `"conforme": true`.

## 5. Latence du handshake

```bash
uv run python scripts/bench_pqc.py
```

- **Attendu (exact)** : tailles des messages `Certificate` : 802 o (RSA-2048), 5531 o (ML-DSA-65),
  11114 o (chaîne ML-DSA-65). Groupes négociés conformes.
- **Attendu (± 2 octets)** : 406 o pour ECDSA P-256. Le certificat est généré à chaque démarrage, et la
  longueur de sa signature DER varie d'une clé à l'autre : un écart d'un ou deux octets est normal.
- **Attendu (deux écarts types)** : médianes par configuration dans `moyenne ± 2 × écart type`
  de `results/raw/bench_pqc.json`. Par exemple, hybride ECDSA : 924 µs, écart type 0,4 µs
  (fenêtre étroite) ; chaîne ML-DSA hybride : 2081 µs, écart type 358 µs (fenêtre large, la
  configuration est bruitée).

## 6. Signatures post-quantiques

```bash
uv run python scripts/bench_signatures.py
```

- **Attendu (exact, normes FIPS 204 et FIPS 205)** : ML-DSA-65 : clé publique 1952 o, signature
  3309 o ; SLH-DSA-SHA2-128s : clé publique 32 o, signature 7856 o ; SLH-DSA-SHA2-128f : signature
  17088 o.
- **Attendu (deux écarts types)** : temps de signature et de vérification.

## 7. Agent Démonstrateur

```bash
make demonstrateur-agent
```

- **Attendu** : arrêt `termine`, huit appels d'outils, aucun appel refusé ni en double, laboratoire
  arrêté à la fin (`docker ps` ne montre aucun conteneur `qr-lab-*`).
- **Attendu (deux écarts types)** : médianes rapportées par l'agent, comparées à
  `results/raw/demonstrateur_agent.json`.
- **Attendu (exact)** : la réponse finale reprend à l'identique les résultats des outils. Le code
  le vérifie et refuse une réponse qui ne le fait pas.

## 8. Métriques

```bash
make metriques
```

- **Attendu (exact)** : `results/metrics.json` identique à celui versionné, à l'exception du champ
  `genere_le` ; figures `latence.svg` et `signatures.svg` identiques.
- **Attendu** : `results/ENVIRONMENT.json` décrit la machine de l'auditeur (système, versions
  d'OpenSSL, de Python, de Docker) : il diffère de celui des mesures, c'est son rôle. Comparer
  plutôt `configuration_sha256` et l'empreinte du modèle, qui doivent être identiques.
- **Attendu** : la liste `non_mesure` est présente ; elle n'est jamais vide tant que le sujet n'est
  pas entièrement couvert.

## 9. Sécurité du dépôt

- **Attendu** : gitleaks ne signale aucun secret (CI, job `secrets`) ; aucun fichier du SI fictif
  et aucune clé privée n'est versionné. Les traces publiées (`traces/`) ont été relues : aucun
  secret réel ni aucune donnée personnelle ; gitleaks les analyse comme le reste du dépôt.

## 10. Intégrité et authenticité des résultats

À faire **en premier**, sur un clone neuf ou l'archive Zenodo, avant toute commande qui régénère
des résultats (`make metriques` réécrit `results/metrics.json` et `results/ENVIRONMENT.json`).

`SHA256SUMS` liste l'empreinte SHA-256 de chaque artefact publié : `results/`, `traces/` et
`data/ground_truth/`. `SHA256SUMS.minisig` est sa signature [minisign](https://jedisct1.github.io/minisign/)
(Ed25519), faite par l'auteur au moment de la release ; `cle_publique_minisign.pub` est la clé
publique correspondante. Installer minisign : `brew install minisign` (macOS),
`winget install jedisct1.minisign` (Windows), `apt install minisign` (Debian, Ubuntu).

```bash
minisign -V -p cle_publique_minisign.pub -m SHA256SUMS   # authenticité de SHA256SUMS
uv run python -m quantum_ready.integrite verifier         # intégrité de chaque artefact
# ou, en une commande : make verifier-signature
# sous Linux, la seconde vérification peut aussi se faire avec : sha256sum -c SHA256SUMS
```

- **Attendu (exact)** : `Signature and comment signature verified`, avec le commentaire de
  confiance `Quantum-Ready v1.0.0 - SHA256SUMS des artefacts publies`.
- **Attendu (exact)** : l'identifiant de la clé publique (`minisign public key <ID>`, première ligne
  de `cle_publique_minisign.pub`) est celui indiqué sur la fiche de dépôt.
- **Attendu (exact)** : `0 différents, 0 manquants`. Des fichiers « non listés » ne sont qu'un
  avertissement : ils apparaissent si l'auditeur a déjà relancé une évaluation (`evaluation.json`).
- La CI (job `integrite`) refait ces deux vérifications à chaque modification.

Limite assumée : la signature est classique (Ed25519), donc exposée à un futur ordinateur
quantique (Shor), comme les actifs que le projet inventorie. Elle protège l'archive aujourd'hui ;
une signature post-quantique (ML-DSA) n'est pas encore disponible dans minisign.

## 11. Image Docker de reproduction

```bash
docker build -t quantum-ready .
docker run --rm quantum-ready
```

- **Attendu** : la même sortie que la section 1 (l'image exécute `make reproduce` sous un
  utilisateur non privilégié, avec OpenSSL 3.0 de Debian 12). La CI construit et lance l'image
  à chaque modification (job `image-docker`).

## Écarts connus

- **Variante 2 du SI** : pas encore produite. La performance sur un SI non vu n'est pas mesurée.
- **Ablation** : faite pour « outils seuls, sans modèle » (F1 0,9600 contre 0,9605 avec qwen3 4B :
  le modèle n'apporte qu'un actif, QR-020) et pour un très petit modèle (qwen3:0.6b : aucun CBOM
  produit). Pas encore faite avec un second modèle de taille comparable.
- **Répétitions de l'évaluation d'inventaire** : trois exécutions v6 sur la même machine (macOS),
  identiques sur toutes les mesures de qualité (écart type nul) ; seules les durées varient
  (1 807 à 4 064 s). Sur Windows, deux exécutions donnent le même rappel et le même F1 mais un
  chemin différent (5 doublons et 1 composant en trop au lieu de 4 et 2) : à température 0, la
  sortie du modèle reste propre à la machine.
- **`results/metrics.json`** ne reprend pas encore les mesures d'inventaire : la liste
  `non_mesure` le déclare (rappel et précision par catégorie, validité du CBOM sur 3 répétitions).
  Les valeurs se recalculent depuis les traces (section 3).
- **QR-049** (`clients/admin/admin.key`, clé ECDSA P-256 chiffrée par phrase de passe) : classée
  d'exposition « inconnue » faute de pouvoir lire la clé, d'où 42/43 actifs Shor bien classés.
- **Rejeu dépendant d'OpenSSL** : voir section 3 (14 ou 16 suites RSA selon la branche d'OpenSSL).
