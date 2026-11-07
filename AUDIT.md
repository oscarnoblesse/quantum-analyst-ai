# Procédure d'audit : vérifier les résultats de Quantum-Ready

Ce document permet à un tiers de vérifier les résultats publiés, sans les croire sur parole.
Chaque étape donne la commande, la valeur attendue et la tolérance.

**Règle des tolérances**
- **Exacte** : comptes, tailles en octets des algorithmes à longueur fixe (clés publiques,
  signatures ML-DSA et SLH-DSA), identifiants, résultats de vérification. Un écart est une erreur.
- **± 2 octets** : tailles des certificats générés à chaque démarrage (ECDSA).
- **Deux écarts types** : temps mesurés. La valeur obtenue doit tomber dans
  `moyenne ± 2 × écart type` des valeurs versionnées dans `results/raw/`. Au-delà, l'écart est à
  signaler, pas à corriger en silence.

## 0. Prérequis

- macOS, Linux ou Windows, avec `git`, `uv` et Docker (Docker Desktop sous macOS et Windows).
- Pour les étapes d'agent : Ollama et le modèle `qwen3:4b-instruct-2507-q4_K_M`
  (`make installer-modele` ; empreinte attendue `0edcdef34593`).

## 1. Environnement

```bash
git clone https://github.com/oscarnoblesse/quantum-analyst-ai.git && cd quantum-analyst-ai
uv run python scripts/reproduire.py
```

- **Attendu** : toutes les étapes réussissent ; couverture ≥ 70 % (exact : seuil atteint).
- **Attendu** : `make test` ne donne aucun échec ; le nombre de tests réussis est au moins 473
  (exact sur la version archivée) et une seule ignorance est admise (comparaison DSA refusée par
  `ssh-keygen` récent).

## 2. Vérité terrain et SI fictif

```bash
make si && make verifier-si
```

- **Attendu (exact)** : 52 fichiers dans `si/generated/v1` ; 73 actifs attendus, 16 cachés
  (`data/ground_truth/verite_terrain_v1.csv`) ; `verifier-si` ne signale aucun écart.

## 3. Inventaire multi-agents (évaluation)

Le modèle est non déterministe en pratique (température 0 mais calcul flottant) : cette étape se
vérifie par rejeu des appels d'outils, pas par répétition du modèle.

```bash
make rejeu SESSION=traces/<session>
```

- **Attendu (exact)** : aucun appel d'outil pur `DIFFÉRENT`. Les appels non rejoués sont listés
  (outils qui lisent l'état de la session, laboratoire).
- **Attendu** : sur la session v5, 51 appels identiques sur 75 enregistrés, aucun écart.
- Les traces ne sont pas versionnées dans le dépôt : elles sont à reproduire (`make agents`) ou à
  demander à l'auteur.

**Évaluation** (`make evaluer SESSIONS="traces/<session>"`) :
- **Attendu, exécution v5** : rappel 1,0 ; précision stricte 0,9359 ; F1 0,9669 (valeurs
  arrondies à 0,936 et 0,967 dans les autres documents). Exact à la quatrième décimale.

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
  `genere_le`.
- **Attendu** : la liste `non_mesure` est présente ; elle n'est jamais vide tant que le sujet n'est
  pas entièrement couvert.

## 9. Sécurité du dépôt

- **Attendu** : gitleaks ne signale aucun secret (CI, job `secrets`) ; aucun fichier du SI fictif,
  aucune clé privée et aucun dossier `traces/` n'est versionné (`git ls-files | grep -c traces/`
  renvoie 0).

## Écarts connus

- **Traces non versionnées** : l'étape 3 ne peut pas être refaite à partir du dépôt seul tant que
  les traces ne sont pas publiées (elles doivent être relues avant publication).
- **Variante 2 du SI** : pas encore produite. La performance sur un SI non vu n'est pas mesurée.
- **Ablation avec un second modèle** : pas encore faite.
- **Répétitions de l'évaluation d'inventaire** : une seule exécution pour l'instant ; l'écart type
  n'est donc pas disponible pour le rappel et la précision.
