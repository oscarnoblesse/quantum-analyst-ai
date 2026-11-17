# Quantum-Ready

Copilote multi-agents de migration post-quantique : inventaire cryptographique (CBOM CycloneDX 1.6), analyse de risque quantique (inégalité de Mosca) et démonstrateur TLS 1.3 hybride X25519MLKEM768.

> **Statut : en cours de développement.**

## Contexte

Un ordinateur quantique suffisamment puissant casserait RSA, Diffie-Hellman et les courbes elliptiques. Un attaquant peut déjà enregistrer des échanges chiffrés pour les déchiffrer plus tard (*harvest now, decrypt later*). La première étape de toute migration vers la cryptographie post-quantique est de savoir où se trouve la cryptographie dans un système d'information.

Ce projet construit une équipe d'agents IA qui, sur un système d'information **fictif** :

1. inventorie la cryptographie (code, configurations, certificats, clés SSH) ;
2. produit un CBOM valide au format CycloneDX 1.6 ;
3. évalue le risque quantique de chaque actif ;
4. propose un plan de migration priorisé ;
5. démontre la solution sur un serveur TLS 1.3 hybride post-quantique (OpenSSL 3.5, ML-KEM, ML-DSA).

## Principes

- **Le modèle de langage décide et explique ; le code calcule.** Aucune opération cryptographique n'est confiée au modèle.
- **Modèle de langage local** (Ollama), exécutable sur un ordinateur portable de 8 ou 16 Go, sans GPU ni abonnement.
- **Outils exposés via un serveur MCP**, avec une liste fermée d'outils par agent et un journal d'audit complet.
- **Humain dans la boucle** : aucune modification du SI sans validation humaine.
- **Science ouverte** : résultats reproductibles par une commande unique (`make reproduce`).

## Architecture prévue

| Agent | Rôle |
|---|---|
| Inventoriste | Recherche la cryptographie dans le SI fictif |
| Cartographe | Normalise les trouvailles en CBOM CycloneDX 1.6 |
| Analyste risque | Calcule un score de risque par actif (Mosca) |
| Architecte | Rédige le plan de migration priorisé |
| Démonstrateur | Monte un laboratoire TLS hybride local (Docker), le sonde et mesure le handshake face au X25519 classique |

Le Démonstrateur se lance avec `make demonstrateur-agent` (modèle local et Docker requis), ou sans modèle avec `make demonstrateur` (vérification du laboratoire seule). Il n'est pas appelé par `make agents` : son rôle dans le graphe reste à décider. En revanche, `make agents` utilise le même laboratoire pour vérifier le plan de l'Architecte quand Docker est présent (voir [Docker](#docker-facultatif)).

## Documentation

- [Règles de la vérité terrain](docs/regles_verite_terrain.md)
- [Périmètre technologique et validation des outils d'inventaire](docs/perimetre_et_validation_des_outils.md)
- [Comparer deux implémentations des agents](docs/comparaison_des_agents.md)
- [Journal des prompts et de la boucle agentique](docs/journal_des_prompts.md)
- [Publier la version v1.0.0 : signature, release, Zenodo](docs/publication.md)

## Installation

Prérequis : [uv](https://docs.astral.sh/uv/), Git et OpenSSL 3. uv installe lui-même le Python 3.12 du projet ; il n'est pas nécessaire d'en avoir un.

OpenSSL sert à développer la macro TLS `HIGH` de nginx : sans lui, l'actif caché QR-015 n'est pas détecté et `scripts/reproduire.py` refuse de démarrer. Il est déjà présent sous macOS et Linux. Sous Windows, Git for Windows en fournit un, hors du PATH :

```powershell
$env:Path += ";C:\Program Files\Git\usr\bin"
```

```bash
# macOS / Linux : installer uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Windows (PowerShell) : installer uv
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Puis, sur les trois systèmes :

```bash
git clone https://github.com/oscarnoblesse/quantum-analyst-ai.git
cd quantum-analyst-ai
```

## Installer le modèle local (Ollama)

Les agents utilisent un modèle de langage local servi par [Ollama](https://ollama.com). Une seule commande installe Ollama s'il manque, télécharge le modèle figé dans `config/experiment.yaml` (environ 2,5 Go), vérifie son empreinte et sa capacité « tools » :

```bash
uv run python -m quantum_ready.installation_modele      # ou : make installer-modele
```

Selon le système, l'installation d'Ollama passe par :
- **macOS** : Homebrew (`brew install ollama`) ; sans Homebrew, téléchargement sur [ollama.com/download](https://ollama.com/download) ;
- **Windows** : winget (`winget install Ollama.Ollama`) ; sans winget, même téléchargement ;
- **Linux** : le script officiel d'Ollama, qui peut demander votre mot de passe administrateur.

Le script est idempotent : relancez-le sans risque. Il n'installe rien tant que tout est en place.

## Docker (facultatif)

[Docker](https://docs.docker.com/get-docker/) fait tourner le laboratoire TLS hybride local. Il n'est pas nécessaire pour reproduire le projet (`scripts/reproduire.py`), ni pour lancer les agents.

| Commande | Sans Docker |
|---|---|
| `scripts/reproduire.py` | fonctionne : Docker n'est pas utilisé |
| `make agents` | fonctionne ; les étapes du plan démontrables au laboratoire (TLS hybride, certificat ML-DSA-65, SSH hybride) sont marquées « non vérifiées » (motif : Docker introuvable) au lieu d'être démontrées |
| `make demonstrateur`, `make demonstrateur-agent`, `make reproduce-complet` | impossible : Docker requis |

La démonstration du plan au laboratoire est réglée par `verification_demonstration` dans `config/experiment.yaml`.

Installation : Docker Desktop sous macOS et Windows (`winget install Docker.DockerDesktop`), paquet `docker.io` ou [Docker Engine](https://docs.docker.com/engine/install/) sous Linux.

## Reproduire le projet

Une seule commande, identique sous macOS, Linux et Windows :

```bash
uv run python scripts/reproduire.py
```

Elle installe l'environnement figé (`uv.lock`), valide la vérité terrain, génère le SI fictif, vérifie qu'il correspond à la vérité terrain et lance les tests avec un seuil de couverture de 70 %. Durée : environ une minute.

Pour une vérification rapide (environnement et tests, sans régénérer le SI) :

```bash
uv run python scripts/reproduire.py --petite
```

Sur macOS et Linux, `make reproduce` et `make reproduce-small` font la même chose. Sous Windows, utilisez les commandes `uv run` ci-dessus.

Notes :
- Le SI généré (`si/generated/v1`) est fictif, produit localement et jamais commité.
- Certains tests sont ignorés selon le système, sans que cela soit une erreur : droits POSIX et liens symboliques (Windows), `ssh-keygen` absent, clés DSA refusées par OpenSSH récent. `openssl`, lui, est obligatoire (voir Installation).
- Si vous lancez un module à la main sous Windows (`uv run python -m quantum_ready...`), activez d'abord le mode UTF-8 : `$env:PYTHONUTF8 = "1"`.

## Reproduire avec Docker

Sur une machine qui n'a que Docker, l'image du dépôt exécute la même reproduction (`make reproduce`), sans rien installer d'autre :

```bash
docker build -t quantum-ready .
docker run --rm quantum-ready
```

L'image ne contient ni Ollama ni le laboratoire TLS : les agents et le démonstrateur se lancent sur l'hôte (voir plus haut).

## Vérifier l'intégrité des résultats

`SHA256SUMS` donne l'empreinte de chaque artefact publié (`results/`, `traces/`, `data/ground_truth/`) ; il est signé avec [minisign](https://jedisct1.github.io/minisign/) (`SHA256SUMS.minisig`, clé publique `cle_publique_minisign.pub`). Vérification : `make verifier-signature`, ou les deux commandes de la section 10 d'[AUDIT.md](AUDIT.md).

## Cadre éthique

Le système d'information analysé est entièrement fictif. Aucune clé privée réelle n'est publiée dans ce dépôt : toutes les clés sont factices et générées par script.

## Licence

- Code : [Apache-2.0](LICENSE)
- Documentation, données, résultats et traces : [CC BY 4.0](LICENSE-docs)

## Auteur

Oscar Noblesse — projet individuel (sujet n°7 « Quantum-Ready »), module *Cryptographie appliquée et IA agentique*, 2026.
