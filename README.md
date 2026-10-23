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
| Démonstrateur | Monte le serveur TLS hybride et mesure les performances |

## Installation

*À venir.*

## Cadre éthique

Le système d'information analysé est entièrement fictif. Aucune clé privée réelle n'est publiée dans ce dépôt : toutes les clés sont factices et générées par script.

## Licence

- Code : [Apache-2.0](LICENSE)
- Documentation et données : CC BY 4.0

## Auteur

Oscar Noblesse — projet individuel (sujet n°7 « Quantum-Ready »), module *Cryptographie appliquée et IA agentique*, 2026.
