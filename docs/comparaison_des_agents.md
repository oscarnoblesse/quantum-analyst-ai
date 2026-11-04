# Quantum-Ready — Comparer deux implémentations des agents

*Licence : CC BY 4.0 — Oscar Noblesse, 2026*

## Objet

Le projet compare deux implémentations du système multi-agents, écrites indépendamment sur les mêmes outils déterministes : celle du dossier `src/quantum_ready/agents/` (écrite avec l'assistance d'une IA, voir `AI_USAGE.md`) et celle de l'auteur. Ce document fixe le **contrat** que toute implémentation respecte, pour que la comparaison porte sur la qualité des agents et non sur des différences de format ou de mesure.

## Contrat

Une implémentation reçoit la racine d'un SI fictif et produit un **dossier de session** contenant :

| Fichier | Obligatoire | Contenu |
| --- | --- | --- |
| `cbom.json` | oui | CBOM CycloneDX 1.6 du SI. La propriété `quantum-ready:exposition-quantique` (shor, grover, resistant, aucune, inconnue) est conseillée : elle est mesurée. |
| `journal_outils.jsonl` | conseillé | Un événement par appel d'outil : `agent`, `outil`, `arguments`, `statut` (ok, erreur, exception, refus), `duree_ms`. |
| `journal_agents.jsonl` | conseillé | Un événement par tour de modèle (`evenement: "tour"`, `jetons_entree`, `jetons_sortie`, `duree_ms`) et un événement `fin` par agent (`arret`, `duree_ms`). |
| `plan.json` | conseillé | Plan de migration : `etapes` (`ordre`, `actifs`, `action`, `cible`, `echeance`, `references`). Sa conformité est revérifiée : fiches du corpus existantes, actifs existants, actifs critiques couverts. |
| `scores.json`, `rapport.json` | facultatif | Scores de Mosca et rapport d'exécution. |

Sans journaux, la qualité de l'inventaire est mesurée mais pas les coûts.

Le plus simple pour respecter ce format est de réutiliser `quantum_ready.serveur_mcp` : la classe `Session` écrit le dossier, le serveur MCP journalise les appels d'outils, et `quantum_ready.agents.boucle` journalise les tours. Une implémentation peut aussi tout réécrire (autre boucle, autre cadriciel, autres prompts) tant que le dossier produit respecte le contrat.

## Ce qui est commun et ce qui est libre

**Commun, à ne pas modifier pour la comparaison :** les outils de `src/quantum_ready/outils/`, le SI fictif, la vérité terrain, le modèle de langage et ses réglages (`config/experiment.yaml`), et le module d'évaluation.

**Libre :** le découpage en agents, les prompts, la mémoire de travail, la stratégie de parcours du SI, la gestion des erreurs, l'orchestration. C'est précisément ce qui est comparé.

## Mesures

Le module `quantum_ready.evaluation` apparie chaque composant du CBOM à au plus un actif de la vérité terrain : même type CycloneDX, même emplacement (ou tous deux implicites), puis le plus de mots en commun entre noms et paramètres.

| Mesure | Définition |
| --- | --- |
| Rappel | Actifs de la vérité terrain appariés / actifs attendus |
| Rappel des actifs cachés | Idem sur les 16 actifs cachés, détaillé par catégorie |
| Précision stricte | Composants appariés / composants du CBOM |
| Précision hors doublons | Idem, sans compter les doublons (même actif vu deux fois, à un emplacement attendu) |
| F1 | Moyenne harmonique du rappel et de la précision stricte |
| Actifs Shor bien classés | Actifs « Oui (Shor) » appariés à un composant d'exposition `shor` |
| Plan | Nombre d'étapes et conformité (vérifiée avec les mêmes règles pour toutes les implémentations) |
| Coûts | Appels d'outils (refusés, en erreur), tours de modèle, jetons, durée |

## Points de référence

Deux exécutions sans modèle de langage encadrent les résultats ; elles servent aussi à l'étude d'ablation.

| Référence | Commande | Rôle |
| --- | --- | --- |
| Outils seuls | `make reference` | Chaque fichier passe dans l'outil conseillé, sans aucun lien entre fichiers |
| Agents à règles fixes | `make agents-regles` | La même architecture d'agents, pilotée par des règles écrites à la main |

Sur le SI v1, la référence « outils seuls » trouve 72 actifs sur 73 : elle manque la clé privée contenue dans le PKCS#12 (QR-020), qui exige de relier `KEYSTORE_PASS` (dans `api/.env`) au code de `factures/signer.py`. Un agent doit au minimum faire ce lien.

## Procédure

```bash
make si                          # génère le SI fictif v1
make reference                   # référence : outils seuls
make agents-regles               # référence : agents à règles fixes
make agents                      # agents avec le modèle local (Ollama doit tourner)
# … exécuter l'autre implémentation, qui écrit sa session dans traces/<nom>
make evaluer SESSIONS="traces/reference_outils_seuls traces/regles traces/<session_ollama> traces/<nom>"
```

La commande affiche un tableau Markdown et écrit `evaluation.json` dans chaque session. Pour une comparaison équitable, chaque implémentation est exécutée plusieurs fois (le modèle, même à température 0, n'est pas parfaitement déterministe d'une machine à l'autre) et les résultats sont publiés avec leurs traces.

## Limites

- L'appariement est automatique : il est documenté et identique pour tous, mais un composant mal nommé peut être compté comme « en trop » alors qu'un humain l'apparierait.
- Le SI v1 a servi au développement des outils et des deux implémentations : la comparaison finale doit être refaite sur la variante 2 du SI, non vue pendant le développement.
