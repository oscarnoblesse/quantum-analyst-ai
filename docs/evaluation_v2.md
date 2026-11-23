# Évaluation sur la variante non vue du SI (v2)

Le sujet demande d'évaluer la « robustesse sur une seconde variante du SI non vue pendant le
développement » et de conclure « explicitement sur l'apport mesuré des agents » (§4.5, §6.2).
Ce document décrit le protocole suivi, les résultats et leur lecture. Tous les chiffres viennent
de `results/raw/evaluation_v2.json` et de la section `inventaire_v2` de `results/metrics.json` ;
ils se recalculent depuis les traces avec `make evaluer-v2`.

## 1. Le SI v2

« Fret Lab », un transporteur routier fictif, sans aucun nom de dossier, d'hôte ni d'autorité
repris de la v1. Construction et règles : `docs/regles_verite_terrain.md`.

| | Nombre |
| --- | --- |
| Actifs | 100 (`data/ground_truth/verite_terrain_v2.csv`) |
| Sur des technologies connues (mêmes que la v1) | 80 |
| Hors périmètre (aucun analyseur dédié au format du fichier) | 20, sur 11 technologies |
| Cachés | 27 (20 connus, 7 hors périmètre) ; 6 cachettes seulement reprises de la v1 |
| Leurres (ressemblent à de la cryptographie sans en être) | 8 (`data/ground_truth/leurres_v2.csv`) |

Contrôles : `make verifier-si-v2` donne 100/100 actifs conformes. CBOM attendu :
`data/ground_truth/cbom_attendu_v2.json`, valide CycloneDX 1.6.

## 2. Protocole

- **Système gelé.** Aucun fichier des outils, des agents, des prompts, du serveur MCP, de
  l'orchestrateur ni de `config/experiment.yaml` n'a été modifié pour la v2 (vérifié sur
  la PR #21). Le SI a été conçu sans lire le code des outils.
- **Limite assumée.** Le SI v2 a été conçu par le même assistant de programmation que celui
  qui a écrit les outils (voir `AI_USAGE.md`) : il en connaît indirectement les forces. La
  règle de conception « à l'aveugle » réduit ce biais sans l'éliminer.
- **Une même machine** (MacBook Air, macOS, OpenSSH 10, Ollama 0.40.15) pour toutes les
  exécutions : certains outils dépendent de la version locale d'OpenSSH ou d'OpenSSL.
- **Configurations** (ablation, sujet §6.2) :

| Session | Configuration | Ablation |
| --- | --- | --- |
| `v2_reference_outils_seuls` | outils seuls, heuristique codée en dur, sans modèle | (a) |
| `v2_regles` | agents à règles fixes, sans modèle | (a) |
| `v2_ollama_run1` à `run3` | système complet, qwen3:4b-instruct-2507 Q4 (empreinte 0edcdef34593), budget de l'Inventoriste 90 étapes | (b) |
| `v2_posthoc_budget_run1` | idem, budget de 162 étapes — **expérience a posteriori**, section 4 | (b) |

## 3. Résultats (configuration principale)

| | Outils seuls | Agents à règles | qwen3:4b (×3) |
| --- | --- | --- | --- |
| Rappel | 79,0 % | 33,0 % | 57,0 % ± 0 |
| — actifs connus | 70/80 | 28/80 | 51/80 |
| — hors périmètre | 9/20 | 5/20 | 6/20 |
| Rappel des cachés | 70,4 % | 33,3 % | 40,7 % ± 0 |
| Précision stricte | 69,3 % | 71,7 % | 73,1 % ± 0 |
| F1 | 0,738 | 0,452 | 0,640 ± 0 |
| Actifs Shor bien classés | 42/55 | 23/55 | 39/55 |
| Leurres touchés | L2-01, L2-04, L2-05 | aucun | aucun |
| Plan de migration | — | 0 étape, non conforme | 3 étapes, conforme, démontré au laboratoire |
| Arrêt de l'Inventoriste | — | limite d'étapes | limite d'étapes (90) |
| Durée | < 1 s | 3 s | 1 279 à 2 209 s |

**Répétitions.** Les trois exécutions avec le modèle sont identiques : mêmes 103 appels d'outils,
mêmes arguments, mêmes sorties, même plan. À température 0 et graine fixe, le modèle est
déterministe sur cette tâche et cette machine ; l'écart type est nul. Seule la durée varie.

**Lecture.**
1. **Les agents à règles s'effondrent** (100 % sur la v1, 33 % sur la v2) : leurs règles
   dépendaient des noms de fichiers de la v1. C'est le surapprentissage que la variante non vue
   devait révéler.
2. **Le système avec modèle perd 22 actifs par rapport aux outils seuls et n'en trouve aucun
   en plus.** L'Inventoriste s'arrête sur sa limite de 90 étapes : 35 fichiers sur 95 ne sont
   jamais ouverts, dont tout le code Python de `suivi/` et `lettres/`.
3. **Sa meilleure précision n'est pas un mérite** : il ne touche aucun leurre parce qu'il n'a
   jamais ouvert les fichiers qui les contiennent, pas parce qu'il les a reconnus.

## 4. Expérience a posteriori : le budget d'étapes

**Question**, posée après avoir vu la section 3 : le rappel perdu vient-il du budget d'étapes
ou de la stratégie de l'Inventoriste ?

**Règle fixée sur la v1 seule, avant l'exécution** (`config/experiment_posthoc_budget.yaml`) : sur
la v1 (52 fichiers), l'Inventoriste a utilisé au plus 76 étapes, soit 1,46 étape par fichier.
Budget = ⌈1,7 × fichiers⌉ (16 % de marge au-dessus de ce maximum), soit 162 étapes pour les
95 fichiers de la v2. Seule différence avec la configuration principale : cette valeur. Un budget
plus grand ne peut pas gonfler le résultat : c'est un plafond, l'agent s'arrête de lui-même
quand il juge avoir fini.

**Prédiction écrite avant l'exécution** (Oscar Noblesse) : l'agent réussira à lire tous les
fichiers et le score augmentera.

**Résultat** (`v2_posthoc_budget_run1`) :

| | Outils seuls | qwen3:4b, 90 étapes | qwen3:4b, 162 étapes |
| --- | --- | --- | --- |
| Rappel | 79,0 % | 57,0 % | 79,0 % |
| Rappel des cachés | 70,4 % | 40,7 % | 70,4 % |
| Précision stricte | 69,3 % | 73,1 % | 68,7 % |
| F1 | 0,738 | 0,640 | 0,735 |
| Fichiers jamais ouverts | — | 35/95 | 1/95 (le magasin JKS) |
| Appels d'outils (en erreur, en double) | 91 | 103 (13, 15) | 159 (31, 35) |
| Arrêt de l'Inventoriste | — | limite (90) | limite (162) |
| Durée | < 1 s | 1 279 s | 4 915 s |

**Lecture.**
1. **La prédiction se vérifie en partie** : l'agent ouvre 94 fichiers sur 95 et le rappel
   remonte de 57 % à 79 %. La chute de la section 3 venait donc du budget.
2. **Mais il atteint encore la limite** : la stratégie reste coûteuse. Il lance bien
   `scanner_code_crypto` sur un dossier (`suivi/app`, `lettres/signature`), puis rescanne chaque
   fichier un par un (35 appels en double) ; 21 appels visent des formats que l'outil ne lit pas.
3. **Il retrouve exactement les 79 actifs des outils seuls** : mêmes 21 actifs manqués, mêmes
   trois leurres touchés, aucun lien entre fichiers déclaré. Avec un budget suffisant, le
   modèle n'ajoute aucun actif sur la v2, pour un coût de 82 minutes au lieu d'une seconde.

## 5. Conclusion sur l'apport mesuré des agents

| Sur… | Apport mesuré des agents |
| --- | --- |
| l'inventaire du SI de développement (v1) | positif mais faible : un actif de plus que les outils seuls (QR-020, lien entre le `.env` et le PKCS#12) |
| l'inventaire du SI non vu (v2) | **nul au mieux** (budget suffisant), **négatif** avec le budget réglé sur la v1 (−22 actifs) |
| le plan de migration | positif : plan priorisé, conforme et démontré au laboratoire, stable sur trois répétitions ; les outils seuls n'en produisent pas |

Sur la v2, la qualité de l'inventaire vient des outils déterministes ; le modèle les déclenche,
moins efficacement qu'une boucle de code. Les 21 actifs que personne ne trouve sont des limites
d'outils, pas de prompt :
- **des directives ou des API d'une technologie connue, absentes de la v1, même visibles** :
  `ssl_dhparam` (V2-023), `proxy_ssl_ciphers` (V2-027), `ssl_conf_command Ciphersuites` (V2-030),
  l'échange X25519 de `cryptography` (V2-060), `ssh-keygen -t ecdsa` dans un script (V2-078) ;
- **des cachettes nouvelles** : `Include sshd_config.d/*.conf` avec bloc `Match` (V2-039), clé PEM
  dans une chaîne Python (V2-046), clé Fernet en base64 dans un `.env` (V2-051), valeur par défaut
  d'une variable shell (V2-080), et le croisement suites / certificat RSA (V2-029) ;
- **les technologies hors périmètre**, par construction : 11 actifs sur 20 manqués ; les 9 trouvés
  le sont par le repli textuel `rechercher_algorithmes`.

## 6. Ce qui n'est pas fait

- **Ablation (c)** : second modèle de taille différente, non exécuté.
- **Une seule exécution** de l'expérience a posteriori (les trois exécutions principales étant
  identiques, une variation est peu probable, mais elle n'est pas mesurée).
- La comparaison aux leurres se fait par fichier : un composant non apparié situé dans le fichier
  d'un leurre est compté comme faux positif ; un composant apparié à un vrai actif du même
  fichier ne l'est jamais.
