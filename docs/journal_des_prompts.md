# Quantum-Ready — Journal des prompts et de la boucle agentique

*Licence : CC BY 4.0 — Oscar Noblesse, 2026*

Le sujet exige que chaque modification d'un prompt soit consignée avec son effet mesuré. Chaque entrée donne la version, l'empreinte du prompt (12 premiers caractères du SHA-256 de son texte, également écrite dans `journal_agents.jsonl` à chaque exécution), le défaut constaté, la modification et son effet sur les mesures de `make evaluer`. Les modifications de la boucle agentique, qui changent ce que voit le modèle, sont consignées ici aussi.

Modèle : `qwen3:4b-instruct-2507-q4_K_M` (empreinte `0edcdef34593`), contexte de 4096 jetons, température 0, graine 42. SI fictif v1.

## Version 1 — 4 novembre 2026

| Agent | Empreinte du prompt |
| --- | --- |
| Inventoriste | `251a0f33887d` |
| Cartographe | `cffc651c79c6` |
| Analyste risque | `fc1f62c491b9` |
| Architecte | `4c26b477e1e4` |

**Exécution de référence :** `traces/20261104T174709Z_ollama`, validation humaine refusée.

| Mesure | Valeur |
| --- | --- |
| Rappel | 24,7 % (18 actifs sur 73) |
| Précision stricte | 90,0 % |
| Plan | 3 étapes, non conforme (un actif critique non couvert) |
| Tours de modèle | 22 |
| Durée totale | 1 385 s |

**Défauts constatés dans les traces :**

1. *Inventoriste interrompu au 8e tour.* Le modèle choisissait correctement un outil par tour, sans refus ni doublon, mais la requête grossissait à chaque tour (1 473 puis 3 630 jetons) jusqu'à dépasser la fenêtre de 4096 jetons. Le modèle a alors généré sans fin jusqu'au délai de 300 s (`ReadTimeout`). La description des outils coûte à elle seule environ 1 000 jetons par tour.
2. *Inventaire partiel transmis.* L'orchestrateur a poursuivi avec 20 composants au lieu de s'arrêter.
3. *Analyste sans discrimination.* x = 10 pour les 20 actifs, avec des justifications génériques recopiées de l'exemple du prompt ; 14 actifs sur 20 classés critiques, y compris une clé SSH qui ne sert qu'à l'authentification. Une seule évaluation de 20 actifs : 1 474 jetons écrits en 246 s.
4. *Architecte superficiel.* Une seule recherche, formulée avec un identifiant de fiche ; FIPS 203 (échange de clés) cité pour la migration des certificats, qui relève de FIPS 204.

## Version 2 — 4 novembre 2026

| Agent | Empreinte du prompt | Modification |
| --- | --- | --- |
| Inventoriste | `251a0f33887d` | inchangé |
| Cartographe | `cffc651c79c6` | inchangé |
| Analyste risque | `168ee09c20e7` | grille explicite de x et de y selon ce que protège l'actif ; obligation de faire varier x ; justification qui nomme l'usage ; lots de 5 actifs |
| Architecte | `11dabc033983` | table de correspondance type d'actif → fiche (jamais FIPS 203 pour une signature) ; au moins trois recherches par mots-clés, jamais par identifiant |

**Boucle agentique et orchestrateur :**

- budget de contexte par agent : 4096 − 1024 (réponse) − 200 = 2 872 jetons estimés, description des outils comprise. Au-delà, les résultats d'outils déjà lus sont raccourcis, puis les échanges les plus anciens oubliés par blocs ;
- la mémoire de travail est placée en dernier, après les échanges, pour que le début de la requête reste identique d'un tour à l'autre et puisse être réutilisé par le cache d'Ollama ;
- réponse bornée à 1024 jetons (`num_predict`), pour qu'une génération qui s'emballe ne puisse plus bloquer un agent ;
- l'orchestrateur s'arrête (`erreur_modele`) si l'Inventoriste est interrompu, au lieu de transmettre un inventaire partiel ;
- la mémoire de travail de l'Analyste affiche directement les 5 prochains actifs avec leurs indices, pour qu'il n'ait plus besoin de garder une page de `lister_actifs` dans sa fenêtre ;
- le client retire le raisonnement d'un modèle « thinking » même sans balise d'ouverture (observé avec `qwen3:4b`, variante écartée).

**Effet mesuré :** exécution `traces/20261104T182150Z_ollama`, validation humaine refusée.

| Mesure | Version 1 | Version 2 |
| --- | --- | --- |
| Rappel | 24,7 % | **95,9 %** (70 actifs sur 73) |
| Rappel des actifs cachés | 25,0 % | 87,5 % |
| Précision stricte | 90,0 % | 92,1 % |
| F1 | 0,387 | **0,940** |
| Actifs Shor bien classés | 11/43 | 40/43 |
| Plan | 3 étapes, non conforme | 3 étapes, conforme |
| Tours de modèle | 22 | 90 |
| Durée totale | 1 385 s | 1 558 s |

L'Inventoriste parcourt désormais tout le SI (76 tours, 58 appels d'outils, aucun refus) et fait le lien `KEYSTORE_PASS` → PKCS#12 (QR-020), que la référence « outils seuls » ne fait pas. Pour ouvrir le conteneur, il a essayé quatre emplacements erronés du fichier `.env` avant de trouver `api/.env` de lui-même.

**Défauts constatés :**

1. *Exclusions abusives.* L'Inventoriste a exclu le certificat admin (QR-070) et le chiffrement du PKCS#12 (QR-021), avec des raisons comme « algorithme Shor détecté, donc à exclure » : il a compris « exclure » comme « écarter ce qui est vulnérable ».
2. *Fichier analysé avec le mauvais outil.* `scripts/backup.sh` (QR-043) n'a pas été lu par `analyser_configuration` ; la mémoire de travail le comptait pourtant comme analysé.
3. *Analyste arrêté trop tôt.* Réponse finale après 15 actifs évalués sur 76, malgré la mémoire de travail.
4. *Plan : champ « cible » rempli avec des chemins de fichiers* au lieu d'algorithmes ; il ne couvre que les 6 actifs critiques issus des 15 évalués.

## Version 3 — 4 novembre 2026

| Agent | Empreinte du prompt | Modification |
| --- | --- | --- |
| Inventoriste | `2c5b467ffdc2` | les exclusions ne portent que sur des « indices à confirmer » ; ne jamais exclure un actif parce qu'il est vulnérable |
| Cartographe | `3c56409f708a` | même règle : un actif vulnérable n'est pas un faux positif |
| Analyste risque | `168ee09c20e7` | inchangé |
| Architecte | `728113259bc8` | le champ « cible » est un algorithme, un protocole ou une version, jamais un chemin |

**Garde-fous du code sur la réponse finale** (la réponse est renvoyée à l'agent avec le motif, au plus 4 fois, puis acceptée avec le motif consigné) :

- Inventoriste : refus tant qu'un fichier n'a pas été lu par l'outil conseillé (sauf s'il est déclaré laissé de côté), et refus d'une exclusion qui ne porte pas sur un indice à confirmer ;
- Analyste risque : refus tant qu'il reste des actifs à évaluer ;
- un fichier ne compte comme analysé que s'il a été lu par l'outil conseillé ;
- l'erreur « fichier .env introuvable » liste les fichiers de variables du SI.

**Effet mesuré** (exécution `20261104T193349Z_ollama`, qwen3:4b-instruct-2507, 0edcdef34593) :

| Mesure | v2 | v3 |
| --- | --- | --- |
| Rappel | 95,9 % | 100 % |
| Rappel des actifs cachés | — | 100 % |
| Précision stricte | — | 93,6 % |
| F1 | 0,940 | 0,967 |
| Classification Shor | — | 42 / 43 |
| Plan | 3 étapes, conforme | 4 étapes, conforme |
| Tours de modèle | — | 85 |
| Durée | 1 558 s | 2 100 s |

Les deux défauts de la v2 (exclusions abusives, fichier lu avec le mauvais outil) ont disparu. Deux défauts restent :

- l'Analyste risque a rendu 5 fois une réponse finale prématurée ; le garde-fou l'a refusée 4 fois puis l'a acceptée, et 39 des 78 actifs n'ont pas été évalués. La fenêtre de 4 échanges lui laissait relire ses anciens JSON finals refusés, qu'il recopiait ;
- le résumé de l'Inventoriste affirme que curve25519 est « post-quantique » : le modèle porte un jugement qu'aucun outil n'a produit.

## Version 4

| Agent | Empreinte du prompt | Modification |
| --- | --- | --- |
| Inventoriste | `4e1f7282b6c6` | le résumé décrit ce qui a été fait, sans juger les algorithmes (le jugement revient aux outils et à l'Analyste) |
| Cartographe | `3c56409f708a` | inchangé |
| Analyste risque | `b4a3125663d1` | justification de douze mots au plus ; continuer d'appeler `score_mosca` tant qu'il reste des actifs |
| Architecte | `728113259bc8` | inchangé |

**Changements du code et de la configuration :**

- la mémoire de travail de l'Analyste devient impérative : « Il reste N actif(s) : NE réponds PAS par le JSON final… », suivie des 5 prochains actifs ;
- fenêtre de l'Analyste ramenée à 1 échange (il n'a pas besoin de son historique, la mémoire contient tout) ; `max_etapes` porté à 40 ;
- le nombre de refus de la réponse finale devient un paramètre par agent (`max_refus_de_fin`) : 12 pour l'Analyste, 4 pour les autres.

**Effet mesuré :** à compléter après la prochaine exécution.
