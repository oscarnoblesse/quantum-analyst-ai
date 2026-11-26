# Quantum-Ready : copilote multi-agents de migration post-quantique

Rapport technique — projet individuel n° 7, Cryptographie appliquée et IA agentique (édition 2026) · Oscar Noblesse · Novembre 2026

# Résumé

Un ordinateur quantique suffisamment puissant casserait les algorithmes à clé publique utilisés aujourd'hui (RSA, Diffie-Hellman, courbes elliptiques). Toute migration post-quantique commence par savoir où se trouve la cryptographie d'un système d'information. Ce projet construit Quantum-Ready, un système multi-agents exécuté avec un modèle de langage local (qwen3:4b-instruct, 4 milliards de paramètres, sans GPU), qui inventorie la cryptographie d'un SI fictif, produit un CBOM CycloneDX 1.6, évalue le risque de chaque actif selon l'inégalité de Mosca, rédige un plan de migration priorisé et le vérifie sur un laboratoire TLS 1.3 et SSH hybride post-quantique. Le modèle décide et explique ; toute la cryptographie et tous les calculs sont faits par des outils déterministes exposés en MCP. Sur le SI de développement (73 actifs), le système atteint un rappel de 100 % (F1 0,961). Sur une variante jamais vue (100 actifs), il obtient 57 % avec le budget d'étapes réglé sur la v1, et 79 % avec un budget adapté, soit exactement le résultat des outils seuls : sur l'inventaire, l'apport mesuré du modèle est nul, alors que son apport au plan de migration, démontré au laboratoire, est réel. L'échange hybride X25519MLKEM768 coûte environ 35 % de latence et 1 176 octets de plus que X25519 seul.

Ces résultats suggèrent que la limite observée tient moins à l'approche agentique elle-même qu'à la capacité du modèle utilisé et à la coordination entre agents : avec un modèle plus puissant et une orchestration mieux réglée, l'inventaire de SI plus volumineux avec peu d'actifs perdus est une perspective plausible, qui reste à démontrer expérimentalement.

# Abstract

A cryptographically relevant quantum computer would break today's public-key algorithms (RSA, Diffie-Hellman, elliptic curves). Any post-quantum migration starts by finding where cryptography lives in an information system. This project builds Quantum-Ready, a multi-agent system running on a local language model (qwen3:4b-instruct, 4 billion parameters, no GPU). It inventories the cryptography of a fictitious information system, produces a CycloneDX 1.6 CBOM, scores each asset's quantum risk with Mosca's inequality, writes a prioritised migration plan and checks it on a hybrid post-quantum TLS 1.3 and SSH laboratory. The model decides and explains; all cryptography and computation are done by deterministic tools exposed through MCP. On the development system (73 assets) the agents reach 100 % recall (F1 0.961). On an unseen variant (100 assets) they reach 57 % with the step budget tuned on the first system, and 79 % with an adapted budget — exactly what the tools achieve alone. The measured contribution of the language model to the inventory is therefore nil, whereas its contribution to the migration plan, verified in the laboratory, is real. Hybrid X25519MLKEM768 key exchange costs about 35 % more handshake latency and 1,176 more bytes than X25519 alone.

These results suggest that the observed limitation lies less in the agentic approach itself than in the capacity of the model and in the coordination between agents: with a more capable model and better-tuned orchestration, inventorying larger information systems with few missed assets is a plausible prospect that remains to be demonstrated experimentally.

# 1. Contexte et problème

## 1.1 La menace quantique

Le NIST a publié en août 2024 les trois premiers standards post-quantiques : FIPS 203 (ML-KEM, encapsulation de clé), FIPS 204 (ML-DSA, signature sur réseaux euclidiens) et FIPS 205 (SLH-DSA, signature à base de fonctions de hachage). L'ANSSI recommande une transition hybride, qui combine un algorithme classique et un algorithme post-quantique, et les feuilles de route publiques fixent des jalons entre 2030 et 2035. OpenSSL intègre ces algorithmes depuis la version 3.5 et propose par défaut l'échange hybride X25519MLKEM768 en TLS 1.3 ; OpenSSH 10 propose `mlkem768x25519-sha256`.

**Pourquoi Shor casse l'asymétrique.** La sécurité de RSA repose sur la difficulté de factoriser un grand nombre, celle de Diffie-Hellman et des courbes elliptiques (ECDH, ECDSA, Ed25519, X25519) sur la difficulté du logarithme discret. Pour un ordinateur classique, les meilleurs algorithmes connus restent sous-exponentiels ou exponentiels. L'algorithme de Shor ramène ces deux problèmes à la recherche de la période d'une fonction, qu'un ordinateur quantique réalise en temps polynomial grâce à la transformée de Fourier quantique. Augmenter la taille des clés ne suffit donc pas : il faut changer de problème mathématique, ce que font ML-KEM et ML-DSA (réseaux euclidiens) et SLH-DSA (fonctions de hachage).

**Pourquoi Grover affecte peu le symétrique.** L'algorithme de Grover accélère la recherche exhaustive de façon seulement quadratique : trouver une clé de n bits demande de l'ordre de 2^(n/2) opérations au lieu de 2^n. AES-128 descend ainsi vers environ 64 bits de sécurité théorique et AES-256 vers environ 128 bits, qui restent hors de portée. Doubler la taille des clés symétriques et des empreintes suffit donc. En pratique, Grover se parallélise mal et le NIST définit encore le premier niveau de sécurité post-quantique par rapport à la recherche d'une clé AES-128.

**« Enregistrer maintenant, déchiffrer plus tard ».** Un adversaire peut capturer aujourd'hui des échanges chiffrés et les conserver jusqu'à disposer d'un ordinateur quantique capable de casser l'échange de clés qui les protège. Toute donnée qui doit rester confidentielle au-delà de cet horizon est donc déjà exposée : la menace est actuelle pour l'échange de clés et le chiffrement asymétrique. Pour une signature, la situation diffère : un ordinateur quantique futur permettra de forger de nouvelles signatures, pas de lire des données passées. Le risque porte alors sur les signatures qui doivent rester vérifiables longtemps (factures conservées 10 ans, autorités de certification) et sur le temps nécessaire pour migrer les infrastructures qui les produisent.

## 1.2 L'inventaire cryptographique

On ne peut pas migrer ce qu'on ne connaît pas. Un inventaire cryptographique recense chaque usage de la cryptographie : certificats, clés, protocoles configurés, algorithmes appelés dans le code, bibliothèques. Le format de référence est le CBOM (Cryptographic Bill of Materials) de CycloneDX 1.6, qui décrit chaque actif (`algorithm`, `certificate`, `protocol`, `related-crypto-material`, `library`), ses propriétés et l'endroit où il a été trouvé.

## 1.3 Objectif du projet

Construire un copilote multi-agents, exécutable sur un ordinateur portable de 8 Go sans GPU ni abonnement, qui :

1. inventorie la cryptographie d'un SI fictif et produit un CBOM CycloneDX 1.6 valide ;
2. évalue le risque quantique de chaque actif selon l'inégalité de Mosca ;
3. propose un plan de migration priorisé, appuyé sur les standards ;
4. démontre et mesure la cible sur un laboratoire TLS 1.3 hybride ;
5. sous contrôle humain, avec un journal complet, et de façon reproductible par un tiers.

# 2. Principes de conception

**Le modèle décide et explique ; le code calcule.** Aucune opération cryptographique, aucun calcul de score et aucune validation n'est confiée au modèle. Il choisit quels outils appeler et dans quel ordre, interprète leurs résultats et rédige. Tout ce qui peut être faux de façon vérifiable est vérifié par du code.

**Le code vérifie, il ne croit pas le modèle.** Chaque sortie d'agent est validée par un schéma Pydantic, puis revérifiée par le code : le CBOM contre le schéma CycloneDX, le plan contre le corpus de normes et la liste des actifs critiques, la fin de l'inventaire contre la liste des fichiers réellement analysés. Une sortie refusée retourne à l'agent avec le motif.

**Un outil analyse un format, pas un SI.** Les outils sont écrits d'après la grammaire des formats (nginx, OpenSSH, X.509, PKCS#12…), jamais d'après les fichiers du SI de développement. Le périmètre technologique est fermé et documenté (`docs/perimetre_et_validation_des_outils.md`) ; un format sans analyseur dédié est signalé et confié à un outil de repli textuel.

Ce partage des rôles répond à un risque concret : un modèle de langage peut halluciner, c'est-à-dire produire une affirmation plausible mais fausse, ce qui dégrade la qualité du résultat sans le signaler. Le projet en a donné des exemples : un résumé de l'Inventoriste a qualifié curve25519 de « post-quantique », et la liste des actifs critiques rendue par l'Analyste ne correspondait pas aux scores calculés. Les outils déterministes, eux, donnent le même résultat à chaque exécution et se testent. En contrepartie, un outil n'applique que des règles écrites à l'avance : l'intérêt attendu de l'agent est de compléter ce que ces règles ne voient pas, en particulier les actifs cachés qui n'apparaissent qu'en reliant plusieurs fichiers. La section 9 mesure dans quelle proportion cet intérêt se vérifie.

# 3. Architecture

## 3.1 Vue d'ensemble

| Agent | Rôle | Outils (liste fermée) | Sortie validée |
| --- | --- | --- | --- |
| Inventoriste | Recherche la cryptographie dans le SI | `lister_fichiers`, `analyser_x509`, `analyser_cle`, `analyser_pkcs12`, `analyser_configuration`, `scanner_code_crypto`, `analyser_dependances`, `rechercher_algorithmes` | résumé, exclusions, liens entre fichiers |
| Cartographe | Normalise les trouvailles en CBOM CycloneDX 1.6 | `lister_trouvailles`, `construire_cbom`, `valider_schema` | CBOM valide |
| Analyste risque | Fixe x et y de Mosca pour chaque actif | `lister_actifs`, `score_mosca` | tous les actifs évalués |
| Architecte | Rédige le plan de migration priorisé | `lister_priorites`, `rechercher_standard` | étapes avec actifs, cible, échéance, références |
| Démonstrateur | Monte le laboratoire, mesure, vérifie le plan | `demarrer_laboratoire`, `scan_tls_lab`, `mesurer_handshake`, `arreter_laboratoire` | mesures |

Tous les agents partagent le même modèle chargé en mémoire et se distinguent par leur prompt versionné (`src/quantum_ready/prompts/`) et leur liste d'outils (`outils/__init__.py`).

Écarts à l'architecture de référence du sujet, justifiés :

- `semgrep_crypto` est remplacé par `scanner_code_crypto`, un analyseur fondé sur l'arbre syntaxique Python, et `ssh-keygen -l` par `analyser_cle`, qui calcule la même empreinte sans dépendre de la version d'OpenSSH installée.
- `scan_tls_lab` est donné au Démonstrateur et non à l'Inventoriste : il faut un serveur du laboratoire en marche, qui n'existe qu'au moment de la démonstration, et l'inventaire d'un SI fictif ne doit pas dépendre d'un réseau.

## 3.2 Les outils et le serveur MCP

Les outils sont des fonctions Python déterministes, testées une à une, exposées par un serveur MCP (SDK Python officiel, version 1.x). Un serveur est créé par agent et n'enregistre que la liste fermée de cet agent : un appel hors liste est refusé côté serveur, même si le modèle le demande. Chaque appel est journalisé (`journal_outils.jsonl`) avec l'agent, les arguments, le statut et la sortie.

Les secrets ne sortent jamais d'un outil : un mot de passe trouvé dans un `.env` est décrit par sa forme (longueur, alphabet), et pour ouvrir un PKCS#12, l'agent donne le nom de la variable, pas sa valeur.

## 3.3 L'orchestrateur

L'orchestrateur est un graphe LangGraph à état typé :

```
Inventoriste ─▶ Cartographe ⇄ revalidation du CBOM par le code (3 tentatives)
             ─▶ Analyste risque
             ─▶ Architecte ⇄ verifier_plan (2 tentatives)
                           ⇄ démonstration au laboratoire (échec → plan à réviser)
             ─▶ validation humaine ─▶ fin
```

Trois boucles de vérification existent : le CBOM revalidé par le code, le plan vérifié par le code (références du corpus existantes, actifs existants, critiques tous couverts, échéances non passées), puis chaque étape démontrable du plan montée au laboratoire. Aucune modification du SI n'est possible : aucun outil n'écrit dans le SI, et le plan passe par une validation humaine.

## 3.4 La boucle d'agent

Un modèle de 4 milliards de paramètres a une fenêtre de 4 096 jetons. La boucle (`agents/boucle.py`) est construite autour de cette contrainte :

- **budget de contexte** : 4 096 − 1 024 (réponse) − 200 (marge) = 2 872 jetons estimés ; au-delà, les anciens résultats d'outils sont raccourcis, puis les vieux échanges retirés ;
- **mémoire de travail** placée en dernier message, recalculée par le code à chaque tour (fichiers restant à analyser, actifs restant à évaluer…) : le modèle n'a pas à se souvenir, il lit ;
- **appels en double** rappelés depuis un cache au lieu d'être relancés ;
- **garde-fous de fin** (`verifier_fin`) : une réponse finale prématurée est refusée avec le motif (par exemple « il reste 39 actifs à évaluer ») ;
- **limite d'étapes** par agent et arrêt propre en cas de panne du modèle.

Ces choix découlent d'une observation répétée pendant le développement : avec 4 milliards de paramètres et une fenêtre de 4 096 jetons, le modèle perd en fiabilité dès que son contexte se remplit. Lorsque la conversation s'allonge, il confond les échanges, s'appuie sur ses propres réponses précédentes comme s'il s'agissait de faits et finit par halluciner. En version 1, la saturation du contexte a provoqué un dépassement de délai et un rappel de 24,7 %. En version 3, l'Analyste recopiait ses anciennes réponses finales pourtant refusées, et n'a évalué que 39 actifs sur 78. La réponse a été de retirer au modèle la tâche de se souvenir : le code compresse les anciens échanges, ne conserve qu'une fenêtre glissante adaptée à chaque agent (un seul échange pour l'Analyste) et place en dernier une mémoire de travail qu'il recalcule à chaque tour. En version 4, l'Analyste a ainsi évalué 78 actifs sur 78 sans aucune réponse finale prématurée.

# 4. Le SI fictif et la vérité terrain

## 4.1 SI de développement (v1)

Le SI v1 est généré par script à graine fixe (`make si`) : une API Python, une configuration nginx, une configuration SSH, une PKI (racine, intermédiaire, certificats serveurs et clients), un module de signature de factures, une base de données, des dépendances. Il contient **73 actifs cryptographiques**, dont **16 cachés** (dépendances transitives, code mort, configurations indirectes, croisements entre fichiers), documentés dans `data/ground_truth/verite_terrain_v1.csv`. Le seuil du sujet (40 actifs dont 10 cachés) est dépassé.

Les clés privées sont générées au moment de la génération et ne sont jamais commitées ; les secrets sont écrits hors du SI.

**Critère « caché ».** Un actif est classé caché lorsqu'on ne peut pas le trouver en lisant un seul fichier ou en cherchant un mot-clé : il faut déployer une configuration, croiser plusieurs fichiers ou raisonner sur l'usage. Sept catégories sont retenues (`docs/regles_verite_terrain.md`) : configuration indirecte, actif implicite (valeur par défaut), croisement de fichiers, code ou dépendance morts, dépendance transitive, emplacement trompeur et usage à interpréter. Chaque actif caché porte sa catégorie dans la vérité terrain, et le validateur refuse un actif caché sans catégorie reconnue. Deux exemples conçus pour le SI v1 illustrent ce critère :

- **QR-015, suite TLS à échange de clés RSA.** La directive `ssl_ciphers` de nginx ne contient que la macro `HIGH:!aNULL:!MD5` ; aucune suite n'y est nommée et le mot « RSA » n'apparaît pas. Il faut déployer la macro avec OpenSSL pour découvrir qu'elle autorise des suites à échange de clés RSA statique (`AES256-GCM-SHA384`, Kx=RSA). Le risque n'existe en outre que si TLS 1.2 est actif et si le certificat du serveur est RSA : il faut croiser `ssl_protocols`, `ssl_ciphers` et le certificat. Dans ce cas, la confidentialité de tout le trafic enregistré dépend d'une seule clé RSA, cassable par Shor.
- **QR-045, ancien certificat d'AC dans un bundle.** Le fichier `api/config/ca_bundle.pem` contient plusieurs certificats à la suite ; le deuxième est une ancienne autorité à clé RSA-1024 signée en SHA-1, restée dans le magasin de confiance. Un inventaire qui ne lit que le premier certificat du fichier la manque.

## 4.2 Variante d'évaluation (v2)

Le SI v2, « Fret Lab », est un transporteur routier fictif qui ne reprend aucun nom de la v1. Il compte **100 actifs** : 80 sur les technologies de la v1 et **20 hors périmètre** (11 technologies sans analyseur : Java et JKS, Go, Node.js, HAProxy, strongSwan, WireGuard, OpenVPN, Kubernetes, Terraform, SAML, DNSSEC…), dont **27 cachés**, et **8 leurres** qui ressemblent à de la cryptographie sans en être (MD5 d'une clé de cache, certificat de test, commentaire). Un actif est « hors périmètre » quand aucun analyseur dédié ne lit le format du fichier qui le porte. Les contrôles automatiques confirment les 100 actifs dans le SI généré (`make verifier-si-v2`).

Le système évalué a été gelé pendant toute la construction de la v2 : aucun outil, agent ou prompt n'a été modifié, et le SI a été conçu sans lire le code des outils.

# 5. Analyse de risque : l'inégalité de Mosca

Pour chaque actif, l'Analyste fixe deux durées que le code combine avec l'horizon de la menace :

- **x** : durée pendant laquelle les données ou la signature doivent rester sûres ;
- **y** : durée nécessaire pour migrer cet actif ;
- **z** : années avant un ordinateur quantique capable de le casser (10 ans, scénarios 5 et 15).

L'actif est en danger si **x + y > z**. L'outil `score_mosca` calcule le score de 0 à 100 : score = 100 × poids × urgence, avec un poids de 1 pour une exposition à Shor ou inconnue, 0,3 pour Grover, 0 sinon, et une urgence de 1 si l'actif est en danger, (x + y) / z sinon.

**Définition retenue de la priorité « critique »** : un actif est critique si et seulement s'il est en danger au sens de Mosca et exposé à Shor (ou d'algorithme inconnu, par prudence). Sur le SI v1, cette règle donne 6 à 7 actifs critiques (signatures des factures conservées 10 ans, chiffrement OpenPGP des sauvegardes), contre 21 avec un simple seuil sur le score.

**Justification.** L'exposition à Shor indique *si* un actif sera cassé ; l'inégalité de Mosca indique si ce sera *avant* la fin de la période pendant laquelle il doit rester sûr. Les actifs menacés par Shor sont les plus graves, car leur rupture est complète : pour le chiffrement et l'échange de clés, elle donne un accès direct aux données, y compris à celles enregistrées aujourd'hui ; pour une signature, elle permet de forger des documents ou des identités. Mais un actif exposé à Shor qui ne protège que des données éphémères peut migrer dans le cycle normal de renouvellement. La première version de la règle, fondée sur un simple seuil de score, classait 21 actifs sur 78 « critiques » : le plan ne pouvait pas tous les couvrir, et l'explication produite se contredisait (« ne dépasse pas l'horizon de la menace… priorité critique »). Une telle liste n'aide pas un responsable de la sécurité à décider par où commencer. La définition retenue réserve la priorité critique aux actifs dont la migration ne peut pas attendre, et c'est ce que le lecteur du plan doit voir en premier.

**Limite.** Les durées x et y sont choisies par le modèle, et ses valeurs restent grossières : beaucoup d'actifs reçoivent x = 1 ou x = 5 sans justification fine. Le score n'est donc fiable que dans la mesure où ces estimations le sont. Un modèle plus capable, mieux renseigné sur le contexte métier de chaque actif (durée de conservation légale, cycle de renouvellement), pourrait en améliorer nettement la pertinence ; à défaut, ces valeurs devraient être relues par une personne qui connaît le SI.

# 6. Plan de migration, crypto-agilité et feuille de route

## 6.1 Le plan

L'Architecte cherche dans un corpus local de 12 fiches (FIPS 203, 204, 205, NIST IR 8547, avis de l'ANSSI, IETF TLS hybride, OpenSSH post-quantique, CNSA 2.0, feuille de route européenne, Mosca, symétrique et hachage, GnuPG) avec une recherche BM25, puis rédige des étapes : actifs concernés, action, cible (algorithme ou protocole), échéance, références. Le code refuse un plan qui cite une fiche inexistante, un actif absent du CBOM, oublie un actif critique ou fixe une échéance déjà passée.

## 6.2 Vérification du plan au laboratoire (décision de méthode n° 2)

Une étape dont la cible est démontrable (`X25519MLKEM768`, `ML-DSA-65`, `mlkem768x25519-sha256`) est montée au laboratoire ; le code vérifie qu'elle est réellement négociée et mesure son coût. Un échec renvoie le plan à l'Architecte. Une étape non démontrable (GnuPG, PKI hors laboratoire) est marquée « non vérifiée », jamais « validée ». Sur le SI v2, le plan produit compte trois étapes : ML-DSA-65 et X25519MLKEM768 démontrées, GnuPG post-quantique non vérifiée.

**Pourquoi « non vérifiée » plutôt que « validée ».** Toutes les étapes d'un plan ne peuvent pas être démontrées : le laboratoire sait monter un serveur TLS ou SSH hybride, mais pas rechiffrer des sauvegardes GnuPG ni remplacer une PKI d'entreprise. Si l'absence de démonstration valait validation, le plan afficherait la même confiance pour une étape prouvée et pour une étape seulement écrite par le modèle. Le statut « non vérifiée » évite cette confusion : il indique au lecteur ce qui a été réellement négocié et mesuré, et ce qu'il doit encore faire tester par l'équipe concernée avant de s'engager. Un plan dont une partie reste non vérifiée n'est pas un plan en échec ; c'est un plan qui dit honnêtement où s'arrête la preuve.

## 6.3 Indicateur de crypto-agilité (décision de méthode n° 1)

L'agilité d'un actif dépend de l'endroit où il apparaît : élevée dans un fichier de configuration (changer une valeur), moyenne dans une dépendance (mettre à jour une bibliothèque), faible dans le code source (modifier et redéployer) ou dans un certificat ou une clé (réémettre et distribuer). Un actif présent à plusieurs endroits prend le niveau le plus rigide. Sur le CBOM d'exemple (77 actifs) : 20 actifs d'agilité élevée, 5 moyenne, 52 faible (`results/metrics.json`, section `crypto_agilite`).

Un actif peu agile est plus difficile et plus long à corriger : il demande de modifier du code, de réémettre et de redistribuer des certificats, donc plus de moyens. Retenir le niveau le plus rigide quand un actif apparaît à plusieurs endroits suit la même logique : la migration n'est terminée qu'une fois le dernier emplacement corrigé, et c'est le plus difficile qui fixe la durée. Avec plus des deux tiers des actifs peu agiles, l'équipe doit anticiper ces chantiers et les engager tôt. Faible agilité ne signifie pas pour autant criticité : un actif peu agile mais peu exposé peut attendre, alors qu'un actif très agile et critique doit être traité en premier. Les deux mesures sont complémentaires ; l'agilité éclaire en particulier la durée de migration y de l'inégalité de Mosca.

## 6.4 Feuille de route en trois vagues et tableau de bord

Les exigences complémentaires n° 4 (feuille de route en trois vagues, avec effort, dépendances et diagramme de Gantt généré depuis les données) et n° 5 (tableau de bord HTML de la migration généré depuis le CBOM et publié sur GitHub Pages) **ne sont pas réalisées**, faute de temps dans les délais du projet. Les données nécessaires existent déjà (plan, priorités, crypto-agilité, CBOM) ; ces deux livrables sont des générations à partir de ces fichiers et constituent le premier travail à reprendre (section 13).

# 7. Démonstrateur post-quantique

## 7.1 Le laboratoire

Le laboratoire est un ensemble de conteneurs Docker locaux : un serveur et un client TLS 1.3 sous OpenSSL 3.5.7, et un serveur OpenSSH 10.0. Les certificats et clés sont éphémères, créés au démarrage. La vérification automatique (`results/raw/demonstrateur_verification.json`) confirme :

- TLS : groupe négocié **X25519MLKEM768**, et un client purement classique est refusé ;
- SSH : échange négocié **mlkem768x25519-sha256** (OpenSSH 10.0), et un client classique est refusé.

La sonde `scan_tls_lab` refuse toute cible non locale avant la moindre connexion : le projet ne scanne aucun système réel (article 323-1 du Code pénal).

## 7.2 Latence de la poignée de main TLS 1.3

Mesure `bench_pqc` : 1 000 poignées de main après 100 d'échauffement, trois répétitions par configuration, en boucle locale (sans latence réseau). Médianes en microsecondes (`results/metrics.json`, `results/figures/latence.svg`).

| Échange | Certificat | Médiane (µs) | Message Certificate (octets) |
| --- | --- | --- | --- |
| X25519MLKEM768 | ECDSA P-256 | ≈ 924 | 406 |
| X25519 | ECDSA P-256 | ≈ 685 | 406 |
| X25519MLKEM768 | RSA-2048 | ≈ 1 747 | 802 |
| X25519 | RSA-2048 | ≈ 1 511 | 802 |
| X25519MLKEM768 | ML-DSA-65 | ≈ 1 923 | 5 531 |
| X25519 | ML-DSA-65 | ≈ 1 760 | 5 531 |
| X25519MLKEM768 | chaîne ML-DSA-65 (2 certificats) | ≈ 2 081 | 11 114 |
| X25519 | chaîne ML-DSA-65 (2 certificats) | ≈ 1 700 | 11 114 |

Le ClientHello passe de 221 à 1 397 octets avec l'échange hybride (+1 176 octets, la clé publique ML-KEM-768), et le rapport des médianes hybride / classique est d'environ 1,35 avec un certificat ECDSA. La chaîne ML-DSA-65 (racine, intermédiaire, feuille) multiplie la taille du message Certificate par 27 par rapport à ECDSA P-256.

Le surcoût de l'échange hybride est modéré : environ 240 µs par poignée de main avec un certificat ECDSA (+35 %) et 1 176 octets de plus dans le ClientHello. Pour la grande majorité des services, ce coût est négligeable devant la latence du réseau, et il protège dès aujourd'hui contre « enregistrer maintenant, déchiffrer plus tard » : c'est la première mesure à déployer. Les certificats post-quantiques coûtent davantage : passer d'un certificat ECDSA à un certificat ML-DSA-65 ajoute environ 1,1 ms en échange classique, et une chaîne ML-DSA complète pèse 11 114 octets contre 406. Cette taille compte plus que le temps de calcul : elle dépasse largement la taille d'un paquet (environ 1 500 octets), multiplie les fragments, se rapproche de la fenêtre de congestion initiale de TCP (une dizaine de segments) et pénalise les liaisons lentes ou mobiles. Ces mesures sont faites en boucle locale, sans latence ni perte : elles comparent les configurations entre elles mais sous-estiment l'effet de la taille sur un vrai réseau.

## 7.3 Signatures : ML-DSA-65 contre SLH-DSA

Mesure `bench_signatures` : moyenne sur trois répétitions de 100 opérations (`results/figures/signatures.svg`).

| Algorithme | Génération | Signature | Vérification | Clé publique | Signature |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | 0,24 ms | 1,07 ms | 0,24 ms | 1 952 o | 3 309 o |
| SLH-DSA-SHA2-128s | 66,4 ms | 509 ms | 0,54 ms | 32 o | 7 856 o |
| SLH-DSA-SHA2-128f | 1,05 ms | 24,2 ms | 1,45 ms | 32 o | 17 088 o |

**Hypothèses de sécurité.** ML-DSA (FIPS 204) repose sur la difficulté supposée de problèmes sur des réseaux euclidiens structurés, Module-LWE et Module-SIS : aucun algorithme, classique ou quantique, ne les résout efficacement à ce jour, mais ces hypothèses sont récentes à l'échelle de la cryptographie et leur structure algébrique pourrait un jour être exploitée. SLH-DSA (FIPS 205, issu de SPHINCS+) ne repose que sur les propriétés d'une fonction de hachage (résistance aux préimages et aux secondes préimages) : c'est l'hypothèse la plus ancienne et la mieux comprise, sur laquelle les ordinateurs quantiques n'ont qu'un effet de type Grover. SLH-DSA est donc considéré comme plus conservateur.

**Coût.** Cette prudence se paie, comme le montre le tableau : la variante « s » (petite signature) signe en environ 0,5 s avec une signature de 7 856 octets ; la variante « f » (rapide) signe en 24 ms mais produit 17 088 octets. ML-DSA-65 signe en environ 1 ms avec 3 309 octets. Les deux familles vérifient rapidement, et SLH-DSA a une clé publique minuscule (32 octets). La comparaison n'est pas à niveau de sécurité égal : ML-DSA-65 vise la catégorie 3 du NIST et SLH-DSA-128 la catégorie 1.

**Choix.** ML-DSA convient aux usages fréquents et sensibles à la taille, comme les certificats TLS et les signatures émises en grand nombre. SLH-DSA convient aux signatures rares, à très longue durée de vie et peu sensibles au temps de signature, comme une autorité racine, la signature de logiciels ou d'archives, lorsque l'on veut dépendre de l'hypothèse la plus sûre.

# 8. Ingénierie des prompts et de la boucle

Chaque prompt est versionné et chaque changement est consigné avec son effet mesuré (`docs/journal_des_prompts.md`). Évolution sur le SI v1 :

| Version | Changement principal | Rappel | Effet observé |
| --- | --- | --- | --- |
| v1 | première version | 24,7 % | contexte saturé, délai dépassé ; l'Analyste met x = 10 partout |
| v2 | budget de contexte, mémoire de travail | 95,9 % | exclusions abusives, un fichier lu avec le mauvais outil |
| v3 | garde-fous de fin (le code refuse une fin prématurée) | 100 % | l'Analyste n'évalue que 39 actifs sur 78 |
| v4 | Analyste : fenêtre d'un échange, mémoire impérative | 100 % | 78/78 évalués ; plan refusé (21 critiques) |
| v5 | critique = Shor ET en danger ; refus rappelé à l'Architecte | 100 % | 7 critiques ; plan conforme au premier essai |
| v6 | Inventoriste : chemins issus de `lister_fichiers` | 100 % | pas de baisse des erreurs (3 → 7), analysée |

Avec un petit modèle, les gains les plus nets ne sont pas venus des formulations du prompt mais du code autour du modèle : budget de contexte, mémoire calculée, refus motivés. La v6 est un exemple de modification de prompt sans effet mesuré, publiée comme telle.

**Deux étapes vécues.** Le passage de la v1 à la v2 a montré que le premier problème n'était pas la consigne mais la quantité de texte envoyée au modèle : en v1, la conversation dépassait la fenêtre de contexte, Ollama dépassait son délai et l'inventaire s'arrêtait à un quart du SI. Une fois le contexte budgété par le code et une mémoire de travail ajoutée, le rappel est passé à 95,9 % sans changement majeur du prompt. Le passage de la v3 à la v4 a confirmé cette leçon sur un autre agent : l'Analyste rendait sa réponse finale trop tôt, et le refus du code n'y changeait rien, car il relisait dans son historique ses anciennes réponses refusées et les recopiait. Réduire sa fenêtre à un seul échange et lui indiquer explicitement « il reste N actifs, ne réponds pas par le JSON final » a suffi à obtenir 78 actifs évalués sur 78. Dans les deux cas, la correction efficace a porté sur ce que le modèle voit, plus que sur la façon dont la consigne est formulée.

# 9. Évaluation

## 9.1 Protocole

- **Mesures** : appariement un à un des composants du CBOM aux actifs de la vérité terrain (même type CycloneDX, même emplacement, recouvrement des mots) ; rappel global, des actifs cachés et par périmètre ; précision stricte et hors doublons ; F1 ; classement de l'exposition à Shor ; conformité du plan ; leurres touchés (faux positifs certains).
- **Ablation** (sujet §6.2) : (a) sans modèle de langage, sous deux formes (outils seuls avec heuristique codée en dur ; agents à règles fixes) ; (b) le système avec qwen3:4b-instruct (8 Go) ; (c) un second modèle de taille différente.
- **Répétitions** : trois exécutions par configuration dépendant du modèle.
- **Même machine** pour toutes les exécutions d'une même comparaison.

## 9.2 SI de développement (v1)

Valeurs exactes dans `AUDIT.md`, section 3.

| Configuration | Rappel | Précision stricte | F1 | Plan |
| --- | --- | --- | --- | --- |
| Outils seuls (a) | 98,6 % | 93,5 % | 0,960 | — |
| Agents à règles fixes (a) | 100 % | — | — | conforme |
| qwen3:4b (b), 3 exécutions identiques | 100 % | 92,4 % | 0,961 | conforme |
| qwen3:0.6b (c) | aucun CBOM produit | — | — | — |

Sur la v1, le modèle n'apporte qu'un actif aux outils seuls : QR-020, le lien entre la variable `KEYSTORE_PASS` d'un fichier `.env` et le conteneur PKCS#12 qu'elle ouvre. Le très petit modèle (0,6 milliard de paramètres) ne parvient pas à produire de sortie valide.

## 9.3 Variante non vue (v2)

Protocole détaillé et lecture complète : `docs/evaluation_v2.md`. Chiffres : `results/metrics.json`, section `inventaire_v2`.

| Configuration | Rappel | Connus (80) | Hors périmètre (20) | Précision stricte | F1 | Leurres touchés |
| --- | --- | --- | --- | --- | --- | --- |
| Outils seuls (a) | 79,0 % | 70 | 9 | 69,3 % | 0,738 | 3 |
| Agents à règles fixes (a) | 33,0 % | 28 | 5 | 71,7 % | 0,452 | 0 |
| qwen3:4b, 90 étapes (b), 3 exécutions | 57,0 % ± 0 | 51 | 6 | 73,1 % ± 0 | 0,640 ± 0 | 0 |
| qwen3:4b, 162 étapes, a posteriori | 79,0 % | 70 | 9 | 68,7 % | 0,735 | 3 |

**Répétitions.** Les trois exécutions avec le modèle sont identiques au caractère près : mêmes 103 appels d'outils, mêmes sorties, même plan. À température 0 et graine fixe, le modèle est déterministe sur cette machine ; l'écart type est nul.

**Ce qui s'est passé.** Les agents à règles fixes passent de 100 % à 33 % : leurs règles dépendaient des noms de fichiers de la v1. Le système avec modèle s'arrête sur sa limite de 90 étapes, réglée sur la v1, sans avoir ouvert 35 fichiers sur 95 (tout le code Python). Sa meilleure précision vient de là : il ne touche aucun leurre parce qu'il n'a jamais ouvert les fichiers qui les contiennent.

**Expérience a posteriori.** Pour savoir si la perte venait du budget ou de la stratégie, une seule valeur a été changée : un budget proportionnel au nombre de fichiers, ⌈1,7 × fichiers⌉, règle fixée sur la v1 seule (au plus 1,46 étape par fichier observée) et décidée avant l'exécution, soit 162 étapes. L'agent ouvre alors 94 fichiers sur 95 et retrouve exactement les 79 actifs des outils seuls : mêmes 21 manqués, mêmes trois leurres touchés, aucun lien entre fichiers. Il atteint encore la limite, car il rescanne un par un les fichiers d'un dossier déjà analysé en bloc (35 appels en double), pour 82 minutes de calcul contre moins d'une seconde.

**Prédiction et résultat.** La prédiction écrite avant l'exécution était que l'agent lirait tous les fichiers et que le score augmenterait. Elle se vérifie : 94 fichiers sur 95 sont ouverts et le rappel remonte de 57 % à 79 %, ce qui est cohérent avec une perte due au budget. L'expérience révèle en revanche un défaut d'utilisation des outils : le modèle dispose d'outils capables d'analyser un dossier entier en un appel, et son prompt le lui indique, mais il continue de traiter les fichiers un par un, au point d'atteindre encore la limite d'étapes. Le gain vient donc d'un budget plus large, non d'une stratégie plus efficace.

## 9.4 Ablation (c) : second modèle

L'ablation (c) n'a pas pu être menée avec un second modèle de taille comparable dans les délais du projet. Le seul second modèle exécuté est qwen3:0.6b, sur le SI v1 (chaîne complète, rejouée en intégration continue) : il ne produit aucun CBOM valide et s'arrête sur une sortie invalide. Ce résultat montre qu'en dessous d'une certaine taille le modèle ne sait plus suivre le protocole d'appel d'outils, mais il ne permet pas de comparer la qualité de l'inventaire entre deux modèles capables. C'est un point faible de l'évaluation : la comparaison qwen3:4b contre un modèle de 3 à 8 milliards de paramètres (llama3.2:3b, qwen3:8b) reste à faire.

## 9.5 Conclusion sur l'apport mesuré des agents

| Sur… | Apport mesuré des agents |
| --- | --- |
| l'inventaire du SI de développement | faible : un actif de plus que les outils seuls (QR-020) |
| l'inventaire du SI non vu | nul avec un budget suffisant ; négatif (−22 actifs) avec le budget réglé sur la v1 |
| le plan de migration | réel : plan priorisé, conforme, démontré au laboratoire, stable sur trois répétitions ; les outils seuls n'en produisent pas |

Les 21 actifs que personne ne trouve sur la v2 sont des limites d'outils : directives d'une technologie connue absentes de la v1 (`ssl_dhparam`, `proxy_ssl_ciphers`, `ssl_conf_command`), nouvelles cachettes (`Include sshd_config.d/*.conf` avec bloc `Match`, clé PEM dans une chaîne Python, valeur par défaut d'une variable shell) et technologies hors périmètre par construction.

**Conclusion sur l'apport des agents.** Avec un modèle de 4 milliards de paramètres, l'apport mesuré des agents à l'inventaire est faible sur le SI de développement et nul sur le SI non vu, pour un coût en temps très supérieur à celui des outils seuls ; leur apport réel porte sur le plan de migration. Ce constat est lié aux limites du modèle employé : fenêtre de contexte réduite et faible capacité à relier des informations dispersées. Un modèle nettement plus grand, quitte à être plus lent (par exemple chargé partiellement en mémoire), apporterait davantage de contexte et de raisonnement, et devrait mieux relier les fichiers entre eux ; cette hypothèse n'est pas mesurée ici. Dans tous les cas, le parcours exhaustif des fichiers et tous les calculs doivent rester confiés au code et aux outils, seuls garants de l'absence d'hallucination. La valeur spécifique d'un système agentique se situe dans les actifs dissimulés entre plusieurs fichiers, qui peuvent cacher un risque post-quantique sérieux, comme le lien entre `KEYSTORE_PASS` et le conteneur PKCS#12 du SI v1 (QR-020), que seul l'agent a trouvé. Une architecture plus efficace laisserait le code parcourir tout le SI et réserverait le modèle à ces liens et à la rédaction du plan.

# 10. Modèle de menace du système multi-agents

Le système lui-même est analysé selon STRIDE (`docs/menace_stride.md`) ; chaque contre-mesure renvoie à un test, et un test vérifie que les tests cités existent.

| Catégorie | Menace principale | Contre-mesure | Limite |
| --- | --- | --- | --- |
| Usurpation | un agent appelle l'outil d'un autre | serveur MCP par agent, liste fermée, refus journalisé | nom d'agent non signé |
| Altération | le modèle modifie le SI ; CBOM ou plan invalides | aucun outil n'écrit dans le SI ; revalidation par le code | le sens complet d'un plan n'est pas vérifié |
| Répudiation | impossible d'attribuer un résultat | journal de chaque appel et de chaque tour, rejeu | messages envoyés au modèle non journalisés en entier |
| Divulgation | un secret dans les journaux ou le dépôt | secrets décrits, jamais recopiés ; gitleaks en CI | relecture des traces non automatisée |
| Déni de service | outil bloqué, modèle qui boucle | délai par outil, limite d'étapes, cache des doublons | — |
| Élévation | commande système arbitraire, scan hors laboratoire | arguments Docker fixes sans shell ; cible non locale refusée | pas de contrôle de la résolution DNS |

**Injection indirecte.** Un fichier du SI peut contenir une consigne piégée. Le texte d'un outil est rangé comme donnée, la liste d'outils est fermée côté serveur et la sortie finale est validée par le code. La fréquence à laquelle le modèle suivrait réellement une consigne piégée n'est pas mesurée.

**Menace prioritaire : l'injection de consignes.** Pour un outil de ce type déployé en entreprise, la menace la plus sérieuse est l'injection de consignes indirecte (risque LLM01 du Top 10 OWASP pour les applications à base de LLM). Le système lit par construction des fichiers qu'il ne contrôle pas ; un seul fichier piégé dans le SI analysé peut contenir une consigne cachée. Si un agent disposait d'un accès direct au SI, cette consigne pourrait l'amener à modifier du code, une configuration ou une clé sans qu'aucun ordre légitime ne l'ait demandé, et à compromettre le système qu'il devait auditer. La contre-mesure essentielle est donc architecturale, et non une meilleure consigne : les agents sont isolés, ne voient le SI qu'à travers des outils, et ces outils sont en lecture seule, à liste fermée par agent et contrôlés côté serveur. Même un agent entièrement manipulé ne peut ainsi rien écrire dans le SI ; le pire effet possible est un inventaire ou un plan faux, que le code et la validation humaine peuvent encore rattraper.

# 11. Robustesse aux défaillances

Des fautes sont injectées dans des tests automatisés (`tests/test_pannes.py`, `tests/test_boucle_agent.py`, `tests/test_orchestrateur.py`) : outil en échec (erreur lisible renvoyée à l'agent), outil hors délai (120 s, transformé en erreur), sortie JSON invalide (corrigée au plus deux fois, puis arrêt « sortie\_invalide »), réponse vide, modèle injoignable (arrêt propre et journalisé). L'orchestrateur réessaie (CBOM, plan), se replie (inventaire partiel quand la limite d'étapes est atteinte, comme sur la v2) ou s'arrête proprement.

# 12. Reproductibilité et science ouverte

- **Commande unique** : `make reproduce` (ou `uv run python scripts/reproduire.py`, identique sous Windows) installe l'environnement figé (`uv.lock`), valide la vérité terrain, génère le SI, le vérifie actif par actif et lance les tests avec un seuil de couverture de 70 %. Une image Docker fait la même chose sur une machine vierge.
- **Paramètres déclarés** : `config/experiment.yaml` (modèle et empreinte, température 0, graine 42, contexte 4 096, version d'Ollama) ; environnement capturé dans `results/ENVIRONMENT.json`.
- **Résultats** : données brutes dans `results/raw/`, agrégats générés dans `results/metrics.json` (aucune valeur saisie à la main), figures régénérées par script, page de résultats générée et publiée sur GitHub Pages, traces de toutes les exécutions publiées, échecs compris.
- **Vérification** : rejeu des appels d'outils d'une session (`make rejeu`), réévaluation à l'identique depuis les traces (`make evaluer-v2`), procédure d'audit avec valeurs attendues et tolérances (`AUDIT.md`).
- **CI** (GitHub Actions) : reproduction sous Ubuntu, macOS et Windows, image Docker, laboratoire TLS, mesure hybride, chaîne complète avec qwen3:0.6b, intégrité des artefacts, gitleaks. Couverture mesurée par la CI : \[À COMPLÉTER : pourcentage affiché par la CI\].
- **Intégrité** : `SHA256SUMS` des artefacts publiés, signé avec minisign ; clé publique dans le dépôt. Version v1.0.0 archivée sur Zenodo : \[À COMPLÉTER : DOI\].

# 13. Limites et travaux futurs

- **Exigences non couvertes à la date du rapport** : feuille de route en trois vagues et diagramme de Gantt (§5.4 du sujet), tableau de bord HTML du CBOM (§5.5), ablation (c) avec un modèle de taille comparable, débit des connexions.
- **Budget d'étapes fixe** : réglé sur le SI de développement, il ne passe pas à l'échelle ; il devrait dépendre de la taille du SI, ou le parcours des fichiers devrait être fait par le code.
- **Outils** : détection de certains formats par le nom du fichier ; directives et API absentes de la v1 non reconnues.
- **Journal** : les messages envoyés au modèle ne sont pas consignés en entier, seulement leur nombre ; le journal n'est pas signé.
- **Mesures** : en boucle locale, sur une seule machine, sans charge ni latence réseau.
- **Biais de conception** : la variante v2 a été conçue par le même assistant que les outils.
- **x et y de Mosca** : choisis par le modèle, de façon grossière.

**Limite principale.** La contrainte la plus déterminante a été le temps disponible, à côté des cours et d'une alternance en entreprise. Avec une semaine de plus, la priorité serait de réaliser les deux exigences complémentaires manquantes (feuille de route en trois vagues et tableau de bord du CBOM), puis l'ablation (c) avec un modèle de taille comparable, et enfin de confier au code le parcours exhaustif des fichiers pour lever la dépendance au budget d'étapes.

# 14. Usage de l'IA générative

Le détail est déclaré dans `AI_USAGE.md`.

Un assistant de programmation fondé sur un grand modèle de langage a été utilisé tout au long du projet, à ma demande. Il a écrit une grande partie du code (agents, boucle d'agent, orchestrateur, outil d'évaluation, générateur du SI v2) et une partie de la documentation, dont un premier jet de ce rapport. J'ai fait ce choix pour ne pas consacrer le temps disponible, limité par mes cours et mon alternance, à écrire moi-même le SI fictif et l'ensemble du code, ce dont j'aurais été capable mais pas dans les délais impartis.

J'ai réalisé moi-même la PKI du SI v1 (`pki.py`) et sa vérité terrain, choisi les actifs plantés, pris les décisions de méthode (définition de la priorité critique, grille de crypto-agilité, vérification du plan, budget de l'expérience a posteriori), validé la liste des actifs du SI v2, lancé et lu toutes les expériences, et écrit mes prédictions avant chaque mesure. Surtout, j'ai vérifié à la main le fonctionnement de ce qui a été produit : le code, les CBOM obtenus, les traces des agents et les résultats annoncés. Cette vérification a représenté la part la plus importante de mon temps. Je reste responsable de l'intégralité du contenu déposé ; le détail est déclaré dans `AI_USAGE.md`.

# 15. Conclusion

Ce projet a produit un copilote multi-agents complet, exécutable sur un ordinateur portable sans GPU : inventaire cryptographique et CBOM CycloneDX 1.6 valide, analyse de risque selon Mosca, plan de migration vérifié au laboratoire, démonstrateur TLS 1.3 et SSH hybride avec mesures, et une chaîne de reproduction et d'audit publique.

Il montre surtout deux choses. D'abord, avec un petit modèle, la fiabilité vient du code qui entoure le modèle plus que du modèle lui-même : budget de contexte, mémoire calculée, refus motivés et outils déterministes ont fait passer le rappel de 24,7 % à 100 % sur le SI de développement. Ensuite, un seul SI de test ne suffit pas : la variante non vue a révélé un budget d'étapes réglé sur le développement, des agents à règles qui avaient appris les noms de fichiers, et un modèle qui, à budget suffisant, n'apporte rien de plus que ses outils.

J'en retiens qu'un agent doit être conçu comme un composant faillible, encadré par du code qui vérifie tout ce qui peut l'être, et qu'il faut mesurer son apport plutôt que le supposer. Je reste convaincu que l'approche a de l'avenir pour relier des indices dispersés dans un grand SI, à condition de disposer d'un modèle plus capable et de conserver cette architecture où le modèle décide et explique, et où le code calcule.

# Annexe A — Commandes principales

```
make reproduce                 # reproduction complète sans modèle (environnement, SI, tests)
make installer-modele          # Ollama et le modèle figé
make agents                    # système multi-agents sur le SI v1
make si-v2 && make verifier-si-v2
make evaluer-v2                # réévalue les sessions v2 depuis leurs traces
make rejeu SESSION=traces/<session>
make metriques                 # results/metrics.json, figures, ENVIRONMENT.json
make demonstrateur             # laboratoire TLS et SSH hybride (Docker)
```

# Annexe B — Correspondance avec les exigences du sujet

| Exigence | Où |
| --- | --- |
| SI fictif, ≥ 40 actifs dont 10 cachés | §4, `data/ground_truth/` |
| Outils MCP testés | §3.2, `src/quantum_ready/outils/`, `serveur_mcp/` |
| 5 agents orchestrés, validation humaine, journal JSONL | §3 |
| Démonstrateur TLS 1.3 X25519MLKEM768, ML-DSA-65, comparaisons | §7 |
| SLH-DSA, chaîne ML-DSA, SSH hybride | §7.2, §7.3, §7.1 |
| Crypto-agilité par actif | §6.3 |
| Feuille de route 3 vagues, tableau de bord | §6.4 (non réalisé) |
| 2 variantes, 3 répétitions | §4.2, §9 |
| Modèle de menace, ablation, robustesse | §10, §9, §11 |
| Prompts versionnés avec effet mesuré | §8 |
| SYSTEM\_CARD, page de résultats, CLI de rejeu | `SYSTEM_CARD.md`, GitHub Pages, `make rejeu` |
| Science ouverte | §12 |
