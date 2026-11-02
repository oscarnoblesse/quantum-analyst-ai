# Quantum-Ready — Périmètre technologique et validation des outils d'inventaire

*Licence : CC BY 4.0 — Oscar Noblesse, 2026*

## Objet

Ce document fixe le **périmètre technologique** des outils déterministes de l'Inventoriste, et décrit la **démarche suivie pour vérifier qu'ils ne sont pas adaptés au seul SI fictif de développement**. Il consigne les résultats obtenus le 2 novembre 2026, les décisions qui en découlent et les limites connues.

Il complète `docs/regles_verite_terrain.md`, qui définit ce qu'est un actif et comment la vérité terrain est construite.

## Contexte et risque traité

Les outils d'inventaire ont été écrits en même temps que le SI fictif v1, à partir de ses fichiers. Ce mode de développement expose à un biais : des outils qui reconnaissent **ce SI-là** plutôt que **les formats** qu'il contient. Un tel biais ne se voit pas sur le SI v1 (le rappel y est maximal par construction), mais il ferait échouer l'évaluation de robustesse exigée par le sujet, menée sur une seconde variante du SI non vue pendant le développement.

La question posée est donc : *un outil qui lit une configuration nginx lit-il n'importe quelle configuration nginx, ou seulement celle du SI v1 ?*

## Ligne de conduite

1. **Un outil analyse un format, pas un SI.** Il est écrit d'après la grammaire et la documentation du format (ou du langage), jamais d'après les noms de fichiers, les valeurs ou la disposition du SI v1.
2. **Le périmètre est fermé et explicite.** Seules les technologies présentes dans le SI fictif (liste ci-dessous) disposent d'un analyseur dédié. Le projet ne cherche pas à couvrir tous les formats existants : ce serait divaguer hors du sujet et dégrader la qualité des analyseurs existants.
3. **Un angle mort est signalé, jamais passé sous silence.** Un fichier dont le format n'a pas d'analyseur dédié est déclaré comme tel par `lister_fichiers` (champ `remarque`) et confié à un outil de repli textuel, `rechercher_algorithmes`, dont les résultats sont des indices à confirmer par l'agent.
4. **Une valeur par défaut n'est jamais supposée en silence.** Lorsqu'un actif implicite dépend d'une version (OpenSSH, OpenSSL, nginx), la version est lue dans le SI ou fournie par l'agent. À défaut, la trouvaille porte la mention « HYPOTHÈSE ».
5. **Une mesure n'est pas suivie d'un réglage sur le jeu mesuré.** Un SI utilisé pour mesurer, puis pour corriger les outils, devient un jeu de développement. Seul un SI jamais consulté pendant le développement peut servir à l'évaluation finale.
6. **L'extension du périmètre est un travail ultérieur.** Elle est possible sans refonte (voir « Évolutions possibles ») mais n'est pas engagée dans la version 1.0.

## Périmètre technologique

### Technologies du SI fictif, analyseur dédié

| Technologie | Fichiers reconnus (par leur contenu) | Outil | Ce qui est extrait |
| --- | --- | --- | --- |
| Certificats X.509 | PEM (un ou plusieurs par fichier), DER | `analyser_x509` | Certificat, clé publique, algorithme de signature ; faiblesses classiques ; empreintes |
| Clés | PEM (PKCS#8, traditionnel, chiffré), OpenSSH, clés publiques SSH (`.pub`, `authorized_keys`, `known_hosts`), OpenPGP, paramètres DH | `analyser_cle` | Type, taille, chiffrement, empreinte identique à `ssh-keygen -l` |
| PKCS#12 | `.p12`, `.pfx` | `analyser_pkcs12` | Algorithmes de chiffrement et MAC sans mot de passe ; contenu avec le mot de passe, lu par l'outil sans être renvoyé |
| nginx | Configuration principale et fichiers inclus | `analyser_configuration` | Par bloc `server` : versions TLS, suites (macros développées par OpenSSL), groupes ECDHE, tickets, suites TLS 1.3 implicites |
| OpenSSH | `sshd_config` (serveur), `ssh_config` et `~/.ssh/config` (client) | `analyser_configuration` | Listes effectives (`+`, `-`, `^`), valeurs par défaut selon la version, retrait d'un échange post-quantique |
| PostgreSQL | `postgresql.conf`, `pg_hba.conf` | `analyser_configuration` | Version TLS minimale, suites, groupe ECDHE, méthodes d'authentification |
| Variables d'environnement | `.env` | `analyser_configuration` | Secrets décrits par leur forme (jamais recopiés), URL de connexion et `sslmode`, algorithmes configurés |
| Image de conteneur | `Dockerfile` | `analyser_configuration` | Versions figées des logiciels cryptographiques, fichiers copiés dans l'image |
| Scripts shell | `#!/bin/sh`, `#!/bin/bash` | `analyser_configuration` | `gpg`, `openssl`, `ssh-keygen`, `*sum` ; durée de conservation des données |
| Python (code) | `.py` | `scanner_code_crypto` | Usages de `hashlib`, `hmac`, `random`/`secrets`, `cryptography`, `pycryptodome`, `argon2`, `pyjwt`, `ssl`, `paramiko` ; clés en dur ; vérifications TLS désactivées ; code mort |
| Python (dépendances) | `pyproject.toml`, `uv.lock` | `analyser_dependances` | Bibliothèques cryptographiques déclarées, verrouillées, transitives et réellement importées ; versions vulnérables connues |

### Formats voisins, pris en charge à titre secondaire

Les formats suivants ne figurent pas dans le SI v1. Ils ont été ajoutés parce qu'ils sont d'usage très courant et que leur prise en charge réutilise un analyseur existant sans le modifier en profondeur : Apache httpd (mod_ssl), YAML et JSON (aplatis puis analysés comme un `.env`), `requirements.txt` et `poetry.lock`. Ils sont testés, mais n'ont pas fait l'objet d'une vérité terrain.

### Hors périmètre de la version 1.0

Sans analyseur dédié, couverts uniquement par le repli textuel : code Java, Go, C, JavaScript ; dépendances npm (`package.json`) ; Postfix, Dovecot, HAProxy, OpenVPN, WireGuard ; fichiers `.properties` ; configuration du client SSH (`~/.ssh/config`) ; magasins Java (JKS) ; balayage réseau d'un serveur TLS en fonctionnement (`scan_tls_lab`, prévu avec le démonstrateur).

## Démarche de validation

La validation repose sur trois SI fictifs de composition croissante en écart avec le SI de développement. Dans tous les cas, les outils sont exécutés **à l'aveugle** : chaque fichier est analysé par l'outil que conseille `lister_fichiers`, sans agent ni intervention. Cette exécution sert aussi de référence pour l'étude d'ablation (outils seuls, sans modèle de langage).

| SI | Rôle | Composition | Référence |
| --- | --- | --- | --- |
| A — SI v1 | Développement | API Python, nginx, SSH, PostgreSQL, PKI, factures, sauvegardes (52 fichiers) | Vérité terrain, 73 actifs |
| B — SI « étranger » | Détection du surajustement | Mêmes familles de technologies, écrites autrement, plus quelques formats inattendus (11 fichiers) | Revue manuelle |
| C — SI sans rapport | Mesure de généralisation | Autre domaine et autres composants (20 fichiers) | 47 actifs attendus, figés avant exécution |

Le protocole de mesure du SI C :

1. Le SI C est construit, puis la liste des actifs attendus est rédigée avec, pour chacun, un critère de correspondance. Cette liste est figée (empreinte SHA-256 `bbbcb884119f5f6105cc578c4e22a1e265fdd28bc8460c17df5f63f36b137f23`) **avant** toute exécution des outils.
2. Les outils sont exécutés à l'aveugle.
3. Chaque correspondance est ensuite vérifiée manuellement : une trouvaille qui satisfait le critère pour une mauvaise raison est comptée comme ratée.
4. Aucun outil n'est corrigé après la mesure.

## Résultats

### SI B : surajustement constaté, puis corrigé

Le SI B a mis en évidence des défauts qui n'apparaissaient pas sur le SI v1 :

- un certificat DER reconnu comme un conteneur PKCS#12, et un fichier Java comme du code Python ;
- un analyseur nginx qui fusionnait les blocs `server`, ne suivait pas les `include` (l'échange hybride `X25519MLKEM768` d'un fragment inclus était ignoré) et ne comprenait pas les valeurs entre guillemets ;
- des valeurs par défaut d'OpenSSH 9.6 appliquées sans connaître la version ;
- des règles Python limitées aux bibliothèques utilisées par l'API du SI v1 ;
- des fichiers de formats non pris en charge passés sous silence.

Ces défauts relèvent du premier principe de la ligne de conduite. Ils ont été corrigés sans élargir le périmètre (commits `44f9f9f` à `95ad3d9` de la branche `developpement_outils`, à partir de l'étiquette `outils-avant-generalisation`). Le SI v1 conserve un rappel de 73/73 et un CBOM valide.

### SI C : mesure de généralisation

| Résultat | Actifs | Part |
| --- | --- | --- |
| Trouvés correctement | 25 | 53 % |
| Trouvés partiellement (algorithme sans son mode ou sa taille) | 3 | 6 % |
| Satisfaisant le critère pour une mauvaise raison (comptés ratés) | 3 | 6 % |
| Ratés | 16 | 34 % |

Sur les formats du périmètre, les outils se comportent sur le SI C comme sur le SI v1 : certificats PEM et DER, clés quel que soit le nom du fichier, PKCS#12, paramètres DH, `.env`, scripts shell et listes d'algorithmes OpenSSH ont tous été inventoriés. Les ratés se répartissent ainsi :

| Cause | Nombre | Exemples |
| --- | --- | --- |
| Format hors périmètre, sans signal textuel exploitable | 10 | Clés WireGuard, niveau de suites Postfix, `InsecureSkipVerify` en Go, fichier `.properties` |
| Limite d'un analyseur du périmètre | 5 | Constantes de configuration Django (`SECRET_KEY`, `MD5PasswordHasher`) ; clé statique OpenVPN ignorée ; secret JWT en dur en JavaScript ; dépendances npm |
| Lien que seul l'agent peut établir | 1 | Clé du PKCS#12 Java, dont le mot de passe est dans un autre fichier |

**Conclusion.** Les outils ne sont pas spécifiques au SI v1 : leur couverture dépend des **formats** et non du SI. La baisse observée sur le SI C est attendue, car ce SI est composé majoritairement de technologies hors périmètre. Elle est conforme à la ligne de conduite : chaque fichier non couvert a été signalé, aucun n'a été ignoré en silence.

## Anomalies connues

| Anomalie | Format | Statut |
| --- | --- | --- |
| Un nom de paquet contenant « token » (`jsonwebtoken`) est pris pour un secret | JSON (secondaire) | Corrigé : un nom n'est un secret que si l'un de ses mots en est un, et jamais sous une liste de dépendances |
| Une configuration client SSH est analysée comme une configuration serveur | OpenSSH | Corrigé : la configuration client est reconnue et analysée par bloc `Host`, sans valeurs par défaut de serveur |
| La détection textuelle signale un protocole désactivé (`!SSLv2`, `no-sslv3`) comme une mention | Repli textuel | Accepté : limite propre à ce type d'outil, qui renvoie des indices à confirmer par l'agent |
| Une constante de module non passée à une fonction cryptographique n'est pas vue | Python | Accepté pour la version 1.0, à reconsidérer |
| Un bloc « OpenVPN Static key » est ignoré par le repli textuel | OpenVPN (hors périmètre) | Reporté |

Les deux anomalies du périmètre ont été corrigées après la mesure du SI C, comme corrections de bogues ; les résultats chiffrés ci-dessus restent ceux de la mesure, et le SI C est désormais un jeu de développement.

## Évolutions possibles

L'architecture permet d'étendre le périmètre après la version 1.0 sans modifier les outils existants : un nouveau format se traduit par un module dans `outils/configurations/` (ou un nouvel analyseur de langage), déclaré dans `lister_fichiers`. Un format n'est ajouté que s'il remplit les conditions suivantes :

1. sa grammaire est documentée et l'analyseur est écrit d'après elle ;
2. il est couvert par des tests unitaires ;
3. il est éprouvé sur un SI de développement qui le contient ;
4. il n'entraîne aucune régression sur le SI v1 (rappel, validité du CBOM).

Candidats identifiés, par intérêt pour l'inventaire post-quantique : dépendances npm, configuration client OpenSSH, Postfix et HAProxy, code Java ou Go (prolongement cité par le sujet).

## Limites de cette validation

- Les SI B et C ont été construits par l'auteur des outils : ils ne sont pas indépendants, ce qui tend à surestimer la généralisation. L'évaluation finale doit se faire sur une seconde variante du SI non consultée pendant le développement.
- Les SI B et C ne sont pas versionnés dans le dépôt à ce stade ; leur composition est décrite en annexe. S'ils sont intégrés plus tard, ce sera comme jeux de développement, puisqu'ils ont été consultés.
- Le SI C ayant servi à une mesure, il ne peut plus servir d'évaluation finale.
- Le rappel a été mesuré à l'aveugle, sans agent. La précision sera mesurée sur le CBOM final, une fois les agents en place.

## Annexe : composition des SI de validation

**SI B (11 fichiers)** : configuration nginx à deux blocs `server` et fragment inclus (`X25519MLKEM768`) ; configuration Apache ; `sshd_config` minimal (`aes128-cbc`, `3des-cbc`) ; `docker-compose.yml` (mot de passe MySQL, TLS désactivé) ; `requirements.txt` (pycryptodome 3.4.7) ; code Python (AES-ECB avec clé en dur, MD5 de mot de passe, `verify=False`) ; code Java (DES-ECB) ; YAML applicatif (secret et algorithme JWT) ; certificat DER ; clé RSA nommée `sauvegarde.txt`.

**SI C (20 fichiers)** : Postfix, Dovecot, OpenVPN (paramètres DH 1024 bits, clé statique), WireGuard, HAProxy (RC4, TLS 1.0) ; micrologiciel C (AES-ECB, clé en dur, MD5) ; passerelle Go (vérification TLS désactivée, RSA-1024, SHA-1) ; application Node.js (`package.json`, AES-128-CBC, JWT HS256) ; configuration Spring (`.properties`) et magasin PKCS#12 moderne ; réglages Django ; configuration client SSH (`group1-sha1`, `ssh-rsa`) ; script de sauvegarde (`openssl enc`, conservation de 20 ans) ; `.env` de production ; certificats ECDSA P-256 et RSA-2048 expiré ; clé privée chiffrée nommée `cle.bak`.
