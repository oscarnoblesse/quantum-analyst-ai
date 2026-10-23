# Quantum-Ready — Règles de la vérité terrain

*Licence : CC BY 4.0 — Oscar Noblesse, 2026*

## Objet

Ce document fixe les règles utilisées pour remplir la vérité terrain du SI fictif de Quantum-Ready : 70 actifs cryptographiques, dont 16 cachés.

La vérité terrain décrit ce qui a été **planté** dans le SI. Elle sert à **évaluer** les agents, en la comparant au CBOM CycloneDX 1.6 qu'ils produisent. Elle n'est pas le CBOM lui-même : elle contient des informations propres à l'évaluation (actif visible ou caché, risque attendu, liens entre actifs).

Le fichier de référence est `data/ground_truth/verite_terrain_v1.csv`. Il est validé et converti en `data/ground_truth/si_v1.json` par `make verite-terrain` (module `quantum_ready.verite_terrain`), et les règles ci-dessous sont vérifiées automatiquement par `tests/test_verite_terrain.py`.

## Qu'est-ce qu'un actif

Un actif est **un algorithme, une clé, un secret ou un paramètre cryptographique précis, à un endroit donné**. Un composant (« le tunnel SSH ») n'est pas un actif : il en contient plusieurs.

- Un certificat donne **trois actifs** : le certificat lui-même, sa clé publique et sa signature par l'émetteur.
- Une clé privée est un actif **distinct** de son certificat, car elle a une protection propre (en clair, chiffrée, droits du fichier) et un risque classique propre.
- Une directive de configuration est un actif seulement si elle **fait un choix cryptographique** (`ssl_protocols`, `KexAlgorithms`). Un simple pointeur vers un fichier (`ssl_certificate`) n'en est pas un.
- Un secret (mot de passe, clé symétrique) est un actif de type « matériel crypto lié », au sens de CycloneDX.
- Un actif **sans risque** fait partie de la vérité terrain : il doit être trouvé, puis classé comme sûr.
- Une clé privée prend le composant du service auquel elle donne accès, et non celui de son certificat : QR-047 dans nginx, QR-048 dans Base de données, QR-034 dans SSH, QR-049 dans nginx.
- Type CycloneDX : `protocol` pour les versions et les suites d'un protocole (`ssl_protocols`, `ssl_ciphers`, suites TLS 1.3, `sslmode`) ; `algorithm` pour une famille d'algorithmes configurée pour un travail précis (`ssl_ecdh_curve`, `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`) ou pour un algorithme de signature ; `certificate` pour chaque certificat X.509, parent de sa clé publique (`related-crypto-material`) et de son algorithme de signature (`algorithm`) ; `related-crypto-material` pour les clés, secrets et mots de passe ; `library` pour les bibliothèques et logiciels.

| Colonne | Contenu |
| --- | --- |
| ID | Identifiant unique, format QR-001 |
| Composant | Valeur courte et répétable : Certificats, nginx, SSH, Base de données, Factures, API, Dépendances |
| Fichier / emplacement | Chemin exact dans le SI ; plusieurs chemins si l'actif est copié |
| Actif | Ce qu'est l'élément crypto |
| Algorithme / paramètres | Valeur exacte telle qu'écrite dans le fichier, avec taille de clé et protection |
| Visible ou caché | Voir le critère « caché » |
| Vulnérable au quantique | Oui (Shor), Partiellement (Grover), Non, Indirect |
| Type de risque | Conséquence concrète, classique et/ou quantique |
| Notes | Liens avec d'autres actifs, conditions, champ X.509, cible de migration |
| Type CycloneDX | algorithm, certificate, protocol, related-crypto-material, library |

## Critère « caché »

Un actif est **caché** quand on ne peut pas le trouver en lisant un seul fichier ou en cherchant un mot-clé : il faut déployer, croiser ou raisonner. Tous les autres actifs sont **visibles**.

Un actif est classé caché s'il relève d'au moins une de ces catégories :

1. **Configuration indirecte** : l'algorithme est choisi hors du code, dans un `.env`, un YAML ou une macro à déployer (ex. `HIGH` dans `ssl_ciphers`).
2. **Actif implicite** : rien n'est écrit, c'est la valeur par défaut de la bibliothèque ou du logiciel qui s'applique (ex. suites TLS 1.3 d'OpenSSL).
3. **Croisement de fichiers** : le risque n'existe que si plusieurs fichiers sont lus ensemble (ex. TLS 1.2 + suite à échange RSA + certificat RSA).
4. **Code mort ou dépendance morte** : présent mais jamais appelé ou importé.
5. **Dépendance transitive** : absente des dépendances déclarées, visible seulement dans `uv.lock`.
6. **Emplacement trompeur** : fichier oublié, dossier ou nom inattendu, ou deuxième élément d'un fichier qui en contient plusieurs (bundle de certificats).
7. **Usage à interpréter** : une fonction banale (`random.choice`) qui produit en fait un secret.

La catégorie est écrite au début de la colonne Notes, sous la forme « Caché, <catégorie> : … ». Le code de validation refuse un actif caché sans catégorie reconnue.

## Vulnérabilité quantique

Cette colonne décrit l'**algorithme**, pas la situation : le risque réel se lit dans la colonne Type de risque.

| Valeur | Règle | Exemples |
| --- | --- | --- |
| Oui (Shor) | Algorithme asymétrique fondé sur la factorisation ou le logarithme discret | RSA, ECDSA, Ed25519, X25519, DH, GPG avec clé RSA |
| Partiellement (Grover) | Algorithme symétrique ou hash dont la sécurité après Grover tombe sous 128 bits | AES-128, MD5, 3DES |
| Non | Algorithme symétrique ou hash dont la sécurité après Grover reste ≥ 128 bits, ou secret sans algorithme asymétrique | AES-256, HMAC-SHA-256, Argon2id, mot de passe |
| Indirect | Actif qui n'est pas cassé lui-même, mais qui bloque ou affaiblit la migration post-quantique | TLS 1.2 autorisé, version d'OpenSSH, bibliothèque crypto |

Un actif « Non » au quantique peut être très risqué classiquement (ex. SHA-256 sans sel pour des mots de passe).

## Type de risque

Le type de risque décrit la **conséquence concrète** pour le SI, pas le moyen de l'attaque (« usurpation du serveur », et non « retrouver la clé privée »).

- Il nomme la propriété touchée : **confidentialité**, **authenticité** ou **intégrité**.
- Il distingue le risque **classique** (immédiat : fuite d'une clé, algorithme déjà faible) du risque **quantique** (après le Q-day). Une clé privée porte souvent les deux.
- Il indique si le **HNDL** s'applique : seulement pour la confidentialité de données capturées aujourd'hui (trafic enregistré, sauvegarde volée) et protégées par un algorithme asymétrique. Les signatures, l'authentification et les MAC n'y sont pas exposés.

Pour l'inégalité de Mosca (x + y > z), **x** est la durée pendant laquelle l'actif doit rester sûr (conservation des factures, validité d'un certificat, conservation des sauvegardes). La valeur de **z** retenue est une hypothèse, à justifier par une source dans le rapport.

## Actifs à plusieurs emplacements

Un même actif copié dans plusieurs fichiers occupe **une seule ligne**, avec tous ses emplacements dans la colonne Fichier. Exemple : la racine (QR-001) est dans `certs/ca/racine.crt`, `nginx/ssl/ca_clients.crt`, `db/tls/root.crt` et `api/config/ca_bundle.pem`.

- C'est la logique du CBOM, où un actif est décrit une fois avec ses occurrences. Le Cartographe ne doit pas le compter plusieurs fois.
- Plusieurs actifs différents dans un même fichier (clé publique et signature d'un certificat) occupent des lignes séparées, distinguées par la colonne Actif et par le champ X.509 en note (`subjectPublicKeyInfo`, `signatureAlgorithm`).
- Une directive qui ne fait que pointer vers un fichier (`ssl_certificate`, `ssl_certificate_key`) n'a pas de ligne : elle est mentionnée dans les notes de l'actif qu'elle référence.

## Clés volontairement absentes du SI

Trois clés privées sont générées par les scripts de PKI lancés par `make reproduce`, mais **ne figurent pas dans le SI scanné**, comme dans une vraie organisation où elles restent hors ligne :

- la clé privée de l'AC racine ;
- la clé privée de l'AC intermédiaire ;
- la clé privée GPG de déchiffrement des sauvegardes.

Elles n'ont donc pas de ligne dans la vérité terrain. Les scripts de PKI sont dans un dossier séparé, exclu du périmètre des agents.

**Exception plantée** : une copie oubliée de la clé de l'intermédiaire se trouve dans `deploy/old/backup_2024/inter.key` (QR-046). C'est un actif caché critique, à risque classique immédiat.

Aucune clé réelle n'est commitée : toutes les clés et tous les secrets du SI sont factices et générés par script, pour que gitleaks ne signale rien.

## Arborescence du SI fictif

Chaque dossier représente une machine ou un composant du SI. Les noms de dossiers sont volontairement hétérogènes (`ssl/`, `tls/`, `keys/`), comme dans un vrai SI : les agents doivent se fier au **contenu** des fichiers, pas à leur nom.

| Dossier | Représente |
| --- | --- |
| `certs/ca/` | Certificats publics de l'AC (racine, intermédiaire) |
| `nginx/` | Serveur web : front, reverse proxy vers l'API, terminaison TLS |
| `api/` | API Python et sa configuration (`.env`, magasin de confiance) |
| `db/` | Serveur de base de données PostgreSQL |
| `factures/` | Module de signature des factures |
| `ssh/server/` | Serveur SSH (config, clés d'hôte, `authorized_keys`) |
| `clients/admin/` | Poste de travail de l'admin (certificat mTLS, clé SSH, `known_hosts`) : il fait partie du SI, mais n'est pas un serveur |
| `scripts/` | Tâches planifiées (sauvegardes) et scripts de déploiement |
| `deploy/old/` | Vestiges d'anciens déploiements |

La 2ᵉ variante du SI, non vue pendant le développement, reprend cette structure en faisant varier les actifs et leurs conditions.

## Ce que l'évaluation mesurera

La comparaison entre le CBOM des agents et la vérité terrain porte sur **deux niveaux distincts** :

1. **Inventaire** : l'actif a-t-il été trouvé ? Rappel = actifs plantés trouvés / actifs plantés ; précision = trouvailles correspondant à un actif planté / trouvailles.
2. **Diagnostic** : pour chaque actif trouvé, la vulnérabilité et le type de risque attribués correspondent-ils à la vérité terrain ?

Les résultats sont aussi détaillés par composant et pour les actifs cachés seuls.

**Pièges de précision** : certains actifs ressemblent à des problèmes sans en être. Ils doivent être inventoriés **et** classés comme sûrs ou peu risqués. Les signaler comme vulnérables est une erreur de diagnostic.

- QR-055 : `random.SystemRandom`, sûr malgré le nom du module.
- QR-059 : MD5 utilisé comme simple clé de cache, sans rôle de sécurité.
- QR-029 : MAC HMAC-SHA-256/512, sans risque quantique.
