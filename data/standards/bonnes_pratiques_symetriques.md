id: SYMETRIQUE-ET-HACHAGE
titre: Cryptographie symétrique, hachage et secrets face au quantique — synthèse
source: https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
date: 2024

L'algorithme de Grover réduit de moitié, au mieux, la sécurité effective d'une clé symétrique : AES-256 conserve une marge confortable, AES-128 reste généralement jugé acceptable mais AES-256 est préférable pour les données à longue durée de vie. SHA-256 et HMAC-SHA-256 restent adaptés.

Les faiblesses classiques passent avant le quantique : MD5, SHA-1, DES, 3DES et RC4 sont à retirer quelle que soit la menace quantique ; un générateur d'aléa non cryptographique (random de Python) ne doit jamais produire de secret ; une comparaison de MAC doit être faite en temps constant.

Mots de passe : Argon2id (RFC 9106) avec des paramètres de mémoire suffisants ; un hachage rapide sans sel (SHA-256 seul, MD5) est à remplacer. Les secrets en clair dans des fichiers de configuration sont à déplacer dans un coffre-fort de secrets.

Conteneurs PKCS#12 : préférer PBES2 avec AES-256 et PBKDF2 (format par défaut d'OpenSSL 3) aux anciens formats 3DES et RC2 avec MAC SHA-1.
