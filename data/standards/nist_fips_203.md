id: NIST-FIPS-203
titre: FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
source: https://csrc.nist.gov/pubs/fips/203/final
date: 2024-08

ML-KEM est le mécanisme d'encapsulation de clés normalisé par le NIST en août 2024, issu de CRYSTALS-Kyber. Il remplace les échanges de clés fondés sur RSA, Diffie-Hellman et les courbes elliptiques (ECDH, X25519), que l'algorithme de Shor casse.

Trois jeux de paramètres sont définis : ML-KEM-512 (catégorie de sécurité 1), ML-KEM-768 (catégorie 3) et ML-KEM-1024 (catégorie 5). ML-KEM-768 est le choix courant pour TLS et SSH.

Usage : établissement de secrets partagés (échange de clés TLS, SSH, chiffrement hybride de fichiers). ML-KEM ne signe pas : l'authentification relève de ML-DSA ou SLH-DSA.
