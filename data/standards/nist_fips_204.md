id: NIST-FIPS-204
titre: FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
source: https://csrc.nist.gov/pubs/fips/204/final
date: 2024-08

ML-DSA est l'algorithme de signature numérique normalisé par le NIST en août 2024, issu de CRYSTALS-Dilithium. Il remplace RSA, DSA, ECDSA et EdDSA pour les signatures, que l'algorithme de Shor casse.

Trois jeux de paramètres : ML-DSA-44 (catégorie 2), ML-DSA-65 (catégorie 3) et ML-DSA-87 (catégorie 5). Les clés publiques et les signatures sont nettement plus grandes qu'en ECDSA (de l'ordre du kilo-octet), ce qui pèse sur les certificats et les chaînes de certification.

Usage : certificats X.509 (autorités et serveurs), signature de documents et de factures, signature de code, authentification de serveurs TLS et SSH.
