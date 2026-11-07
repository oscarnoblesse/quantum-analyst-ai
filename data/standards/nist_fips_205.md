id: NIST-FIPS-205
titre: FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)
source: https://csrc.nist.gov/pubs/fips/205/final
date: 2024-08

SLH-DSA est un algorithme de signature fondé uniquement sur des fonctions de hachage, issu de SPHINCS+. Sa sécurité repose sur des hypothèses très conservatrices, au prix de signatures volumineuses et d'une signature plus lente.

Usage conseillé : signatures qui doivent rester vérifiables très longtemps ou pour lesquelles une seconde famille d'hypothèses est souhaitée en complément de ML-DSA (racines de confiance, archives signées sur plusieurs décennies).
