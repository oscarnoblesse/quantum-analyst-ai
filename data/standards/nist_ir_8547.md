id: NIST-IR-8547
titre: NIST IR 8547 (projet) — Transition to Post-Quantum Cryptography Standards
source: https://csrc.nist.gov/pubs/ir/8547/ipd
date: 2024-11

Le projet de rapport NIST IR 8547 propose un calendrier de transition : les algorithmes vulnérables au quantique (RSA, ECDSA, EdDSA, DH, ECDH) offrant 112 bits de sécurité seraient dépréciés après 2030 et interdits après 2035 ; les variantes plus fortes seraient interdites après 2035.

Le document recommande de commencer immédiatement l'inventaire et la migration, en priorité pour les données qui doivent rester confidentielles longtemps, à cause de la menace « enregistrer maintenant, déchiffrer plus tard ».

Pour la cryptographie symétrique, le NIST considère qu'AES-128, AES-192 et AES-256 restent utilisables ; l'algorithme de Grover n'impose pas de remplacement, seulement une marge sur la taille des clés.
