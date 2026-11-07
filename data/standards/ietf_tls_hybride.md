id: IETF-TLS-HYBRIDE
titre: IETF — Échange de clés hybride ECDHE-MLKEM pour TLS 1.3 (X25519MLKEM768)
source: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
date: 2024-2025

Le groupe X25519MLKEM768 combine X25519 et ML-KEM-768 dans l'échange de clés de TLS 1.3 : le secret de session reste sûr tant que l'un des deux algorithmes n'est pas cassé. C'est la réponse directe à la menace « enregistrer maintenant, déchiffrer plus tard » sur les sessions TLS.

Ce groupe est pris en charge par les navigateurs récents et par OpenSSL à partir de la version 3.5, qui le propose par défaut. Côté serveur, il suffit en général de mettre à jour OpenSSL et d'inclure X25519MLKEM768 dans la liste des groupes (ssl_ecdh_curve pour nginx, SSLOpenSSLConfCmd Groups pour Apache).

L'hybridation de l'échange de clés ne protège pas l'authentification : les certificats RSA ou ECDSA du serveur restent à migrer vers ML-DSA, ce qui est moins urgent car une signature ne peut pas être cassée rétroactivement pour une session passée.

TLS 1.2 et les suites à échange de clés RSA (sans confidentialité persistante) sont à désactiver : un attaquant qui obtiendra la clé RSA du serveur pourra déchiffrer toutes les sessions enregistrées.
