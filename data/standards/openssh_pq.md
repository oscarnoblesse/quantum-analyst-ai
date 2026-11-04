id: OPENSSH-PQ
titre: OpenSSH — Échange de clés post-quantique hybride
source: https://www.openssh.com/pq.html
date: 2022-2025

OpenSSH 9.0 a fait de sntrup761x25519-sha512 (hybride NTRU Prime et X25519) l'échange de clés par défaut. OpenSSH 9.9 a ajouté mlkem768x25519-sha256 (hybride ML-KEM-768 et X25519), qui devient l'échange par défaut avec OpenSSH 10.0.

Une liste KexAlgorithms écrite à la main dans sshd_config remplace la liste par défaut : si elle omet ces algorithmes hybrides, elle désactive la protection post-quantique pourtant fournie par la version installée. Correction : retirer la directive ou y placer mlkem768x25519-sha256 en tête.

Les clés d'hôte et d'utilisateur (Ed25519, ECDSA, RSA) servent à l'authentification ; leur remplacement par des algorithmes post-quantiques est moins urgent que celui de l'échange de clés. Les clés DSA et les algorithmes ssh-rsa (SHA-1) sont à retirer dès maintenant pour des raisons classiques.
