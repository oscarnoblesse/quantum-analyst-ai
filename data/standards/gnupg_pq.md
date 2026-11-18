id: GNUPG-PQ
titre: GnuPG — Chiffrement post-quantique hybride (série 2.5)
source: https://gnupg.org/ (annonces de la série 2.5)
date: 2024

La série de développement GnuPG 2.5 introduit le chiffrement hybride combinant ML-KEM (Kyber) et une courbe elliptique classique, pour protéger les données chiffrées à long terme contre un déchiffrement futur.

Des sauvegardes chiffrées aujourd'hui pour une clé RSA et conservées de nombreuses années sont exposées à la menace « enregistrer maintenant, déchiffrer plus tard » : elles doivent être rechiffrées pour une clé hybride, ce qui suppose aussi de traiter les sauvegardes déjà produites.
