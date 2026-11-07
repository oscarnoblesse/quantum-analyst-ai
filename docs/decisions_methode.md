# Décisions de méthode

Décisions prises par l'auteur, notées ici pour que le rapport et le code s'y réfèrent.

## 1. Grille de crypto-agilité par actif (validée)

Le niveau d'agilité d'un actif dépend de l'endroit où il apparaît dans le SI. Un actif présent à
plusieurs endroits prend le niveau le plus rigide.

| Emplacement | Niveau | Changement nécessaire |
| --- | --- | --- |
| Fichier de configuration | élevée | changer une valeur |
| Dépendance ou logiciel par défaut | moyenne | mettre à jour une bibliothèque ou un logiciel |
| Code source | faible | modifier et redéployer le code |
| Certificat ou clé | faible | réémettre le certificat ou la clé et les distribuer |

Implémentation : `src/quantum_ready/outils/crypto_agilite.py`.

## 2. Vérification du plan (validée)

Une étape du plan de l'Architecte est vérifiée ainsi :

1. Si sa cible est démontrable au laboratoire (`X25519MLKEM768`, `ML-DSA-65`, `mlkem768x25519-sha256`),
   le code monte cette configuration, vérifie qu'elle est réellement négociée, et mesure son coût.
2. Si la démonstration échoue, le plan retourne à l'Architecte avec le motif de l'échec.
3. Une étape non démontrable au laboratoire (GnuPG, PKI hors laboratoire) est marquée
   « non vérifiée », jamais « validée ».

Limite assumée : le rapport doit dire qu'une part du plan reste non vérifiée.
