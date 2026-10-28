"""Générateur du SI fictif de Quantum-Ready.

Le SI fictif est un ensemble de fichiers statiques (certificats, clés, configurations,
code) que les agents inventorient. Il n'est jamais commité : il est régénéré par
`make si` à partir de ce paquet, conformément à la vérité terrain
(data/ground_truth/verite_terrain_v1.csv).

Organisation :
- generateur.py : le Contexte (où écrire) et l'enchaînement des étapes ;
- un module par famille d'actifs (pki, ssh, ...), chacun exposant une fonction
  generer_<famille>(ctx) ;
- modeles/ : les fichiers texte (configs, code piégé) avec des {{VARIABLES}}.
"""

from quantum_ready.si_fictif.generateur import Contexte, generer

__all__ = ["Contexte", "generer"]
