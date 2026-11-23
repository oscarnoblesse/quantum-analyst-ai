"""Variante 2 du SI fictif : Fret Lab, transporteur routier (SI d'évaluation, non vu).

Le SI v2 sert à mesurer la robustesse du système sur un SI qu'il n'a jamais vu pendant le
développement. Il a été conçu après le gel du système évalué, sans lire le code des outils
ni lancer les agents dessus (règle d'intégrité : docs/regles_verite_terrain.md, section v2).

Organisation :
- ``valeurs`` : graine, secrets aléatoires, noms et dates communs ;
- ``pki``     : autorités, certificats, clés privées, PKCS#12, keystore JKS, certificat SAML ;
- ``ssh``     : clés d'hôte, clés d'utilisateurs, authorized_keys, known_hosts, clé DSA ;
- ``formats`` : encodages écrits à la main (JKS, OpenPGP EdDSA, DNSKEY, WireGuard, OpenVPN) ;
- ``fichiers``: configurations, code et scripts, rendus depuis ``modeles/v2/`` ;
- ``leurres`` : faux positifs volontaires (data/ground_truth/leurres_v2.csv).
"""

from __future__ import annotations

from quantum_ready.si_fictif.generateur import Etape


def etapes_v2() -> list[Etape]:
    from quantum_ready.si_fictif.v2 import fichiers, pki, ssh, valeurs

    return [
        valeurs.generer_valeurs,
        pki.generer_pki,
        ssh.generer_ssh,
        fichiers.generer_fichiers,
    ]
