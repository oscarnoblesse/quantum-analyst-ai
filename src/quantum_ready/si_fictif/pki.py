"""PKI du SI fictif — À ÉCRIRE PAR OSCAR.

Cette étape doit produire les certificats, leurs clés privées et le conteneur PKCS#12
décrits par la vérité terrain : QR-001 à QR-012, QR-020, QR-021, QR-045 à QR-049
et QR-065 à QR-070.

Utiliser ctx.ecrire(chemin, contenu, prive=True) pour les clés privées du SI,
ctx.ecrire_hors_si(...) pour les clés qui doivent rester hors du SI (AC racine et
intermédiaire), et ctx.valeurs pour les mots de passe déjà tirés par generer_secrets.
"""

from __future__ import annotations

from quantum_ready.si_fictif.generateur import Contexte


def generer_pki(ctx: Contexte) -> None:
    """Étape PKI : pas encore implémentée, le SI est généré sans certificats."""
    print("[si_fictif] Étape PKI non implémentée : aucun certificat généré.")
