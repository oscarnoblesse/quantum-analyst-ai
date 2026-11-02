"""Description des clés publiques, partagée par analyser_x509 et analyser_cle."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519

# Courbes : nom technique -> nom usuel (celui des RFC et de l'ANSSI)
COURBES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "secp256k1"}

# Seuils classiques (hors quantique), d'après les recommandations ANSSI 2021 :
# RSA/DSA/DH sous 2048 bits et courbes sous 256 bits sont considérés comme faibles dès aujourd'hui.
TAILLE_MIN_RSA = 2048
TAILLE_MIN_COURBE = 256


def decrire_cle(cle) -> tuple[str, dict[str, str | int | bool | list[str]]]:
    """Nom court (« RSA-2048 », « ECDSA P-384 »...) et propriétés d'une clé publique ou privée."""
    if isinstance(cle, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        taille = cle.key_size
        return f"RSA-{taille}", _avec_faiblesse({"algorithme": "RSA", "taille": taille}, taille < TAILLE_MIN_RSA)
    if isinstance(cle, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        courbe = COURBES.get(cle.curve.name, cle.curve.name)
        props = {"algorithme": "ECDSA", "courbe": courbe, "taille": cle.curve.key_size}
        return f"ECDSA {courbe}", _avec_faiblesse(props, cle.curve.key_size < TAILLE_MIN_COURBE)
    if isinstance(cle, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        taille = cle.key_size
        return f"DSA-{taille}", _avec_faiblesse({"algorithme": "DSA", "taille": taille}, True, "DSA est obsolète")
    if isinstance(cle, (dh.DHPublicKey, dh.DHPrivateKey)):
        taille = cle.key_size
        return f"DH-{taille}", _avec_faiblesse({"algorithme": "DH", "taille": taille}, taille < TAILLE_MIN_RSA)
    for classe, nom, taille in (
        ((ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey), "Ed25519", 256),
        ((ed448.Ed448PublicKey, ed448.Ed448PrivateKey), "Ed448", 456),
        ((x25519.X25519PublicKey, x25519.X25519PrivateKey), "X25519", 256),
        ((x448.X448PublicKey, x448.X448PrivateKey), "X448", 448),
    ):
        if isinstance(cle, classe):
            return nom, {"algorithme": nom, "taille": taille}
    return type(cle).__name__, {"algorithme": "inconnu"}


def _avec_faiblesse(props: dict, faible: bool, raison: str | None = None) -> dict:
    if faible:
        props["faiblesse_classique"] = raison or f"taille insuffisante aujourd'hui ({props['taille']} bits)"
    return props
