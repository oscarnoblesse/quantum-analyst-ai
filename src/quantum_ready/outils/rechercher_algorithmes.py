"""Outil rechercher_algorithmes : détection textuelle de repli, pour tout format de fichier.

Aucun jeu d'analyseurs ne couvrira tous les formats d'un vrai SI (Java, Go,
Postfix, HAProxy, YAML maison...). Cet outil cherche dans le texte les noms
d'algorithmes, de protocoles et de suites TLS, mot entier, et les rapporte comme
INDICES (proprietes.confiance) : l'agent doit les confirmer, car un nom dans un
commentaire n'est pas un usage. Les valeurs qui ressemblent à des secrets sont
masquées dans les extraits.

Sur un dossier, il ne lit par défaut que les fichiers sans analyseur dédié
(il complète les autres outils au lieu de les doubler) ; tous=True lit tout.
"""

from __future__ import annotations

import re
from pathlib import Path

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import ErreurOutil, Resultat, Trouvaille, outil, relatif, resoudre

NOM = "rechercher_algorithmes"
LIMITE = 200
_BORD_G, _BORD_D = r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9])"

# Suites TLS complètes (noms OpenSSL « ECDHE-RSA-AES128-GCM-SHA256 » ou IANA « TLS_AES_256_GCM_SHA384 ») :
# reconnues d'abord, puis retirées de la ligne pour ne pas compter leurs morceaux.
_SUITE = re.compile(_BORD_G + r"(TLS_[A-Z0-9_]{6,}|(?:ECDHE|DHE|EDH|ECDH|RSA|PSK|SRP)?-?(?:[A-Z0-9]+-){1,5}(?:SHA\d*|MD5|POLY1305|GCM|CCM8?))" + _BORD_D)
MOTIFS: list[tuple[str, str, int]] = [
    (r"SSLv[23]|TLSv?\s?1(?:\.[0-3])?(?![\d.])", "protocol", re.I),
    (r"X25519MLKEM768|SecP256r1MLKEM768|mlkem768x25519(?:-sha256)?|ML-?KEM-?(?:512|768|1024)|ML-?DSA-?(?:44|65|87)|SLH-?DSA[\w-]*|sntrup761x25519[\w@.-]*|Kyber\d*|Dilithium\d*", "algorithm", re.I),
    (r"RSA(?:[-_ ]?(?:512|1024|2048|3072|4096|8192))?|ECDSA|EdDSA|Ed25519|Ed448|X25519|X448|ECDHE?|DSA|Diffie-?Hellman|ElGamal", "algorithm", re.I),
    (r"secp\d{3}[rk]1|prime256v1|nistp(?:256|384|521)|P-(?:256|384|521)|brainpoolP\d+r1", "algorithm", 0),
    (r"AES(?:[-_ ]?(?:128|192|256))?(?:[-_/](?:GCM|CBC|CTR|ECB|CCM|CFB|OFB))?|ChaCha20(?:-Poly1305)?|Camellia\d*|Blowfish|ARC4|RC4|RC2", "algorithm", re.I),
    (r"3DES|TripleDES|DESede|DES-EDE3[\w-]*|DES-CBC3|DES(?:/\w+)?", "algorithm", 0),  # sensible à la casse : « des » est un mot français
    (r"MD[45]|SHA-?1|SHA-?(?:224|256|384|512)|SHA3-(?:256|384|512)|BLAKE2[bs]?|HMAC[-_]?(?:SHA-?\d*|MD5)?|[HRPE]S(?:256|384|512)", "algorithm", re.I),
    (r"PBKDF2[\w-]*|bcrypt|scrypt|Argon2(?:id|i|d)?", "algorithm", re.I),
]
_MOTIFS = [(re.compile(_BORD_G + "(" + motif + ")" + _BORD_D, drapeaux), type_actif) for motif, type_actif, drapeaux in MOTIFS]
FAIBLES = {"MD4", "MD5", "SHA-1", "DES", "3DES", "RC4", "RC2", "BLOWFISH", "SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1", "RSA-512", "RSA-1024", "DSA"}
_SECRET = re.compile(r"((?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|credential)[\w.\-]*[\"']?\s*[:=]\s*)([\"']?)([^\s\"',;]+)", re.I)


def normaliser(nom: str) -> str:
    """Forme canonique : « sha256 » -> « SHA-256 », « tls 1.2 » -> « TLSv1.2 », « aes_256_gcm » -> « AES-256-GCM »."""
    brut = nom.strip()
    if re.fullmatch(r"(?i)tlsv?\s?1(\.[0-3])?", brut):
        version = re.sub(r"(?i)tlsv?\s?", "", brut)
        return "TLSv" + (version if "." in version else "1.0")
    if re.fullmatch(r"secp\d+[rk]1|prime256v1|nistp\d+|brainpoolP\d+r1|P-\d+", brut):
        return brut  # noms de courbes : la casse d'origine est la norme
    if re.fullmatch(r"(?i)sslv[23]", brut):
        return "SSLv" + brut[-1]
    haut = brut.upper().replace("_", "-").replace(" ", "-").replace("/", "-")
    haut = re.sub(r"^SHA(\d)", r"SHA-\1", haut)
    haut = re.sub(r"^AES(\d)", r"AES-\1", haut)
    haut = re.sub(r"^RSA(\d)", r"RSA-\1", haut)
    return {"TRIPLEDES": "3DES", "DESEDE": "3DES", "DES-CBC3": "3DES", "ARC4": "RC4", "DIFFIEHELLMAN": "DIFFIE-HELLMAN"}.get(haut, haut)


def masquer(ligne: str) -> str:
    return _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}<masqué>", ligne)


def analyser_texte(texte: str, fichier: str) -> list[Trouvaille]:
    groupes: dict[str, Trouvaille] = {}
    dans_pem = False
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if "-----BEGIN " in ligne:
            dans_pem = True
        if dans_pem:
            dans_pem = "-----END " not in ligne
            continue
        reste = ligne
        trouves: list[tuple[str, str]] = []
        for suite in _SUITE.findall(ligne):
            if re.search(r"AES|DES|RC4|CHACHA|CAMELLIA|NULL|ARIA", suite):
                trouves.append((suite, "protocol"))
                reste = reste.replace(suite, " ")
        for motif, type_actif in _MOTIFS:
            trouves += [(m, type_actif) for m in motif.findall(reste)]
        for nom, type_actif in trouves:
            canonique = nom if type_actif == "protocol" and "-" in nom or nom.startswith("TLS_") else normaliser(nom)
            if canonique in groupes:
                lignes = groupes[canonique].proprietes.setdefault("lignes", [str(groupes[canonique].ligne)])
                if str(numero) not in lignes:
                    lignes.append(str(numero))
                continue
            props: dict = {"confiance": "indice : détection textuelle, à confirmer (un nom dans un commentaire n'est pas un usage)"}
            base = canonique.upper().split("-")[0] if not canonique.upper().startswith(("RSA-", "AES-")) else canonique.upper()
            if canonique.upper() in FAIBLES or base in FAIBLES or "ECB" in canonique.upper() or re.search(r"(?i)(^|-)(DES-CBC3|RC4|MD5|NULL|EXPORT)(-|$)", canonique):
                props["faiblesse_classique"] = "algorithme ou protocole considéré comme faible aujourd'hui"
            groupes[canonique] = Trouvaille(
                outil=NOM, fichier=fichier, ligne=numero, type_actif="protocol" if canonique.startswith(("TLS", "SSL")) or type_actif == "protocol" else type_actif,
                nom=canonique, description=f"Mention de {canonique} dans le fichier (détection textuelle)",
                exposition="shor" if canonique.startswith(("TLSv", "SSLv")) else exposition(canonique), proprietes=props, preuve=masquer(ligne.strip())[:120],
            )
    return list(groupes.values())


@outil(NOM)
def rechercher_algorithmes(cible: str, racine: Path, tous: bool = False) -> Resultat:
    """Repère par le texte les algorithmes et protocoles cités dans un fichier (ou un dossier), quel que soit son format."""
    from quantum_ready.outils.lister_fichiers import OUTILS, lister_fichiers

    chemin = resoudre(cible or ".", racine)
    if chemin.is_file():
        fichiers = [relatif(chemin, racine)]
    else:
        liste = lister_fichiers(relatif(chemin, racine) if chemin != racine else ".", racine=racine).fichiers
        fichiers = [f.chemin for f in liste if not f.nature.startswith("binaire") and f.nature != "vide" and (tous or f.nature not in OUTILS)]
    resultat = Resultat(outil=NOM, cible=cible)
    for fichier in fichiers:
        try:
            texte = (racine / fichier).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            if chemin.is_file():
                raise ErreurOutil("Fichier binaire : pas de détection textuelle possible")
            continue
        resultat.trouvailles += analyser_texte(texte, fichier)
    if len(resultat.trouvailles) > LIMITE:
        resultat.erreurs.append(f"{len(resultat.trouvailles)} indices : seuls les {LIMITE} premiers sont renvoyés, analyser fichier par fichier")
        resultat.trouvailles = resultat.trouvailles[:LIMITE]
    return resultat
