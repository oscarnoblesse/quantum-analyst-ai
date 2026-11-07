"""Scripts shell : commandes cryptographiques (gpg, openssl, ssh-keygen, *sum) et conservation des données.

La durée de conservation (« find ... -mtime +3650 -delete ») n'est pas un actif
cryptographique, mais c'est une donnée clé du risque quantique : c'est le x de
l'inégalité de Mosca (combien de temps les données doivent rester confidentielles).
"""

from __future__ import annotations

import re
import shlex

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import Piste, Trouvaille

NOM = "analyser_configuration"
_AFFECTATION = re.compile(r"^\s*([A-Za-z_]\w*)=(.*)$")
EMPREINTES = {"md5sum": "MD5", "sha1sum": "SHA-1", "sha256sum": "SHA-256", "sha512sum": "SHA-512", "b2sum": "BLAKE2b"}


def commandes(texte: str) -> list[tuple[int, list[str]]]:
    """Commandes simples (ligne, mots), variables du script remplacées, lignes « \\ » recollées."""
    variables = {"0": "./script"}
    resultat, tampon, debut = [], "", 0
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if not tampon:
            if not ligne.strip() or ligne.lstrip().startswith("#"):
                continue
            debut = numero
        tampon += ligne.rstrip().removesuffix("\\") + " "
        if ligne.rstrip().endswith("\\"):
            continue
        texte_commande, tampon = tampon, ""
        texte_commande = re.sub(r'\$\(dirname "?\$0"?\)', ".", texte_commande)
        for nom, valeur in variables.items():
            texte_commande = texte_commande.replace("${" + nom + "}", valeur).replace("$" + nom, valeur)
        if (affectation := _AFFECTATION.match(texte_commande.strip())) and " " not in affectation.group(2).strip().strip('"'):
            variables[affectation.group(1)] = affectation.group(2).strip().strip('"')
            continue
        for morceau in re.split(r"\|\||&&|[|;]", texte_commande):
            try:
                mots = shlex.split(morceau)
            except ValueError:
                mots = morceau.split()
            mots = [m for m in mots if m not in (">", "<", ">>") and not m.startswith((">", "<"))]
            if mots:
                resultat.append((debut, mots))
    return resultat


def _option(mots: list[str], *noms: str) -> str | None:
    for i, mot in enumerate(mots):
        for nom in noms:
            if mot == nom and i + 1 < len(mots):
                return mots[i + 1]
            if mot.startswith(nom + "="):
                return mot.split("=", 1)[1]
    return None


def analyser(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    trouvailles, pistes, conservation = [], [], None

    def ajouter(ligne, type_actif, nom, description, expo, props, preuve):
        trouvailles.append(Trouvaille(outil=NOM, fichier=fichier, ligne=ligne, type_actif=type_actif, nom=nom,
                                      description=description, exposition=expo, proprietes=props, preuve=preuve[:120]))

    for ligne, mots in commandes(texte):
        programme = mots[0].split("/")[-1]
        preuve = " ".join(mots)
        if programme in ("gpg", "gpg2"):
            if (cle := _option(mots, "--import")) or ("--import" in mots and mots[-1] != "--import" and (cle := mots[-1])):
                pistes.append(Piste(vers=cle, raison=f"clé importée par gpg (ligne {ligne})"))
            if {"--encrypt", "-e"} & set(mots):
                props: dict = {"destinataire": _option(mots, "--recipient", "-r") or "?",
                               "chiffrement_symetrique": _option(mots, "--cipher-algo") or "choisi par GnuPG selon les préférences de la clé"}
                if _option(mots, "--trust-model") == "always":
                    props["faiblesse_classique"] = "--trust-model always : la clé du destinataire n'est pas vérifiée"
                ajouter(ligne, "algorithm", "Chiffrement OpenPGP à clé publique",
                        f"Données chiffrées par gpg pour la clé de « {props['destinataire']} »", "shor", props, preuve)
            elif {"--symmetric", "-c"} & set(mots):
                ajouter(ligne, "algorithm", f"Chiffrement OpenPGP symétrique ({_option(mots, '--cipher-algo') or 'AES par défaut'})",
                        "Données chiffrées par gpg avec une phrase de passe", "grover", {}, preuve)
            if {"--sign", "-s", "--clearsign", "--detach-sign"} & set(mots):
                ajouter(ligne, "algorithm", "Signature OpenPGP", "Données signées par gpg", "shor", {}, preuve)
        elif programme == "openssl" and len(mots) > 1:
            options = " ".join(mots[2:])
            algorithmes = re.findall(r"-(aes-\d+-\w+|des\S*|chacha20\S*|sha\d*|md5|pbkdf2)\b|(rsa:\d+|ec:\S+|ed25519|ml-dsa-\d+|ml-kem-\d+)", options)
            noms = [a or b for a, b in algorithmes] or [mots[1]]
            ajouter(ligne, "algorithm", f"openssl {mots[1]} ({', '.join(noms)})", f"Commande openssl {mots[1]} dans un script",
                    exposition(" ".join(noms)), {"sous_commande": mots[1], "algorithmes": noms}, preuve)
        elif programme == "ssh-keygen" and (type_cle := _option(mots, "-t")):
            taille = _option(mots, "-b")
            nom = f"{type_cle.upper()}-{taille}" if taille else type_cle
            ajouter(ligne, "related-crypto-material", f"Génération de clé SSH {nom}", "Clé SSH générée par un script",
                    exposition(type_cle), {"type": type_cle} | ({"taille": int(taille)} if taille and taille.isdigit() else {}), preuve)
        elif programme in EMPREINTES:
            ajouter(ligne, "algorithm", EMPREINTES[programme], f"Empreinte {EMPREINTES[programme]} calculée par {programme}",
                    "grover", {"faiblesse_classique": "fonction de hachage cassée"} if programme in ("md5sum", "sha1sum") else {}, preuve)
        elif programme == "find" and "-delete" in mots and (age := _option(mots, "-mtime")):
            jours = int(age.lstrip("+")) if age.lstrip("+").isdigit() else None
            if jours:
                conservation = jours
                pistes.append(Piste(vers=fichier, raison=f"données conservées {jours} jours (environ {jours // 365} ans) avant suppression : "
                                    "c'est la durée de confidentialité x de l'inégalité de Mosca"))
    if conservation:
        for trouvaille in trouvailles:
            trouvaille.proprietes["duree_conservation_jours"] = conservation
    return trouvailles, pistes
