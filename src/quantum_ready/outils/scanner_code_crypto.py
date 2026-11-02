"""Outil scanner_code_crypto : usages de la cryptographie dans du code Python.

Le sujet propose semgrep ; on lit ici directement l'arbre syntaxique (module ast),
ce qui évite un binaire externe et permet trois choses qu'une recherche de texte
ne fait pas :
1. résoudre les imports : « from random import choice as c » puis « c() » est bien
   random.choice, alors que « random.SystemRandom().choice » ne l'est pas ;
2. suivre une variable jusqu'à sa source : si l'algorithme d'un JWT ou le mot de
   passe d'un PKCS#12 vient de os.environ["X"], l'outil le dit (piste vers le .env) ;
3. donner le CONTEXTE (fonction, docstring) : MD5 pour une clé de cache n'est pas
   MD5 pour un mot de passe. L'outil ne tranche pas : il donne les faits, l'agent juge.

Appelé sur un dossier, il signale aussi les modules qu'aucun autre fichier n'importe.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, Trouvaille, outil, relatif, resoudre

NOM = "scanner_code_crypto"
CRYPTO = "cryptography.hazmat.primitives"


@dataclass(frozen=True)
class Regle:
    type_actif: str
    nom: str
    description: str
    exposition: str
    faiblesse: str | None = None


HACHAGES = {
    "md5": ("MD5", "MD5 est cassé (collisions)"), "sha1": ("SHA-1", "SHA-1 est cassé (collisions)"),
    "sha224": ("SHA-224", None), "sha256": ("SHA-256", None), "sha384": ("SHA-384", None), "sha512": ("SHA-512", None),
    "sha3_256": ("SHA3-256", None), "sha3_512": ("SHA3-512", None), "blake2b": ("BLAKE2b", None), "blake2s": ("BLAKE2s", None),
}
ALEA_FAIBLE = ("choice", "choices", "randint", "random", "randrange", "getrandbits", "sample", "shuffle", "uniform", "randbytes")

REGLES: dict[str, Regle] = {
    **{f"hashlib.{f}": Regle("algorithm", nom, f"Empreinte {nom} (hashlib)", "grover", faible) for f, (nom, faible) in HACHAGES.items()},
    **{f"random.{f}": Regle("algorithm", "Mersenne Twister (module random)", f"Aléa du module random ({f})", "aucune",
                            "générateur NON cryptographique : ses sorties sont prévisibles") for f in ALEA_FAIBLE},
    "random.SystemRandom": Regle("algorithm", "random.SystemRandom (os.urandom)", "Aléa du système d'exploitation", "aucune"),
    "os.urandom": Regle("algorithm", "os.urandom", "Aléa du système d'exploitation", "aucune"),
    **{f"secrets.{f}": Regle("algorithm", "secrets (os.urandom)", "Aléa cryptographique du module secrets", "aucune")
       for f in ("token_bytes", "token_hex", "token_urlsafe", "choice", "randbelow", "randbits")},
    "cryptography.fernet.Fernet": Regle("algorithm", "Fernet (AES-128-CBC + HMAC-SHA256)", "Chiffrement symétrique authentifié Fernet", "grover"),
    "cryptography.fernet.MultiFernet": Regle("algorithm", "Fernet (AES-128-CBC + HMAC-SHA256)", "Chiffrement Fernet avec rotation de clés", "grover"),
    f"{CRYPTO}.asymmetric.padding.PKCS1v15": Regle("algorithm", "RSA PKCS#1 v1.5", "Bourrage RSA PKCS#1 v1.5", "shor"),
    f"{CRYPTO}.asymmetric.padding.OAEP": Regle("algorithm", "RSA-OAEP", "Chiffrement RSA-OAEP", "shor"),
    f"{CRYPTO}.asymmetric.padding.PSS": Regle("algorithm", "RSA-PSS", "Signature RSA-PSS", "shor"),
    f"{CRYPTO}.asymmetric.ed25519.Ed25519PrivateKey.generate": Regle("related-crypto-material", "Ed25519", "Génération d'une clé Ed25519", "shor"),
    f"{CRYPTO}.asymmetric.x25519.X25519PrivateKey.generate": Regle("related-crypto-material", "X25519", "Génération d'une clé X25519", "shor"),
    "ssl.create_default_context": Regle("protocol", "TLS (module ssl)", "Contexte TLS créé par le code", "shor"),
    "nacl.secret.SecretBox": Regle("algorithm", "XSalsa20-Poly1305 (PyNaCl)", "Chiffrement symétrique PyNaCl", "grover"),
    "nacl.public.Box": Regle("algorithm", "Curve25519 + XSalsa20-Poly1305 (PyNaCl)", "Chiffrement à clé publique PyNaCl", "shor"),
    "bcrypt.hashpw": Regle("algorithm", "bcrypt", "Hachage de mot de passe bcrypt", "grover"),
}
COURBES = {"SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521", "SECP256K1": "secp256k1"}
MOTS_MOT_DE_PASSE = ("password", "passwd", "mot_de_passe", "motdepasse", "pwd")
# Valeurs par défaut d'argon2-cffi (profil RFC 9106 « basse mémoire »)
ARGON2_DEFAUT = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}


def _constante(noeud):
    return noeud.value if isinstance(noeud, ast.Constant) else None


class Analyse(ast.NodeVisitor):
    """Parcourt un module et produit ses trouvailles et ses pistes."""

    def __init__(self, arbre: ast.Module, fichier: str):
        self.fichier = fichier
        self.alias: dict[str, str] = {}
        self.affectations: list[dict[str, ast.expr]] = [{}]  # pile : module, puis fonctions
        self.fonctions: list[ast.FunctionDef] = []
        self.groupes: dict[str, Trouvaille] = {}
        self.pistes: list[Piste] = []
        self.variables_env: dict[str, int] = {}
        self.docstring_module = (ast.get_docstring(arbre) or "").split("\n")[0]
        self._collecter_affectations(arbre.body, self.affectations[0])

    # --- résolution des noms ---

    def _collecter_affectations(self, corps, cible: dict) -> None:
        for instruction in corps:
            if isinstance(instruction, ast.Assign) and len(instruction.targets) == 1 and isinstance(instruction.targets[0], ast.Name):
                cible[instruction.targets[0].id] = instruction.value
            elif isinstance(instruction, ast.AnnAssign) and isinstance(instruction.target, ast.Name) and instruction.value:
                cible[instruction.target.id] = instruction.value

    def valeur(self, nom: str) -> ast.expr | None:
        for portee in reversed(self.affectations):
            if nom in portee:
                return portee[nom]
        return None

    def qualifie(self, noeud: ast.expr, profondeur: int = 0) -> str | None:
        """Nom complet d'une expression : « hashlib.md5 », « random.SystemRandom().choice »..."""
        if profondeur > 5:
            return None
        if isinstance(noeud, ast.Name):
            if noeud.id in self.alias:
                return self.alias[noeud.id]
            source = self.valeur(noeud.id)
            if isinstance(source, ast.Call):
                base = self.qualifie(source.func, profondeur + 1)
                return f"{base}()" if base else None
            return noeud.id
        if isinstance(noeud, ast.Attribute):
            base = self.qualifie(noeud.value, profondeur + 1)
            return f"{base}.{noeud.attr}" if base else None
        if isinstance(noeud, ast.Call):
            base = self.qualifie(noeud.func, profondeur + 1)
            return f"{base}()" if base else None
        return None

    def variable_env(self, noeud: ast.expr | None, profondeur: int = 0) -> str | None:
        """Nom de la variable d'environnement d'où vient une valeur, en suivant les affectations."""
        if noeud is None or profondeur > 5:
            return None
        if isinstance(noeud, ast.Subscript) and self.qualifie(noeud.value) == "os.environ":
            return _constante(noeud.slice)
        if isinstance(noeud, ast.Call):
            nom = self.qualifie(noeud.func)
            if nom in ("os.getenv", "os.environ.get") and noeud.args:
                return _constante(noeud.args[0])
            if isinstance(noeud.func, ast.Attribute):  # os.environ["X"].encode()
                return self.variable_env(noeud.func.value, profondeur + 1)
        if isinstance(noeud, ast.Attribute):
            return self.variable_env(noeud.value, profondeur + 1)
        if isinstance(noeud, ast.Name):
            return self.variable_env(self.valeur(noeud.id), profondeur + 1)
        return None

    def constante(self, noeud: ast.expr | None, profondeur: int = 0):
        if isinstance(noeud, ast.Name) and profondeur < 5:
            return self.constante(self.valeur(noeud.id), profondeur + 1)
        if isinstance(noeud, (ast.List, ast.Tuple)):
            valeurs = [self.constante(e, profondeur + 1) for e in noeud.elts]
            return valeurs if all(v is not None for v in valeurs) else None
        return _constante(noeud) if noeud is not None else None

    # --- visite ---

    def visit_Import(self, noeud: ast.Import) -> None:
        for nom in noeud.names:
            self.alias[nom.asname or nom.name.split(".")[0]] = nom.name if nom.asname else nom.name.split(".")[0]

    def visit_ImportFrom(self, noeud: ast.ImportFrom) -> None:
        for nom in noeud.names:
            self.alias[nom.asname or nom.name] = f"{noeud.module}.{nom.name}" if noeud.module else nom.name

    def _visiter_fonction(self, noeud) -> None:
        locales: dict[str, ast.expr] = {}
        self._collecter_affectations(ast.walk(noeud), locales)
        self.affectations.append(locales)
        self.fonctions.append(noeud)
        self.generic_visit(noeud)
        self.fonctions.pop()
        self.affectations.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _visiter_fonction

    def contexte(self) -> dict:
        if not self.fonctions:
            return {"contexte": self.docstring_module} if self.docstring_module else {}
        fonction = self.fonctions[-1]
        props = {"fonction": fonction.name, "parametres": [a.arg for a in fonction.args.args]}
        docstring = (ast.get_docstring(fonction) or "").split("\n")[0] or self.docstring_module
        if docstring:
            props["contexte"] = docstring
        return props

    def ajouter(self, regle: Regle, ligne: int, preuve: str, props: dict | None = None) -> Trouvaille:
        props = {**self.contexte(), **(props or {})}
        if regle.nom in self.groupes:  # même algorithme ailleurs dans le fichier : une seule trouvaille
            existante = self.groupes[regle.nom]
            existante.proprietes.setdefault("lignes", [str(existante.ligne)]).append(str(ligne))
            if "fonction" in props and props["fonction"] not in existante.proprietes.setdefault("fonctions", [existante.proprietes.get("fonction", "")]):
                existante.proprietes["fonctions"].append(props["fonction"])
            return existante
        if regle.faiblesse:
            props["faiblesse_classique"] = regle.faiblesse
        trouvaille = Trouvaille(
            outil=NOM, fichier=self.fichier, ligne=ligne, type_actif=regle.type_actif, nom=regle.nom,
            description=regle.description + (f" dans {props['fonction']}()" if "fonction" in props else ""),
            exposition=regle.exposition, proprietes=props, preuve=preuve[:120],
        )
        self.groupes[regle.nom] = trouvaille
        return trouvaille

    def visit_Subscript(self, noeud: ast.Subscript) -> None:
        if (nom := self.variable_env(noeud)) and nom not in self.variables_env:
            self.variables_env[nom] = noeud.lineno
        self.generic_visit(noeud)

    def visit_Call(self, noeud: ast.Call) -> None:
        nom = self.qualifie(noeud.func) or ""
        preuve = ast.unparse(noeud)
        if nom in ("os.getenv", "os.environ.get") and noeud.args and (variable := _constante(noeud.args[0])):
            self.variables_env.setdefault(variable, noeud.lineno)
        if nom in REGLES:
            self._regle_simple(nom, noeud, preuve)
        elif nom == "hashlib.new" and noeud.args:
            algo = str(self.constante(noeud.args[0]) or "?").lower().replace("-", "")
            nom_algo, faiblesse = HACHAGES.get(algo, (algo.upper(), None))
            self._hachage(Regle("algorithm", nom_algo, f"Empreinte {nom_algo} (hashlib.new)", "grover", faiblesse), noeud, preuve)
        elif nom == "hashlib.pbkdf2_hmac" and len(noeud.args) >= 4:
            iterations = self.constante(noeud.args[3])
            regle = Regle("algorithm", f"PBKDF2-HMAC-{str(self.constante(noeud.args[0])).upper()}", "Dérivation de clé PBKDF2", "grover",
                          "trop peu d'itérations" if isinstance(iterations, int) and iterations < 600_000 else None)
            self.ajouter(regle, noeud.lineno, preuve, {"iterations": iterations if iterations is not None else "?"})
        elif nom == "hmac.new":
            self._hmac(noeud, preuve)
        elif nom in ("hmac.compare_digest", "secrets.compare_digest"):
            for trouvaille in self.groupes.values():
                if trouvaille.nom.startswith("HMAC") and trouvaille.proprietes.get("fonction") == self.contexte().get("fonction"):
                    trouvaille.proprietes["comparaison"] = "hmac.compare_digest (temps constant)"
        elif nom in ("jwt.encode", "jwt.decode"):
            self._jwt(nom, noeud, preuve)
        elif nom.endswith("asymmetric.ec.ECDSA"):
            self._ecdsa(noeud, preuve)
        elif nom.endswith("asymmetric.rsa.generate_private_key"):
            taille = self.constante(noeud.args[1]) if len(noeud.args) > 1 else self.constante(next((k.value for k in noeud.keywords if k.arg == "key_size"), None))
            self.ajouter(Regle("related-crypto-material", f"RSA-{taille}", "Génération d'une clé RSA", "shor"), noeud.lineno, preuve)
        elif nom.endswith("asymmetric.ec.generate_private_key") and noeud.args:
            courbe = (self.qualifie(noeud.args[0]) or "").removesuffix("()").split(".")[-1]
            self.ajouter(Regle("related-crypto-material", f"ECDSA {COURBES.get(courbe, courbe)}", "Génération d'une clé sur courbe elliptique", "shor"), noeud.lineno, preuve)
        elif nom in ("argon2.PasswordHasher", "argon2.low_level.hash_secret"):
            self._argon2(noeud, preuve)
        elif nom.endswith("pkcs12.load_key_and_certificates") or nom.endswith("load_pem_private_key"):
            self._chargement_de_cle(nom, noeud)
        elif nom.startswith("paramiko.") and nom.endswith(("SSHClient", "Transport")):
            self.pistes.append(Piste(vers="paramiko", raison=f"connexion SSH ouverte par paramiko (ligne {noeud.lineno}) : les algorithmes sont ceux de la bibliothèque"))
        self.generic_visit(noeud)

    def _regle_simple(self, nom: str, noeud: ast.Call, preuve: str) -> None:
        regle = REGLES[nom]
        if nom.startswith("hashlib."):
            self._hachage(regle, noeud, preuve)
            return
        props = {}
        if nom.startswith("cryptography.fernet") and noeud.args and (variable := self.variable_env(noeud.args[0])):
            props["cle_lue_dans"] = f"variable d'environnement {variable}"
            self.pistes.append(Piste(vers=variable, raison=f"clé de {regle.nom.split(' ')[0]} lue dans {variable} (ligne {noeud.lineno})"))
        self.ajouter(regle, noeud.lineno, preuve, props)

    def _hachage(self, regle: Regle, noeud: ast.Call, preuve: str) -> None:
        props = {}
        fonction = self.fonctions[-1] if self.fonctions else None
        noms = " ".join([fonction.name, *(a.arg for a in fonction.args.args)]).lower() if fonction else ""
        if any(mot in noms for mot in MOTS_MOT_DE_PASSE):
            props["usage_probable"] = "mot de passe"
            regle = Regle(regle.type_actif, regle.nom, regle.description, regle.exposition,
                          "hachage rapide d'un mot de passe, sans sel ni itérations : à remplacer par Argon2id")
        self.ajouter(regle, noeud.lineno, preuve, props)

    def _hmac(self, noeud: ast.Call, preuve: str) -> None:
        digest = noeud.args[2] if len(noeud.args) > 2 else next((k.value for k in noeud.keywords if k.arg == "digestmod"), None)
        texte = (self.qualifie(digest) or str(self.constante(digest) or "?")) if digest is not None else "MD5 (défaut obsolète)"
        algo = texte.split(".")[-1].lower().replace("-", "")
        nom = f"HMAC-{HACHAGES.get(algo, (algo.upper(), None))[0]}"
        props = {}
        if noeud.args and (variable := self.variable_env(noeud.args[0])):
            props["cle_lue_dans"] = f"variable d'environnement {variable}"
            self.pistes.append(Piste(vers=variable, raison=f"clé HMAC lue dans {variable} (ligne {noeud.lineno})"))
        trouvaille = self.ajouter(Regle("algorithm", nom, f"Code d'authentification {nom}", "grover"), noeud.lineno, preuve, props)
        fonction = self.fonctions[-1] if self.fonctions else None
        if fonction and "comparaison" not in trouvaille.proprietes:
            for comparaison in ast.walk(fonction):
                if isinstance(comparaison, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in comparaison.ops):
                    trouvaille.proprietes["comparaison"] = f"« == » ligne {comparaison.lineno} (temps NON constant)"
                    trouvaille.proprietes["faiblesse_classique"] = "tag comparé avec == : attaque temporelle possible, utiliser hmac.compare_digest"

    def _jwt(self, nom: str, noeud: ast.Call, preuve: str) -> None:
        argument = next((k.value for k in noeud.keywords if k.arg in ("algorithm", "algorithms")), None)
        props: dict = {}
        valeur = self.constante(argument)
        if isinstance(valeur, list):
            valeur = ",".join(valeur)
        if isinstance(argument, ast.List) and len(argument.elts) == 1:
            argument = argument.elts[0]
            valeur = valeur or self.constante(argument)
        variable = self.variable_env(argument)
        if valeur:
            props["algorithme"] = valeur
        elif variable:
            props["algorithme"] = f"lu dans la variable d'environnement {variable}"
            self.pistes.append(Piste(vers=variable, raison=f"algorithme des JWT lu dans {variable} (ligne {noeud.lineno}) : sa valeur est dans le .env"))
        elif nom == "jwt.encode":
            props["algorithme"] = "HS256 (défaut de pyjwt)"
        secret = noeud.args[1] if len(noeud.args) > 1 else None
        if (variable_secret := self.variable_env(secret)):
            props["secret_lu_dans"] = f"variable d'environnement {variable_secret}"
            self.pistes.append(Piste(vers=variable_secret, raison=f"secret de signature des JWT lu dans {variable_secret}"))
        expo = exposition(str(valeur)) if valeur else "inconnue"
        nom_trouvaille = f"JWT {valeur}" if valeur else "JWT (algorithme à déterminer)"
        regle = Regle("algorithm", nom_trouvaille, "Signature des jetons JWT (pyjwt)", expo if expo != "inconnue" or not valeur else "inconnue")
        self.ajouter(regle, noeud.lineno, preuve, props)

    def _ecdsa(self, noeud: ast.Call, preuve: str) -> None:
        hachage = (self.qualifie(noeud.args[0]) or "?").removesuffix("()").split(".")[-1] if noeud.args else "?"
        nom_hachage = HACHAGES.get(hachage.lower(), (hachage, None))[0]
        self.ajouter(Regle("algorithm", f"ECDSA avec {nom_hachage}", f"Signature ECDSA avec {nom_hachage}", "shor"), noeud.lineno, preuve,
                     {"courbe": "celle de la clé chargée (voir le certificat ou le conteneur)"})

    def _argon2(self, noeud: ast.Call, preuve: str) -> None:
        reglages = dict(ARGON2_DEFAUT)
        for mot_cle in noeud.keywords:
            if mot_cle.arg in reglages and isinstance(self.constante(mot_cle.value), int):
                reglages[mot_cle.arg] = self.constante(mot_cle.value)
        props = {"t": reglages["time_cost"], "m_kio": reglages["memory_cost"], "p": reglages["parallelism"], "variante": "Argon2id (défaut d'argon2-cffi)"}
        faiblesse = "mémoire inférieure à 19 Mio (minimum OWASP)" if reglages["memory_cost"] < 19456 else None
        self.ajouter(Regle("algorithm", "Argon2id", "Hachage de mots de passe Argon2id", "grover", faiblesse), noeud.lineno, preuve, props)

    def _chargement_de_cle(self, nom: str, noeud: ast.Call) -> None:
        mot_de_passe = noeud.args[1] if len(noeud.args) > 1 else next((k.value for k in noeud.keywords if k.arg == "password"), None)
        variable = self.variable_env(mot_de_passe)
        quoi = "conteneur PKCS#12" if "pkcs12" in nom else "clé privée PEM"
        raison = f"{quoi} ouvert ligne {noeud.lineno}"
        if variable:
            raison += f" avec le mot de passe de la variable {variable} : appeler analyser_pkcs12 avec fichier_env et variable={variable}"
            self.pistes.append(Piste(vers=variable, raison=raison))
        constantes = [n.value for n in ast.walk(ast.Module(body=[ast.Expr(self.valeur(n.id) or n) for n in ast.walk(noeud) if isinstance(n, ast.Name)] + [ast.Expr(noeud)], type_ignores=[]))
                      if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith((".p12", ".pfx", ".pem", ".key"))]
        for fichier in dict.fromkeys(constantes):
            self.pistes.append(Piste(vers=fichier, raison=f"fichier de clé ouvert par le code ({quoi}, ligne {noeud.lineno})"))


def modules_importes(arbres: dict[str, ast.Module]) -> set[str]:
    """Tous les noms de modules importés (« api.auth », « auth », « factures.signer »...)."""
    noms = set()
    for arbre in arbres.values():
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.Import):
                noms |= {a.name for a in noeud.names}
            elif isinstance(noeud, ast.ImportFrom):
                base = noeud.module or ""
                noms.add(base)
                noms |= {f"{base}.{a.name}" if base else a.name for a in noeud.names}
    return noms


@outil(NOM)
def scanner_code_crypto(cible: str, racine: Path) -> Resultat:
    """Cherche la cryptographie dans un fichier Python ou tous les .py d'un dossier."""
    chemin = resoudre(cible or ".", racine)
    fichiers = [chemin] if chemin.is_file() else sorted(p for p in chemin.rglob("*.py") if "__pycache__" not in p.parts)
    if not fichiers:
        raise ErreurOutil("Aucun fichier Python à analyser")
    resultat = Resultat(outil=NOM, cible=relatif(chemin, racine) if chemin != racine else ".")
    arbres: dict[str, ast.Module] = {}
    for fichier in fichiers:
        relatif_si = relatif(fichier, racine)
        try:
            arbres[relatif_si] = ast.parse(fichier.read_text(encoding="utf-8"), filename=relatif_si)
        except SyntaxError as erreur:
            resultat.erreurs.append(f"{relatif_si} : syntaxe Python invalide (ligne {erreur.lineno})")
    importes = modules_importes(arbres) if chemin.is_dir() else None
    for relatif_si, arbre in arbres.items():
        analyse = Analyse(arbre, relatif_si)
        analyse.visit(arbre)
        if importes is not None and analyse.groupes:
            module = relatif_si.removesuffix(".py").replace("/", ".")
            importe = any(nom == module or nom.endswith("." + module) or module.endswith("." + nom) for nom in importes)
            if not importe and not module.endswith(("__main__", "__init__")):
                for trouvaille in analyse.groupes.values():
                    trouvaille.proprietes["module_importe_ailleurs"] = False
                resultat.pistes.append(Piste(vers=relatif_si, raison="aucun autre fichier analysé n'importe ce module : code mort ou point d'entrée ?"))
        resultat.trouvailles += analyse.groupes.values()
        resultat.pistes += [_situer_fichier(p, racine / relatif_si, racine) for p in analyse.pistes]
        for variable, ligne in analyse.variables_env.items():
            if not any(p.vers == variable for p in analyse.pistes):
                resultat.pistes.append(Piste(vers=variable, raison=f"variable d'environnement lue par {relatif_si} (ligne {ligne})"))
    vues = set()
    resultat.pistes = [p for p in resultat.pistes if (p.vers, p.raison.split(" (ligne")[0]) not in vues and not vues.add((p.vers, p.raison.split(" (ligne")[0]))]
    return resultat


def _situer_fichier(piste: Piste, fichier: Path, racine: Path) -> Piste:
    """« factures.p12 » cité par le code devient « factures/keys/factures.p12 » s'il existe un seul fichier de ce nom près du code."""
    if not piste.vers.endswith((".p12", ".pfx", ".pem", ".key")):
        return piste
    candidats = [c for c in fichier.parent.rglob(Path(piste.vers).name) if c.resolve().is_relative_to(racine)]
    if len(candidats) == 1:
        return Piste(vers=relatif(candidats[0], racine), raison=piste.raison)
    return piste
