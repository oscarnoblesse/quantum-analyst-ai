"""Les outils tels que les voit un agent : arguments simples, résultats COMPACTS.

Un petit modèle local a une fenêtre de contexte de quelques milliers de jetons. Un
outil ne lui renvoie donc pas ses trouvailles complètes (elles sont enregistrées
dans la session), mais un résumé d'une ligne par trouvaille, avec un identifiant
(T0012) que les agents suivants utilisent pour y faire référence.

Les fonctions de ce module reçoivent la Session par fermeture : le modèle ne choisit
jamais la racine du SI ni le dossier de session.
"""


from collections.abc import Callable

from pydantic import BaseModel, Field

from quantum_ready.outils.commun import Resultat
from quantum_ready.serveur_mcp.session import Session, ecrire_json, lire_json

MAX_TROUVAILLES_AFFICHEES = 15
MAX_PISTES_AFFICHEES = 8
TAILLE_PAGE = 20


def _court(texte: str, taille: int = 110) -> str:
    texte = " ".join(str(texte).split())
    return texte if len(texte) <= taille else texte[: taille - 1] + "…"


def resumer(resultat: Resultat, identifiants: list[str]) -> str:
    """Résultat d'un outil d'inventaire, en quelques lignes lisibles par le modèle."""
    if resultat.erreurs and not resultat.trouvailles and not resultat.pistes:
        return "\n".join(f"ERREUR : {e}" for e in resultat.erreurs)
    lignes = [f"{resultat.outil} « {resultat.cible} » : {len(resultat.trouvailles)} trouvaille(s) enregistrée(s)"]
    for identifiant, t in list(zip(identifiants, resultat.trouvailles))[:MAX_TROUVAILLES_AFFICHEES]:
        details = [t.type_actif, _court(t.nom, 60), t.exposition]
        if t.implicite:
            details.append("implicite")
        if "faiblesse_classique" in t.proprietes:
            details.append("faible : " + _court(t.proprietes["faiblesse_classique"], 60))
        if "confiance" in t.proprietes:
            details.append("indice à confirmer")
        lignes.append(f"{identifiant} | " + " | ".join(details) + (f" | {t.fichier}" if t.fichier and t.fichier != resultat.cible else ""))
    if len(resultat.trouvailles) > MAX_TROUVAILLES_AFFICHEES:
        lignes.append(f"(+{len(resultat.trouvailles) - MAX_TROUVAILLES_AFFICHEES} autres trouvailles enregistrées)")
    if resultat.pistes:
        lignes.append("Pistes :")
        lignes += [f"- {_court(p.vers, 50)} : {_court(p.raison)}" for p in resultat.pistes[:MAX_PISTES_AFFICHEES]]
        if len(resultat.pistes) > MAX_PISTES_AFFICHEES:
            lignes.append(f"- (+{len(resultat.pistes) - MAX_PISTES_AFFICHEES} autres pistes)")
    lignes += [f"ERREUR : {e}" for e in resultat.erreurs]
    return "\n".join(lignes)


class Evaluation(BaseModel):
    ref: str = Field(description="Référence de l'actif (bom-ref) donnée par lister_actifs")
    x: float = Field(description="Années pendant lesquelles les données ou la signature doivent rester sûres")
    y: float = Field(description="Années nécessaires pour migrer cet actif")
    justification: str = Field(description="Une phrase : pourquoi ces valeurs de x et y")


def creer_outils(session: Session, agent: str, horizon_menace: float = 10) -> dict[str, Callable[..., str]]:
    """Toutes les fonctions exposables, liées à une session. Le serveur n'expose que celles de la liste fermée de l'agent."""
    from quantum_ready.outils import analyser_cle as _cle
    from quantum_ready.outils import analyser_configuration as _conf
    from quantum_ready.outils import analyser_dependances as _dep
    from quantum_ready.outils import analyser_pkcs12 as _p12
    from quantum_ready.outils import analyser_x509 as _x509
    from quantum_ready.outils import lister_fichiers as _lister
    from quantum_ready.outils import rechercher_algorithmes as _textuel
    from quantum_ready.outils import scanner_code_crypto as _code

    racine = session.racine_si

    def inventaire(resultat: Resultat) -> str:
        return resumer(resultat, session.enregistrer(resultat.trouvailles, agent))

    # --- Inventoriste ---

    def lister_fichiers(cible: str = ".") -> str:
        """Liste les fichiers d'un dossier du SI avec leur nature (reconnue d'après le contenu) et l'outil conseillé pour chacun."""
        resultat = _lister.lister_fichiers(cible, racine=racine)
        lignes = [f"{len(resultat.fichiers)} fichier(s) dans « {cible} » (chemin | nature | outil conseillé)"]
        for f in resultat.fichiers:
            lignes.append(f"{f.chemin} | {f.nature} | {f.outil_conseille or '-'}" + (f" | {f.remarque}" if f.remarque else ""))
        lignes += [f"ERREUR : {e}" for e in resultat.erreurs]
        return "\n".join(lignes)

    def analyser_x509(cible: str) -> str:
        """Analyse les certificats X.509 d'un fichier (PEM ou DER) : certificat, clé publique et signature de chacun."""
        return inventaire(_x509.analyser_x509(cible, racine=racine))

    def analyser_cle(cible: str) -> str:
        """Analyse les clés d'un fichier (privées PEM/OpenSSH, publiques SSH, OpenPGP, paramètres DH) : type, taille, chiffrement, empreinte."""
        return inventaire(_cle.analyser_cle(cible, racine=racine))

    def analyser_pkcs12(cible: str, fichier_env: str = "", variable: str = "") -> str:
        """Analyse un conteneur PKCS#12. Pour l'ouvrir, indiquer le fichier .env et le NOM de la variable qui contient le mot de passe (jamais le mot de passe lui-même)."""
        return inventaire(_p12.analyser_pkcs12(cible, racine=racine, fichier_env=fichier_env or None, variable=variable or None))

    def analyser_configuration(cible: str, version_openssh: str = "") -> str:
        """Analyse un fichier de configuration (nginx, Apache, sshd, ssh client, PostgreSQL, .env, YAML, JSON, Dockerfile, script shell). version_openssh : facultatif, si connue."""
        options = {"version_openssh": version_openssh} if version_openssh else {}
        return inventaire(_conf.analyser_configuration(cible, racine=racine, **options))

    def scanner_code_crypto(cible: str = ".") -> str:
        """Cherche la cryptographie dans un fichier Python ou dans tous les fichiers .py d'un dossier."""
        return inventaire(_code.scanner_code_crypto(cible, racine=racine))

    def analyser_dependances(cible: str) -> str:
        """Liste les bibliothèques cryptographiques d'un projet Python (pyproject.toml, uv.lock, poetry.lock, requirements.txt) : versions, transitives, importées ou non."""
        return inventaire(_dep.analyser_dependances(cible, racine=racine))

    def rechercher_algorithmes(cible: str = ".") -> str:
        """Repli pour les formats sans analyseur dédié : repère par le texte les algorithmes et protocoles cités. Résultats à confirmer."""
        return inventaire(_textuel.rechercher_algorithmes(cible, racine=racine))

    # --- Cartographe ---

    def lister_trouvailles(page: int = 1) -> str:
        """Liste les trouvailles enregistrées par l'inventaire (identifiant | type | nom | fichier), par pages de 20."""
        tout = session.trouvailles()
        debut = (max(page, 1) - 1) * TAILLE_PAGE
        lignes = [f"Trouvailles {debut + 1} à {min(debut + TAILLE_PAGE, len(tout))} sur {len(tout)} (page {page}/{max(1, -(-len(tout) // TAILLE_PAGE))})"]
        for e in tout[debut : debut + TAILLE_PAGE]:
            t = e["trouvaille"]
            marque = " | indice à confirmer" if "confiance" in t["proprietes"] else ""
            lignes.append(f"{e['id']} | {t['type_actif']} | {_court(t['nom'], 50)} | {t['fichier'] or 'implicite'}{marque}")
        return "\n".join(lignes)

    def construire_cbom(exclure: list[str] | None = None) -> str:
        """Construit le CBOM CycloneDX 1.6 à partir de toutes les trouvailles, sauf les identifiants à exclure (faux positifs). Le CBOM est enregistré dans la session."""
        from quantum_ready.outils.commun import Trouvaille
        from quantum_ready.outils.construire_cbom import construire_cbom as _construire

        exclues = set(exclure or [])
        inconnues = sorted(exclues - {e["id"] for e in session.trouvailles()})
        retenues = [Trouvaille.model_validate(e["trouvaille"]) for e in session.trouvailles() if e["id"] not in exclues]
        resultat = _construire(retenues, session.nom_systeme)
        if resultat.erreurs:
            return "ERREUR : " + " ; ".join(resultat.erreurs)
        ecrire_json(session.fichier_cbom, resultat.cbom)
        lignes = [f"CBOM enregistré : {resultat.nombre_de_composants} composants, {len(retenues)} trouvailles retenues, {len(exclues) - len(inconnues)} exclues, {len(resultat.fusions)} fusions."]
        if inconnues:
            lignes.append(f"Identifiants à exclure inconnus (ignorés) : {', '.join(inconnues)}")
        lignes += [f"- fusion : {_court(f)}" for f in resultat.fusions[:5]]
        return "\n".join(lignes)

    def valider_schema() -> str:
        """Valide le CBOM enregistré contre le schéma CycloneDX 1.6 et vérifie sa cohérence interne."""
        from quantum_ready.outils.valider_schema import valider_schema as _valider

        if not session.fichier_cbom.is_file():
            return "ERREUR : aucun CBOM enregistré, appeler construire_cbom d'abord"
        validation = _valider(lire_json(session.fichier_cbom, {}))
        return "CBOM VALIDE (CycloneDX 1.6)" if validation.valide else "CBOM INVALIDE :\n" + "\n".join(f"- {_court(e, 200)}" for e in validation.erreurs)

    # --- Analyste risque ---

    def lister_actifs(page: int = 1) -> str:
        """Liste les actifs du CBOM (réf | type | nom | exposition | lieu | indices), par pages de 20, pour choisir x et y de chacun."""
        cbom = lire_json(session.fichier_cbom, {})
        composants = cbom.get("components", [])
        if not composants:
            return "ERREUR : aucun CBOM enregistré"
        debut = (max(page, 1) - 1) * TAILLE_PAGE
        lignes = [f"Actifs {debut + 1} à {min(debut + TAILLE_PAGE, len(composants))} sur {len(composants)} (page {page}/{-(-len(composants) // TAILLE_PAGE)})"]
        for c in composants[debut : debut + TAILLE_PAGE]:
            props = {p["name"].split(":")[-1]: p["value"] for p in c.get("properties", [])}
            indices = [f"{k}={_court(props[k], 50)}" for k in ("duree-conservation-jours", "faiblesse-classique", "contexte") if k in props]
            type_actif = c.get("cryptoProperties", {}).get("assetType", c["type"])
            lieu = c["evidence"]["occurrences"][0]["location"]
            lignes.append(f"{c['bom-ref']} | {type_actif} | {_court(c['name'], 45)} | {props.get('exposition-quantique', '?')} | {_court(lieu, 40)}"
                          + (" | " + " ; ".join(indices) if indices else ""))
        return "\n".join(lignes)

    def score_mosca(evaluations: list[Evaluation]) -> str:
        """Calcule le score de Mosca d'un ou plusieurs actifs. x et y sont choisis par l'agent ; l'exposition vient du CBOM et z de la configuration."""
        from quantum_ready.outils.score_mosca import score_mosca as _score

        cbom = lire_json(session.fichier_cbom, {})
        expositions = {c["bom-ref"]: next((p["value"] for p in c.get("properties", []) if p["name"].endswith("exposition-quantique")), "inconnue")
                       for c in cbom.get("components", [])}
        scores = lire_json(session.fichier_scores, {})
        lignes = []
        for evaluation in evaluations:
            if evaluation.ref not in expositions:
                lignes.append(f"{evaluation.ref} | ERREUR : référence absente du CBOM")
                continue
            resultat = _score(evaluation.x, evaluation.y, horizon_menace, expositions[evaluation.ref])
            if not resultat.valide:
                lignes.append(f"{evaluation.ref} | ERREUR : {' ; '.join(resultat.erreurs)}")
                continue
            scores[evaluation.ref] = resultat.model_dump() | {"justification": evaluation.justification, "exposition": expositions[evaluation.ref]}
            lignes.append(f"{evaluation.ref} | score {resultat.score} | {resultat.priorite} | marge {resultat.marge:+g}")
        ecrire_json(session.fichier_scores, scores)
        manquants = len(expositions) - len(scores)
        return "\n".join(lignes + [f"{len(scores)} actif(s) évalué(s), {manquants} restant(s)."])

    # --- Architecte ---

    def lister_priorites(nombre: int = 15) -> str:
        """Liste les actifs les plus prioritaires d'après les scores de Mosca (réf | score | priorité | nom | lieu | justification)."""
        scores = lire_json(session.fichier_scores, {})
        if not scores:
            return "ERREUR : aucun score enregistré (l'Analyste risque n'a pas encore travaillé)"
        cbom = lire_json(session.fichier_cbom, {})
        composants = {c["bom-ref"]: c for c in cbom.get("components", [])}
        classes = sorted(scores.items(), key=lambda s: (-s[1]["score"], s[0]))[: max(1, nombre)]
        lignes = [f"{len(classes)} actifs les plus prioritaires sur {len(scores)} (horizon z = {horizon_menace:g} ans)"]
        for ref, s in classes:
            c = composants.get(ref, {})
            lieu = c.get("evidence", {}).get("occurrences", [{}])[0].get("location", "?")
            lignes.append(f"{ref} | {s['score']} | {s['priorite']} | {_court(c.get('name', '?'), 40)} | {_court(lieu, 35)} | {_court(s.get('justification', ''), 60)}")
        return "\n".join(lignes)

    def rechercher_standard(requete: str, nombre: int = 3) -> str:
        """Cherche dans le corpus de normes (NIST FIPS 203/204/205, NIST IR 8547, ANSSI, IETF, OpenSSH...) les passages utiles. Citer l'identifiant de fiche dans le plan."""
        from quantum_ready.outils.rechercher_standard import rechercher_standard as _rechercher

        resultat = _rechercher(requete, nombre)
        if resultat.erreurs:
            return "\n".join(f"ERREUR : {e}" for e in resultat.erreurs)
        return "\n".join(f"[{e.fiche}] {_court(e.texte, 420)}" for e in resultat.extraits)

    return {f.__name__: f for f in (
        lister_priorites, rechercher_standard,
        lister_fichiers, analyser_x509, analyser_cle, analyser_pkcs12, analyser_configuration, scanner_code_crypto,
        analyser_dependances, rechercher_algorithmes, lister_trouvailles, construire_cbom, valider_schema, lister_actifs, score_mosca,
    )}
