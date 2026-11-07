"""YAML et JSON : configuration structurée, aplatie en « chemin.de.cle = valeur ».

docker-compose, Kubernetes, application.yml, config.json... ont tous la même forme :
un arbre de clés. On l'aplatit (« jwt.secret », « services.db.environment.MYSQL_ROOT_PASSWORD »)
puis on applique la même analyse que pour un .env : secrets, URL de connexion,
réglages TLS désactivés, noms d'algorithmes. Les listes « - NOM=valeur » de
docker-compose sont comprises comme des variables d'environnement.
"""

from __future__ import annotations

import json
import re

from quantum_ready.outils.commun import ErreurOutil, Piste, Trouvaille
from quantum_ready.outils.configurations.env import analyser_variables


def aplatir(objet, prefixe: str = ""):
    if isinstance(objet, dict):
        for cle, valeur in objet.items():
            yield from aplatir(valeur, f"{prefixe}.{cle}" if prefixe else str(cle))
    elif isinstance(objet, list):
        for i, valeur in enumerate(objet):
            if isinstance(valeur, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", valeur):
                nom, contenu = valeur.split("=", 1)
                yield (f"{prefixe}.{nom}" if prefixe else nom), contenu
            else:
                yield from aplatir(valeur, f"{prefixe}[{i}]")
    elif objet is not None and not isinstance(objet, bool | int | float) or isinstance(objet, bool):
        yield prefixe, objet if not isinstance(objet, bool) else str(objet).lower()


def _ligne(texte: str, chemin: str) -> int | None:
    """Ligne approximative d'une clé : la première où apparaît son dernier élément."""
    dernier = re.sub(r"\[\d+\]$", "", chemin.split(".")[-1])
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if re.search(rf"(^|[\s\"'-]){re.escape(dernier)}[\"']?\s*[:=]", ligne):
            return numero
    return None


def _analyser(objets, texte: str, fichier: str, lieu: str) -> tuple[list[Trouvaille], list[Piste]]:
    variables = [(_ligne(texte, chemin), chemin, valeur) for objet in objets for chemin, valeur in aplatir(objet)]
    return analyser_variables(variables, fichier, lieu)


def analyser_yaml(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    import yaml

    try:
        documents = [d for d in yaml.safe_load_all(texte) if d is not None]
    except yaml.YAMLError as erreur:
        raise ErreurOutil(f"YAML invalide : {erreur}") from erreur
    return _analyser(documents, texte, fichier, "un fichier YAML")


def analyser_json(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    try:
        return _analyser([json.loads(texte)], texte, fichier, "un fichier JSON")
    except ValueError as erreur:
        raise ErreurOutil(f"JSON invalide : {erreur}") from erreur
