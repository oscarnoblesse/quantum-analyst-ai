"""Contexte d'écriture et enchaînement des étapes du générateur."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

PAQUET = "quantum_ready.si_fictif"
EXTENSION_MODELE = ".tmpl"


class ErreurGenerateur(RuntimeError):
    """Erreur levée quand le générateur ne peut pas produire le SI."""


def lire_modele(chemin: str) -> str:
    """Lit modeles/<chemin>.tmpl dans le paquet."""
    fichier = resources.files(PAQUET).joinpath("modeles", chemin + EXTENSION_MODELE)
    return fichier.read_text(encoding="utf-8")


def remplir(modele: str, variables: dict[str, str]) -> str:
    """Remplace chaque {{NOM}} par sa valeur.

    On n'utilise pas string.Template : les configurations nginx et les scripts shell
    contiennent déjà des $variables qui doivent rester telles quelles.
    """
    for nom, valeur in variables.items():
        modele = modele.replace("{{" + nom + "}}", str(valeur))
    if "{{" in modele:
        reste = modele[modele.index("{{"):].split("}}")[0] + "}}"
        raise ErreurGenerateur(f"Variable de modèle non remplie : {reste}")
    return modele


@dataclass
class Contexte:
    """Où écrire le SI, et ce que les étapes se transmettent."""

    racine_si: Path
    racine_hors_si: Path
    variante: str = "v1"
    # Valeurs partagées entre étapes (secrets, clés publiques déjà générées...).
    valeurs: dict[str, str] = field(default_factory=dict)
    # Fichiers écrits, relatifs à racine_si, dans l'ordre d'écriture.
    fichiers: list[str] = field(default_factory=list)

    def ecrire(self, chemin: str, contenu: str | bytes, prive: bool = False) -> Path:
        """Écrit un fichier du SI. prive=True : droits 600, comme une vraie clé privée."""
        cible = self.racine_si / chemin
        cible.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenu, str):
            cible.write_text(contenu, encoding="utf-8", newline="\n")
        else:
            cible.write_bytes(contenu)
        if prive:
            os.chmod(cible, stat.S_IRUSR | stat.S_IWUSR)
        self.fichiers.append(chemin)
        return cible

    def ecrire_modele(self, chemin: str, sortie: str | None = None, **variables: str) -> Path:
        """Écrit le modèle modeles/<chemin>.tmpl à l'emplacement <sortie> (par défaut <chemin>)."""
        return self.ecrire(sortie or chemin, remplir(lire_modele(chemin), variables))

    def ecrire_hors_si(self, chemin: str, contenu: str | bytes) -> Path:
        """Écrit un fichier HORS du périmètre scanné (clés d'AC, secrets pour le démonstrateur)."""
        cible = self.racine_hors_si / chemin
        cible.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenu, str):
            cible.write_text(contenu, encoding="utf-8", newline="\n")
        else:
            cible.write_bytes(contenu)
        os.chmod(cible, stat.S_IRUSR | stat.S_IWUSR)
        return cible


def generer_secrets(ctx: Contexte) -> None:
    """Tire les secrets aléatoires utilisés par plusieurs étapes.

    Ils changent à chaque génération : la vérité terrain décrit leur forme, pas leur valeur.
    """
    ctx.valeurs["MOT_DE_PASSE_BASE"] = secrets.token_urlsafe(18)
    ctx.valeurs["MOT_DE_PASSE_CONTENEUR_FACTURES"] = secrets.token_urlsafe(12)
    ctx.valeurs["PHRASE_DE_PASSE_ADMIN_MTLS"] = secrets.token_urlsafe(16)


Etape = Callable[[Contexte], None]


def etapes() -> list[Etape]:
    """Les étapes du générateur, dans l'ordre. Chaque module ajoute la sienne."""
    from quantum_ready.si_fictif import code_applicatif, configurations, pki, ssh

    return [
        generer_secrets,
        pki.generer_pki,
        ssh.generer_ssh,
        configurations.generer_config_ssh,
        configurations.generer_config_nginx,
        configurations.generer_config_postgresql,
        code_applicatif.generer_api,
        code_applicatif.generer_factures,
        code_applicatif.generer_dependances,
    ]


def generer(
    racine_si: str | Path,
    racine_hors_si: str | Path | None = None,
    variante: str = "v1",
    ecraser: bool = False,
) -> Contexte:
    """Génère le SI fictif complet dans racine_si."""
    racine_si = Path(racine_si)
    racine_hors_si = Path(racine_hors_si) if racine_hors_si else racine_si.parent / "hors_si" / variante
    for dossier in (racine_si, racine_hors_si):
        if dossier.exists():
            if not ecraser:
                raise ErreurGenerateur(f"{dossier} existe déjà (utiliser ecraser=True)")
            shutil.rmtree(dossier)
    racine_si.mkdir(parents=True)
    ctx = Contexte(racine_si=racine_si, racine_hors_si=racine_hors_si, variante=variante)
    for etape in etapes():
        etape(ctx)
    # Secrets utiles au démonstrateur (connexion mTLS, ouverture du PKCS#12...), hors du SI.
    ctx.ecrire_hors_si("secrets.json", json.dumps(ctx.valeurs, indent=2, ensure_ascii=False) + "\n")
    return ctx
