"""Dossier de session : l'état partagé entre agents, et le journal d'audit.

Les agents s'exécutent l'un après l'autre, chacun avec son propre processus
serveur MCP. Ce qu'ils se transmettent est donc écrit sur disque :

    traces/<session>/
        trouvailles.json         trouvailles de l'inventaire, avec leur identifiant (T0001...)
        cbom.json                CBOM CycloneDX 1.6 construit par le Cartographe
        scores.json              scores de Mosca de l'Analyste risque
        journal_outils.jsonl     un événement par appel d'outil (audit)
        journal_agents.jsonl     un événement par tour d'agent (messages, décisions)
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from quantum_ready.outils.commun import Trouvaille


def maintenant() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ecrire_json(chemin: Path, donnees: Any) -> None:
    """Écriture atomique : un fichier à moitié écrit ne doit jamais être lu par un autre agent."""
    chemin.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=chemin.parent, delete=False, suffix=".tmp") as flux:
        json.dump(donnees, flux, ensure_ascii=False, indent=1)
        temporaire = flux.name
    os.replace(temporaire, chemin)


def lire_json(chemin: Path, defaut: Any) -> Any:
    return json.loads(chemin.read_text(encoding="utf-8")) if chemin.is_file() else defaut


class Session:
    def __init__(self, dossier: str | Path, racine_si: str | Path, nom_systeme: str = "SI fictif"):
        self.dossier = Path(dossier)
        self.dossier.mkdir(parents=True, exist_ok=True)
        self.racine_si = Path(racine_si).resolve()
        self.nom_systeme = nom_systeme

    @property
    def fichier_trouvailles(self) -> Path:
        return self.dossier / "trouvailles.json"

    @property
    def fichier_cbom(self) -> Path:
        return self.dossier / "cbom.json"

    @property
    def fichier_scores(self) -> Path:
        return self.dossier / "scores.json"

    # --- trouvailles ---

    def trouvailles(self) -> list[dict]:
        """[{"id": "T0001", "agent": ..., "trouvaille": {...}}, ...]"""
        return lire_json(self.fichier_trouvailles, [])

    def enregistrer(self, trouvailles: list[Trouvaille], agent: str) -> list[str]:
        """Ajoute des trouvailles et renvoie leurs identifiants. Une trouvaille identique
        (même outil rappelé sur le même fichier) garde son identifiant : pas de doublon."""
        existantes = self.trouvailles()
        par_empreinte = {e["empreinte"]: e["id"] for e in existantes}
        identifiants = []
        for trouvaille in trouvailles:
            contenu = trouvaille.model_dump(mode="json")
            empreinte = hashlib.sha256(json.dumps(contenu, sort_keys=True).encode()).hexdigest()[:16]
            if empreinte not in par_empreinte:
                identifiant = f"T{len(existantes) + 1:04d}"
                existantes.append({"id": identifiant, "agent": agent, "empreinte": empreinte, "trouvaille": contenu})
                par_empreinte[empreinte] = identifiant
            identifiants.append(par_empreinte[empreinte])
        ecrire_json(self.fichier_trouvailles, existantes)
        return identifiants

    # --- journaux ---

    def journaliser(self, fichier: str, evenement: dict) -> None:
        with (self.dossier / fichier).open("a", encoding="utf-8") as flux:
            flux.write(json.dumps({"horodatage": maintenant(), **evenement}, ensure_ascii=False) + "\n")

    def evenements(self, fichier: str) -> list[dict]:
        chemin = self.dossier / fichier
        if not chemin.is_file():
            return []
        return [json.loads(ligne) for ligne in chemin.read_text(encoding="utf-8").splitlines() if ligne.strip()]
