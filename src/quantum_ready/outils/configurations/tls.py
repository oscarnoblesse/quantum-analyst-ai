"""Développement d'une chaîne de suites TLS (« HIGH:!aNULL:!MD5 ») avec `openssl ciphers -v`.

Une macro comme HIGH ne dit rien en elle-même : il faut demander à OpenSSL quelles
suites elle active. C'est là qu'apparaissent les suites TLS 1.2 à échange de clés
RSA (Kx=RSA), sans confidentialité persistante et cassées par Shor : un actif caché.
Le résultat dépend de la version d'OpenSSL, qui est donc notée.
"""

from __future__ import annotations

import shutil
import subprocess


def version_openssl() -> str | None:
    if shutil.which("openssl") is None:
        return None
    return subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=10).stdout.strip()


def developper_suites(chaine: str) -> list[dict[str, str]] | None:
    """Suites TLS 1.2 (et antérieures) activées par une chaîne ; None si openssl est absent."""
    if shutil.which("openssl") is None:
        return None
    sortie = subprocess.run(["openssl", "ciphers", "-v", chaine], capture_output=True, text=True, timeout=10)
    if sortie.returncode != 0:
        return []
    suites = []
    for ligne in sortie.stdout.splitlines():
        champs = ligne.split()
        if len(champs) < 3 or champs[1] == "TLSv1.3":
            continue  # les suites TLS 1.3 ne sont pas réglées par cette chaîne
        infos = dict(champ.split("=", 1) for champ in champs[2:] if "=" in champ)
        suites.append({"nom": champs[0], "protocole": champs[1], "echange": infos.get("Kx", "?"), "chiffrement": infos.get("Enc", "?")})
    return suites


def resume_suites(chaine: str) -> tuple[dict, list[str]]:
    """Propriétés à joindre à la trouvaille d'une chaîne de suites, et suites à échange RSA."""
    suites = developper_suites(chaine)
    if suites is None:
        return {"developpement": "openssl absent : chaîne non développée"}, []
    echange_rsa = [s["nom"] for s in suites if s["echange"] == "RSA"]
    props = {
        "nombre_de_suites_tls12": len(suites),
        "echanges_de_cles": sorted({s["echange"] for s in suites}),
        "developpe_avec": version_openssl() or "openssl",
    }
    if echange_rsa:
        props["suites_echange_rsa"] = echange_rsa
    return props, echange_rsa
