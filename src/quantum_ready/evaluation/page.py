"""Génère la page de résultats (docs/site/index.html) à partir de results/metrics.json.

Aucune valeur n'est saisie à la main : la page est une vue de metrics.json. Tout texte venant des
fichiers est échappé ; la page n'a ni script, ni ressource externe, ni police distante.

Usage : uv run python -m quantum_ready.evaluation.page
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
METRIQUES = RACINE / "results" / "metrics.json"
SORTIE = RACINE / "docs" / "site" / "index.html"


def _e(valeur) -> str:
    return html.escape("—" if valeur is None else str(valeur))


def _cellule_ecart(moyenne, ecart) -> str:
    if moyenne is None:
        return "—"
    return f"{moyenne:g} ± {ecart:g}" if ecart is not None else f"{moyenne:g} (une seule mesure)"


def _tableau(entetes: list[str], lignes: list[list[str]]) -> str:
    tete = "".join(f"<th>{_e(h)}</th>" for h in entetes)
    corps = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in ligne) + "</tr>" for ligne in lignes)
    return f"<table><thead><tr>{tete}</tr></thead><tbody>{corps}</tbody></table>"


def _latence(bench: dict | None) -> str:
    if not bench:
        return "<p>Pas de mesure de latence.</p>"
    lignes = []
    for nom, c in bench["configurations"].items():
        lignes.append([
            _e(nom), _e(c["groupe"]), _e(c["certificat_type"]),
            _e(_cellule_ecart(c["mediane_us"], c.get("mediane_ecart_type_us"))),
            _e(c["client_hello_octets"]), _e(c["certificat_octets"]), _e(c["certificate_verify_octets"]),
            _e(c["repetitions_faites"]),
        ])
    return (
        f"<p>{_e(bench['echantillons'])} handshakes après {_e(bench['echauffement'])} d'échauffement, "
        f"{_e(bench.get('repetitions', '?'))} répétitions, OpenSSL : {_e(bench['openssl'])}. "
        f"Hybride / classique (certificat ECDSA) : rapport {_e(bench['rapport_mediane_hybride_sur_classique'])}.</p>"
        + _tableau(["Configuration", "Échange", "Certificat", "Médiane (µs)", "ClientHello (o)", "Certificate (o)",
                    "CertificateVerify (o)", "Répétitions"], lignes)
    )


def _signatures(sig: dict | None) -> str:
    if not sig:
        return "<p>Pas de mesure de signature.</p>"
    lignes = []
    for nom, a in sig["algorithmes"].items():
        lignes.append([
            _e(nom), _e(a["cle_publique_octets"]), _e(a["signature_octets"]),
            _e(_cellule_ecart(a["generation"]["moyenne_us"], a["generation"]["ecart_type_us"])),
            _e(_cellule_ecart(a["signature"]["moyenne_us"], a["signature"]["ecart_type_us"])),
            _e(_cellule_ecart(a["verification"]["moyenne_us"], a["verification"]["ecart_type_us"])),
        ])
    return (
        f"<p>{_e(sig['repetitions'])} répétitions de {_e(sig['mesures'])} mesures, OpenSSL : {_e(sig['openssl'])}. "
        "Temps en microsecondes, moyenne ± écart type entre répétitions.</p>"
        + _tableau(["Algorithme", "Clé publique (o)", "Signature (o)", "Génération (µs)", "Signature (µs)",
                    "Vérification (µs)"], lignes)
    )


def _agent(agent: dict | None) -> str:
    if not agent:
        return "<p>Pas d'exécution de l'agent Démonstrateur.</p>"
    lignes = []
    for groupe, cellules in agent["groupes"].items():
        m, h = cellules["mediane_us"], cellules["client_hello_octets"]
        lignes.append([_e(groupe), _e(_cellule_ecart(m["moyenne"], m["ecart_type"])), _e(h["moyenne"])])
    return (
        f"<p>{_e(agent['executions'])} exécution(s), {_e(agent['terminees'])} terminée(s), "
        f"{_e(agent['appels_refuses_total'])} appel(s) refusé(s), {_e(agent['appels_en_double_total'])} en double, "
        f"{_e(agent['erreurs_outils_total'])} erreur(s) d'outil. Modèle : {_e(', '.join(agent['modele']))}.</p>"
        + _tableau(["Groupe", "Médiane (µs), moyenne ± écart type", "ClientHello (o)"], lignes)
    )


def _verification(v: dict | None) -> str:
    if not v:
        return "<p>Pas de vérification du laboratoire.</p>"
    etat = "conforme" if v.get("conforme") else "NON conforme"
    return (f"<p>Laboratoire TLS et SSH : <strong>{_e(etat)}</strong> (vérifié le {_e(v.get('date_utc'))}). "
            f"Groupe TLS négocié : {_e(v['tls']['groupe_negocie'])} ; échange SSH négocié : {_e(v['ssh']['kex_negociee'])}. "
            f"Client classique refusé : TLS {_e(v['tls']['classique_refuse'])}, SSH {_e(v['ssh']['classique_refuse'])}.</p>")


def construire(metriques: dict) -> str:
    d = metriques["demonstrateur"]
    avertissements = "".join(f"<li>{_e(a)}</li>" for a in metriques["avertissements"])
    non_mesure = "".join(f"<li>{_e(n)}</li>" for n in metriques["non_mesure"])
    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quantum-Ready : résultats</title>
<style>
:root {{ --fond:#fbfbf9; --texte:#1d1d1b; --discret:#5b5b57; --ligne:#d9d9d4; --accent:#2a5d8f; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --fond:#161615; --texte:#ededeb; --discret:#a3a39e; --ligne:#363634; --accent:#8ab4e0; }} }}
:root[data-theme="dark"] {{ --fond:#161615; --texte:#ededeb; --discret:#a3a39e; --ligne:#363634; --accent:#8ab4e0; }}
body {{ background:var(--fond); color:var(--texte); font:16px/1.5 system-ui,sans-serif; margin:0; padding:16px; }}
main {{ max-width:960px; margin:0 auto; }}
h1 {{ font-size:1.6rem; }} h2 {{ font-size:1.2rem; margin-top:2rem; border-bottom:1px solid var(--ligne); padding-bottom:4px; }}
table {{ border-collapse:collapse; width:100%; font-size:14px; overflow-x:auto; display:block; }}
th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--ligne); vertical-align:top; }}
th {{ color:var(--discret); font-weight:600; }}
.discret {{ color:var(--discret); font-size:14px; }}
a {{ color:var(--accent); }}
</style>
</head>
<body>
<main>
<h1>Quantum-Ready : résultats du laboratoire post-quantique</h1>
<p class="discret">Généré le {_e(metriques['genere_le'])} à partir de <code>results/metrics.json</code>, version {_e(metriques['version'])}.
Aucune valeur n'est saisie à la main ; les fichiers sources sont : {_e(', '.join(metriques['sources']))}.</p>

<h2>Vérification du laboratoire</h2>
{_verification(d['verification'])}

<h2>Latence du handshake TLS 1.3</h2>
{_latence(d['latence_bench_pqc'])}

<h2>Signatures : ML-DSA-65 contre SLH-DSA</h2>
{_signatures(d['signatures'])}

<h2>Agent Démonstrateur</h2>
{_agent(d['agent'])}

<h2>Avertissements</h2>
<ul>{avertissements or '<li>Aucun avertissement.</li>'}</ul>

<h2>Ce qui n'est pas encore mesuré</h2>
<ul>{non_mesure}</ul>
</main>
</body>
</html>
"""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    metriques = json.loads(METRIQUES.read_text(encoding="utf-8"))
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(construire(metriques), encoding="utf-8")
    print(f"Page écrite dans {SORTIE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
