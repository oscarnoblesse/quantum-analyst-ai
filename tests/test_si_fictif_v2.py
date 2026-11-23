"""Tests du SI v2 (Fret Lab) : générateur, vérité terrain, leurres, contrôles et CBOM attendu."""

import csv
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from quantum_ready.si_fictif import controles_v2
from quantum_ready.si_fictif.generateur import ErreurGenerateur, generer
from quantum_ready.verite_terrain import COLONNES, charger_csv, convertir

RACINE = Path(__file__).resolve().parents[1]
CSV_V1 = RACINE / "data" / "ground_truth" / "verite_terrain_v1.csv"
CSV_V2 = RACINE / "data" / "ground_truth" / "verite_terrain_v2.csv"
JSON_V2 = RACINE / "data" / "ground_truth" / "si_v2.json"
LEURRES_V2 = RACINE / "data" / "ground_truth" / "leurres_v2.csv"
CBOM_V2 = RACINE / "data" / "ground_truth" / "cbom_attendu_v2.json"

# Fichiers dont le contenu change d'une génération à l'autre parce qu'ils contiennent une
# clé, un certificat (clé publique, signature, dates) ou un secret tirés au hasard.
ALEATOIRES = {
    "pki/racine/ac-racine.pem", "pki/exploitation/ac-exploitation.pem", "portail/tls/suivi.crt",
    "portail/tls/suivi.key", "portail/tls/chaine.pem", "portail/tls/tickets.key", "edi/certs/edi-douane.der",
    "edi/certs/edi-douane.p12", "edi/certs/ca.pem", "edi/certs/procedure_douane.txt", "edi/.env",
    "flotte/certs/camion-0427.crt", "flotte/certs/camion-0427.key", "lettres/cles/signature-cmr.pem",
    "sauvegardes/2021/exploitation.bak", "flotte/passerelle-java/src/main/resources/keystore.jks",
    "flotte/passerelle-java/src/main/resources/application-prod.properties",
    "suivi/tests/donnees/certificat_test.pem", "suivi/app/securite/cles_partenaires.py", "suivi/.env",
    "sso/metadata/idp-metadata.xml", "dns/zones/db.fret.lab.local", "vpn/ipsec.secrets", "vpn/wg0.conf",
    "vpn/agences.ovpn", "exploitation/gpg/sauvegarde_pub.asc", "exploitation/gpg/partenaires/douane.asc",
    "bastion/ssh/authorized_keys.d/exploitation", "postes/chef-quai/.ssh/known_hosts",
    "postes/chef-quai/.ssh/id_ecdsa", "postes/chef-quai/.ssh/id_ecdsa.pub", "depot/ssh/id_dsa_routeur",
    *(f"bastion/ssh/ssh_host_{t}_key{s}" for t in ("ecdsa", "rsa", "ed25519") for s in ("", ".pub")),
}


@pytest.fixture(scope="module")
def actifs():
    return charger_csv(CSV_V2)


@pytest.fixture(scope="module")
def si(tmp_path_factory) -> Path:
    racine = tmp_path_factory.mktemp("si") / "v2"
    generer(racine, variante="v2")
    return racine


@pytest.fixture(scope="module")
def leurres():
    return controles_v2.charger_leurres(LEURRES_V2)


def contenus(racine: Path) -> dict[str, bytes]:
    return {f.relative_to(racine).as_posix(): f.read_bytes() for f in racine.rglob("*") if f.is_file()}


# --- Générateur ---


def test_variante_inconnue_refusee(tmp_path):
    with pytest.raises(ErreurGenerateur, match="Variante inconnue"):
        generer(tmp_path / "v9", variante="v9")
    assert not (tmp_path / "v9").exists()


def test_secrets_hors_du_si(si):
    secrets = json.loads((si.parent / "hors_si" / "v2" / "secrets.json").read_text(encoding="utf-8"))
    assert {"SECRET_JWT", "CLE_ADRESSES", "EDI_CONTENEUR_SECRET", "MOT_DE_PASSE_KEYSTORE", "PSK_IPSEC"} <= set(secrets)
    assert not (si / "secrets.json").exists()


def test_generation_deterministe_hors_cles(si, tmp_path):
    seconde = tmp_path / "v2"
    generer(seconde, variante="v2")
    premier, deuxieme = contenus(si), contenus(seconde)
    assert set(premier) == set(deuxieme), "l'arborescence doit être identique"
    differents = {chemin for chemin in premier if premier[chemin] != deuxieme[chemin]}
    assert differents <= ALEATOIRES, f"contenus non déterministes : {sorted(differents - ALEATOIRES)}"
    # Les métadonnées attendues (algorithme, taille, courbe, durées) ne changent pas.
    resultats = controles_v2.verifier(seconde, [a.id for a in charger_csv(CSV_V2)])
    assert [i for i, m in resultats.items() if m] == []


# --- Contrôles ---


def test_controles_100_sur_100(si, actifs):
    resultats = controles_v2.verifier(si, [a.id for a in actifs])
    assert {i: m for i, m in resultats.items() if m} == {}
    assert len(resultats) == 100


def test_aucun_fichier_cryptographique_hors_verite_terrain(si, actifs, leurres):
    references = [f"{a.fichier}\n{a.notes}" for a in actifs] + [l["Fichier / emplacement"] for l in leurres]
    assert controles_v2.fichiers_non_inventories(si, references) == []


def test_main_des_controles(si, capsys):
    assert controles_v2.main([str(si), str(CSV_V2), str(LEURRES_V2)]) == 0
    assert "100/100 actifs conformes, 0 fichier(s) en trop" in capsys.readouterr().out


def test_un_controle_par_actif(actifs):
    assert set(controles_v2.CONTROLES) == {a.id for a in actifs}


@pytest.fixture
def copie(si, tmp_path) -> Path:
    cible = tmp_path / "v2"
    shutil.copytree(si, cible)
    shutil.copytree(si.parent / "hors_si", tmp_path / "hors_si")
    return cible


def test_ecart_de_configuration_detecte(copie):
    sshd = copie / "bastion/ssh/sshd_config"
    sshd.write_text(sshd.read_text().replace("mlkem768x25519-sha256,", ""), encoding="utf-8")
    assert controles_v2.verifier(copie, ["V2-031"])["V2-031"]


def test_ecart_de_cle_detecte(copie):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (copie / "portail/tls/suivi.key").write_bytes(cle.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    assert controles_v2.verifier(copie, ["V2-067"])["V2-067"]  # même taille, mais ≠ certificat


def test_fichier_absent_detecte(copie):
    (copie / "vpn/ipsec.conf").unlink()
    resultats = controles_v2.verifier(copie, ["V2-091", "V2-092"])
    assert all("fichier absent" in m for m in resultats.values())


def test_fichier_cryptographique_en_trop_detecte(copie, actifs):
    (copie / "divers").mkdir()
    shutil.copy(copie / "portail/tls/suivi.key", copie / "divers/oubli.pem")
    references = [f"{a.fichier}\n{a.notes}" for a in actifs]
    assert "divers/oubli.pem" in controles_v2.fichiers_non_inventories(copie, references)


def test_actif_sans_controle_signale(si):
    assert controles_v2.verifier(si, ["V2-999"]) == {"V2-999": "aucun contrôle écrit pour cet actif"}


# --- Lecture par des outils tiers ---


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")
def test_cle_dsa_lue_par_openssl(si):
    sortie = subprocess.run(["openssl", "pkey", "-in", str(si / "depot/ssh/id_dsa_routeur"), "-noout",
                             "-text_pub"], capture_output=True, text=True, check=True).stdout
    assert "1024 bit" in sortie


def test_keystore_jks_lu_par_pyjks(si):
    jks = pytest.importorskip("jks")
    mot_de_passe = json.loads((si.parent / "hors_si/v2/secrets.json").read_text())["MOT_DE_PASSE_KEYSTORE"]
    magasin = jks.KeyStore.load(str(si / "flotte/passerelle-java/src/main/resources/keystore.jks"), mot_de_passe)
    assert magasin.store_type == "jks"
    (entree,) = magasin.private_keys.values()
    assert entree.algorithm_oid == (1, 2, 840, 113549, 1, 1, 1)  # rsaEncryption
    assert len(entree.cert_chain) == 3


@pytest.mark.skipif(shutil.which("keytool") is None or shutil.which("java") is None, reason="JDK absent")
def test_keystore_jks_lu_par_keytool(si):
    mot_de_passe = json.loads((si.parent / "hors_si/v2/secrets.json").read_text())["MOT_DE_PASSE_KEYSTORE"]
    resultat = subprocess.run(["keytool", "-list", "-keystore",
                               str(si / "flotte/passerelle-java/src/main/resources/keystore.jks"),
                               "-storepass", mot_de_passe], capture_output=True, text=True)
    if "Unable to locate a Java Runtime" in resultat.stderr + resultat.stdout:
        pytest.skip("JDK absent")
    assert resultat.returncode == 0 and "passerelle" in resultat.stdout


def _gpg(dossier: Path, *arguments: str) -> subprocess.CompletedProcess:
    """gpg avec un dossier personnel en chemin « / » (accepté aussi par le gpg MSYS de Git for Windows)."""
    return subprocess.run(["gpg", "--homedir", dossier.as_posix(), "--batch", *arguments],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def _echec_gpg(etape: str, resultat: subprocess.CompletedProcess) -> None:
    """Échec de gpg : un vrai échec sous Linux et macOS ; sous Windows seulement, un saut motivé.

    La lecture OpenPGP est vérifiée par gpg en CI sur ubuntu et macOS : le repli Windows ne
    retire donc aucune vérification du format, seulement la répétition avec le gpg de Git for Windows.
    """
    erreur = resultat.stderr.strip()
    if sys.platform == "win32":
        pytest.skip(f"gpg de Git for Windows (MSYS) : {etape} en échec (code {resultat.returncode}) : {erreur} "
                    "— lecture OpenPGP vérifiée par gpg en CI sur ubuntu et macOS")
    pytest.fail(f"gpg : {etape} en échec (code {resultat.returncode}) : {erreur}")


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg absent")
def test_cles_openpgp_importees_par_gpg(si):
    # Dossier court : gpg joint son agent par un socket placé dans ce dossier, et le chemin d'un
    # socket est limité (~104 caractères sous macOS) ; le dossier temporaire de pytest est trop long.
    dossier = Path(tempfile.mkdtemp(prefix="gpg", dir="/tmp" if Path("/tmp").is_dir() else None))
    dossier.chmod(0o700)
    try:
        for chemin in ("exploitation/gpg/sauvegarde_pub.asc", "exploitation/gpg/partenaires/douane.asc"):
            resultat = _gpg(dossier, "--import", (si / chemin).as_posix())
            if resultat.returncode != 0:
                _echec_gpg(f"import de {chemin}", resultat)
        resultat = _gpg(dossier, "--with-colons", "--list-keys")
        if resultat.returncode != 0:
            _echec_gpg("--list-keys", resultat)
        algorithmes = sorted(l.split(":")[3] for l in resultat.stdout.splitlines() if l.startswith("pub:"))
        assert algorithmes == ["1", "22"], resultat.stderr  # RSA et EdDSA
    finally:
        if shutil.which("gpgconf"):
            subprocess.run(["gpgconf", "--homedir", dossier.as_posix(), "--kill", "gpg-agent"], capture_output=True)
        shutil.rmtree(dossier, ignore_errors=True)


# --- Vérité terrain v2 ---


def test_colonnes_identiques_a_la_v1_plus_perimetre():
    with CSV_V1.open(encoding="utf-8") as v1, CSV_V2.open(encoding="utf-8") as v2:
        entete_v1, entete_v2 = next(csv.reader(v1)), next(csv.reader(v2))
    assert entete_v1 == list(COLONNES)
    assert entete_v2 == entete_v1 + ["Périmètre"]


def test_identifiants_continus(actifs):
    assert [a.id for a in actifs] == [f"V2-{i:03d}" for i in range(1, 101)]


def test_decompte(actifs):
    assert sum(a.perimetre == "connu" for a in actifs) == 80
    assert sum(a.perimetre == "hors périmètre" for a in actifs) == 20
    caches = [a for a in actifs if a.est_cache]
    assert len(caches) == 27
    assert sum(a.perimetre == "connu" for a in caches) == 20
    assert sum(a.perimetre == "hors périmètre" for a in caches) == 7


def test_seuils_du_sujet(actifs):
    assert len(actifs) >= 40 and sum(a.est_cache for a in actifs) >= 25


def test_hors_perimetre_au_moins_six_technologies(actifs):
    assert len({a.composant for a in actifs if a.perimetre == "hors périmètre"}) >= 6


def test_au_moins_deux_usages_post_quantiques(actifs):
    hybrides = {a.id: a.vulnerabilite for a in actifs if "mlkem" in a.algorithme.lower()}
    # SSH : hybrides seuls → Non ; nginx : groupes de repli classiques → Shor.
    assert hybrides == {"V2-020": "Oui (Shor)", "V2-031": "Non"}


def test_melange_de_vulnerabilites(actifs):
    texte = " ".join(a.algorithme for a in actifs)
    for algorithme in ("RSA", "ECDSA", "X25519", "DH", "DSA", "AES-128", "MD5", "SHA-1", "RC4", "3DES",
                       "RSA-1024", "AES-256", "SHA-384"):
        assert algorithme in texte, algorithme


def test_un_seul_fichier_principal(actifs):
    for actif in actifs:
        assert "(+" not in actif.fichier and "," not in actif.fichier and " " not in actif.fichier, actif.id


def test_chaque_cache_dit_pourquoi(actifs):
    for actif in actifs:
        if actif.est_cache:
            assert len(actif.notes.split(":", 1)[1].strip()) > 20, actif.id


def test_json_a_jour(tmp_path):
    sortie = tmp_path / "si_v2.json"
    convertir(CSV_V2, sortie)
    assert sortie.read_text(encoding="utf-8") == JSON_V2.read_text(encoding="utf-8")


ESPACES_DE_NOMS = {"www.w3.org"}  # identifiants d'espaces de noms XML, pas des hôtes contactés


def test_aucun_domaine_reel(si):
    for fichier in si.rglob("*"):
        if fichier.is_file() and fichier.suffix not in (".der", ".p12", ".jks", ".key"):
            texte = fichier.read_text(encoding="utf-8", errors="ignore")
            for domaine in re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(?:com|fr|org|net|io)\b", texte):
                if domaine in ESPACES_DE_NOMS:
                    continue
                pytest.fail(f"domaine non fictif dans {fichier.name} : {domaine}")


# --- Leurres ---


def test_leurres(leurres, si, actifs):
    assert len(leurres) == 8
    assert [l["ID"] for l in leurres] == [f"L2-{i:02d}" for i in range(1, 9)]
    for leurre in leurres:
        assert (si / leurre["Fichier / emplacement"]).is_file(), leurre["ID"]


# --- CBOM attendu ---


def _module_cbom():
    spec = importlib.util.spec_from_file_location("cbom_attendu", RACINE / "scripts" / "cbom_attendu.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cbom_attendu_regenere_a_l_identique(tmp_path):
    sortie = tmp_path / "cbom.json"
    assert _module_cbom().main([str(CSV_V2), str(sortie)]) == 0
    assert sortie.read_text(encoding="utf-8") == CBOM_V2.read_text(encoding="utf-8")


def test_cbom_attendu_valide(actifs):
    from quantum_ready.outils.valider_schema import valider_schema

    cbom = json.loads(CBOM_V2.read_text(encoding="utf-8"))
    assert valider_schema(cbom).valide
    assert [c["bom-ref"] for c in cbom["components"]] == [a.id for a in actifs]
    certificats = [c for c in cbom["components"] if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert len(certificats) == 7
