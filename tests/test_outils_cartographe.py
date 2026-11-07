"""construire_cbom et valider_schema : fusion des doublons, CycloneDX 1.6 valide et reproductible."""

import copy
import json

import pytest

from quantum_ready.outils.analyser_cle import analyser_cle
from quantum_ready.outils.analyser_configuration import analyser_configuration
from quantum_ready.outils.analyser_dependances import analyser_dependances
from quantum_ready.outils.analyser_x509 import analyser_x509
from quantum_ready.outils.commun import Trouvaille
from quantum_ready.outils.construire_cbom import construire_cbom, primitive
from quantum_ready.outils.valider_schema import valider_schema


@pytest.fixture(scope="module")
def trouvailles(racine_si):
    resultats = [
        *(analyser_x509(f, racine=racine_si) for f in ("certs/ca/racine.crt", "nginx/ssl/ca_clients.crt", "nginx/ssl/fullchain.pem", "nginx/ssl/server.crt")),
        *(analyser_cle(f, racine=racine_si) for f in ("ssh/server/ssh_host_ed25519_key", "ssh/server/ssh_host_ed25519_key.pub", "clients/admin/.ssh/known_hosts")),
        analyser_configuration("nginx/nginx.conf", racine=racine_si),
        analyser_dependances("api", racine=racine_si),
    ]
    return [t for r in resultats for t in r.trouvailles]


@pytest.fixture(scope="module")
def cbom(trouvailles, monkeypatch_module):
    monkeypatch_module.setenv("SOURCE_DATE_EPOCH", "1767225600")
    resultat = construire_cbom(trouvailles, "SI de test")
    assert resultat.erreurs == []
    return resultat


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def _composants(resultat, nom):
    return [c for c in resultat.cbom["components"] if c["name"] == nom]


def test_le_cbom_est_valide(cbom):
    validation = valider_schema(cbom.cbom)
    assert validation.valide, validation.erreurs
    assert cbom.cbom["specVersion"] == "1.6" and cbom.cbom["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"


def test_un_certificat_present_dans_deux_fichiers_est_fusionne(cbom):
    (racine,) = _composants(cbom, "Certificat « Lab Root CA »")
    lieux = [o["location"] for o in racine["evidence"]["occurrences"]]
    assert lieux == ["certs/ca/racine.crt", "nginx/ssl/ca_clients.crt"]
    proprietes = racine["cryptoProperties"]["certificateProperties"]
    references = {c["bom-ref"]: c["name"] for c in cbom.cbom["components"]}
    assert references[proprietes["signatureAlgorithmRef"]] == "sha256WithRSAEncryption"
    assert references[proprietes["subjectPublicKeyRef"]] == "RSA-4096"


def test_cle_ssh_et_son_pub_fusionnees_mais_pas_known_hosts(cbom):
    ed25519 = _composants(cbom, "Ed25519")
    assert sorted(len(c["evidence"]["occurrences"]) for c in ed25519) == [1, 2]
    types = sorted(c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] for c in ed25519)
    assert types == ["private-key", "public-key"]


def test_traduction_des_types(cbom):
    composants = cbom.cbom["components"]
    pycryptodome = next(c for c in composants if c["name"] == "pycryptodome")
    assert pycryptodome["type"] == "library" and pycryptodome["purl"] == "pkg:pypi/pycryptodome@3.9.9"
    implicite = next(c for c in composants if c["evidence"]["occurrences"][0]["location"].startswith("implicite"))
    assert {"name": "quantum-ready:implicite", "value": "true"} in implicite["properties"]
    tls = next(c for c in composants if c["name"] == "TLSv1.2 TLSv1.3")
    assert tls["cryptoProperties"]["protocolProperties"] == {"type": "tls", "version": "1.2 1.3"}


def test_reproductible(trouvailles, cbom):
    deuxieme = construire_cbom(list(trouvailles), "SI de test")
    assert json.dumps(deuxieme.cbom, sort_keys=True) == json.dumps(cbom.cbom, sort_keys=True)


def test_entrees_invalides():
    assert "Aucune trouvaille" in construire_cbom([]).erreurs[0]
    assert "invalides" in construire_cbom([{"nom": "x"}]).erreurs[0]


@pytest.mark.parametrize(
    ("nom", "description", "attendu"),
    [("MD5", "Empreinte MD5", "hash"), ("Argon2id", "Hachage", "kdf"), ("HMAC-SHA-256", "Code", "mac"),
     ("ecdsa-with-SHA384", "Signature", "signature"), ("DH-2048", "Paramètres", "key-agree"),
     ("Mersenne Twister (module random)", "Aléa", "drbg"), ("PermitRootLogin", "Option", "other")],
)
def test_primitive(nom, description, attendu):
    trouvaille = Trouvaille(outil="t", fichier="f", type_actif="algorithm", nom=nom, description=description, exposition="inconnue")
    assert primitive(trouvaille) == attendu


def test_validation_detecte_les_erreurs(cbom):
    casse = copy.deepcopy(cbom.cbom)
    casse["components"][0]["cryptoProperties"]["assetType"] = "inconnu"
    assert not valider_schema(casse).valide
    renvoi = copy.deepcopy(cbom.cbom)
    certificat = next(c for c in renvoi["components"] if c.get("cryptoProperties", {}).get("assetType") == "certificate")
    certificat["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"] = "absent"
    renvoi["components"].append(copy.deepcopy(renvoi["components"][0]))
    erreurs = valider_schema(json.dumps(renvoi)).erreurs
    assert any("absent" in e for e in erreurs) and any("double" in e for e in erreurs)
    assert "JSON invalide" in valider_schema("{pas du json").erreurs[0]
