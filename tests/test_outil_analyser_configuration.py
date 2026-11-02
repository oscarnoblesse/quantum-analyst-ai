"""analyser_configuration : un test par format, avec les actifs visibles, cachés et implicites."""

import shutil

import pytest

from quantum_ready.outils.analyser_configuration import analyser_configuration
from quantum_ready.outils.configurations import sshd
from quantum_ready.outils.configurations.tls import developper_suites, resume_suites

openssl_present = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")


def _analyser(racine, fichier):
    resultat = analyser_configuration(fichier, racine=racine)
    assert resultat.erreurs == []
    return resultat


def _par_nom(resultat):
    return {t.nom: t for t in resultat.trouvailles}


# --- nginx ---

def test_nginx_directives_visibles(racine_si):
    trouvailles = _par_nom(_analyser(racine_si, "nginx/nginx.conf"))
    assert trouvailles["TLSv1.2 TLSv1.3"].type_actif == "protocol"
    courbes = trouvailles["X25519:secp256r1"]
    assert courbes.proprietes["hybride_post_quantique"] is False and courbes.exposition == "shor"
    assert trouvailles["Clé des tickets de session TLS"].exposition == "grover"


@openssl_present
def test_nginx_macro_high_cache_des_suites_rsa(racine_si):
    trouvailles = _par_nom(_analyser(racine_si, "nginx/nginx.conf"))
    rsa = next(t for nom, t in trouvailles.items() if nom.startswith("Échange de clés RSA"))
    assert "AES256-GCM-SHA384" in rsa.proprietes["suites"]
    assert "RSA" in trouvailles["HIGH:!aNULL:!MD5"].proprietes["echanges_de_cles"]


def test_nginx_suites_tls13_implicites(racine_si):
    implicites = [t for t in _analyser(racine_si, "nginx/nginx.conf").trouvailles if t.implicite]
    suites = next(t for t in implicites if t.type_actif == "protocol")
    assert suites.fichier == "" and suites.proprietes["suites"][0] == "TLS_AES_256_GCM_SHA384"


def test_nginx_pistes_relatives_au_si(racine_si):
    pistes = {p.vers for p in _analyser(racine_si, "nginx/nginx.conf").pistes}
    assert {"nginx/ssl/fullchain.pem", "nginx/ssl/server.key", "nginx/ssl/dhparam.pem", "nginx/ssl/ca_clients.crt"} <= pistes


def test_nginx_minimal_valeurs_par_defaut(tmp_path):
    (tmp_path / "site.conf").write_text("server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n  ssl_session_tickets off;\n}\n")
    resultat = analyser_configuration("site.conf", racine=tmp_path)
    noms = _par_nom(resultat)
    assert "faiblesse_classique" in noms["TLSv1 TLSv1.2"].proprietes
    assert noms["auto"].implicite and "Clé des tickets de session TLS" not in noms


# --- sshd ---

def test_sshd_listes_explicites_et_regression(racine_si):
    resultat = _analyser(racine_si, "ssh/server/sshd_config")
    kex = resultat.trouvailles[0]
    assert kex.nom == "curve25519-sha256,diffie-hellman-group14-sha256" and kex.ligne is not None
    assert kex.proprietes["post_quantique_retire"] == ["sntrup761x25519-sha512@openssh.com"]
    assert [t.exposition for t in resultat.trouvailles[1:3]] == ["grover", "grover"]


def test_sshd_cles_acceptees_implicites(racine_si):
    resultat = _analyser(racine_si, "ssh/server/sshd_config")
    implicite = next(t for t in resultat.trouvailles if t.implicite)
    assert "PubkeyAcceptedAlgorithms" in implicite.description and "ssh-ed25519" in implicite.nom
    assert any(p.vers == "version d'OpenSSH" for p in resultat.pistes)


def test_sshd_hostkey_retrouvee_a_cote(racine_si):
    pistes = {p.vers for p in _analyser(racine_si, "ssh/server/sshd_config").pistes}
    assert "ssh/server/ssh_host_ed25519_key" in pistes


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [("a,b", ["a", "b"]), ("+c", ["a", "b", "c"]), ("-b", ["a"]), ("-*", []), ("^b", ["b", "a"])],
)
def test_sshd_ecritures_des_listes(valeur, attendu):
    assert sshd.appliquer(valeur, ["a", "b"]) == attendu


def test_sshd_vide_tout_par_defaut(tmp_path):
    (tmp_path / "sshd_config").write_text("PermitRootLogin no\nMACs +hmac-sha1\nMatch User x\n  Ciphers aes128-ctr\n")
    resultat = analyser_configuration("sshd_config", racine=tmp_path)
    kex = resultat.trouvailles[0]
    assert kex.implicite and "sntrup761" in kex.nom
    macs = next(t for t in resultat.trouvailles if "MACs" in t.description)
    assert "faiblesse_classique" in macs.proprietes and not macs.implicite
    chiffrement = next(t for t in resultat.trouvailles if "Ciphers" in t.description)
    assert chiffrement.implicite  # la ligne du bloc Match n'est pas la valeur globale


# --- divers ---

def test_format_non_pris_en_charge(racine_si):
    assert "non pris en charge" in analyser_configuration("certs/ca/racine.crt", racine=racine_si).erreurs[0]


@openssl_present
def test_chaine_invalide():
    assert developper_suites("CECI_N_EXISTE_PAS") == []


def test_sans_openssl(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    props, rsa = resume_suites("HIGH")
    assert rsa == [] and "openssl absent" in props["developpement"]
