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
    assert implicite.proprietes["version_openssh"] == "9.6 (lue dans ssh/Dockerfile)"
    assert not any(p.vers == "version d'OpenSSH" for p in resultat.pistes)


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


# --- PostgreSQL ---

def test_postgresql_conf(racine_si):
    resultat = _analyser(racine_si, "db/postgresql.conf")
    noms = _par_nom(resultat)
    assert noms["TLSv1.2"].ligne is not None and noms["prime256v1"].exposition == "shor"
    implicite = noms["HIGH:MEDIUM:+3DES:!aNULL"]
    assert implicite.implicite and "faiblesse_classique" in implicite.proprietes
    pistes = {p.vers: p.raison for p in resultat.pistes}
    assert "password_encryption = md5" in pistes["db/pg_hba.conf"]
    assert "db/tls/server.key" in pistes


def test_postgresql_sans_ssl(tmp_path):
    (tmp_path / "postgresql.conf").write_text("listen_addresses = '*'\nssl = off\n")
    resultat = analyser_configuration("postgresql.conf", racine=tmp_path)
    assert resultat.trouvailles == [] and "pas chiffrées" in resultat.pistes[0].raison


def test_pg_hba(racine_si):
    resultat = _analyser(racine_si, "db/pg_hba.conf")
    assert [t.nom for t in resultat.trouvailles] == ["md5"]
    assert any("password_encryption" in p.raison for p in resultat.pistes)


def test_pg_hba_methodes_et_connexions_sans_tls(tmp_path):
    (tmp_path / "pg_hba.conf").write_text(
        "local all all scram-sha-256\nhost all all 0.0.0.0/0 password  # à corriger\nhostssl all all ::/0 cert\n"
    )
    resultat = analyser_configuration("pg_hba.conf", racine=tmp_path)
    assert [t.nom for t in resultat.trouvailles] == ["scram-sha-256", "password", "cert"]
    assert "sans TLS" in resultat.pistes[0].raison


# --- .env ---

def test_env_secrets_decrits_jamais_recopies(racine_si):
    from quantum_ready.outils.commun import lire_env

    resultat = _analyser(racine_si, "api/.env")
    texte = resultat.model_dump_json()
    for _, nom, valeur in lire_env((racine_si / "api/.env").read_text()):
        if nom != "JWT_ALGORITHM":
            assert valeur not in texte, f"{nom} recopié dans le résultat"
    noms = [t.nom for t in resultat.trouvailles]
    assert "Secret faible (JWT_SECRET)" in noms
    assert "Clé Fernet 256 bits (FIELD_ENCRYPTION_KEY)" in noms
    assert "Secret aléatoire de 256 bits (WEBHOOK_SECRET)" in noms
    assert "Secret en clair (KEYSTORE_PASS)" in noms


def test_env_url_de_connexion(racine_si):
    noms = _par_nom(_analyser(racine_si, "api/.env"))
    assert noms["sslmode=require"].proprietes["faiblesse_classique"].startswith("certificat du serveur non vérifié")
    assert noms["Mot de passe de connexion (secret en clair)"].proprietes["utilisateur"] == "lab_app"


def test_env_nom_d_algorithme_devient_une_piste(racine_si):
    pistes = {p.vers: p.raison for p in _analyser(racine_si, "api/.env").pistes}
    assert "HS256" in pistes["JWT_ALGORITHM"]
    assert pistes["api/config/ca_bundle.pem"].startswith("magasin d'AC")


def test_env_verify_full_sans_faiblesse(tmp_path):
    (tmp_path / ".env").write_text("DB=postgresql://u@h/db?sslmode=verify-full\nAPI_TOKEN=Zq8!rT2#pL9@xW4$\n")
    noms = _par_nom(analyser_configuration(".env", racine=tmp_path))
    assert "faiblesse_classique" not in noms["sslmode=verify-full"].proprietes
    assert "Secret en clair (API_TOKEN)" in noms


# --- Dockerfile ---

def test_dockerfile_version_d_openssh(racine_si):
    resultat = _analyser(racine_si, "ssh/Dockerfile")
    openssh = resultat.trouvailles[0]
    assert (openssh.type_actif, openssh.nom) == ("library", "OpenSSH 9.6p1")
    assert openssh.proprietes["kex_post_quantique_par_defaut"] == "sntrup761x25519-sha512@openssh.com"
    assert openssh.proprietes["image_de_base"] == "ubuntu:24.04"
    assert "ssh/server/sshd_config" in {p.vers for p in resultat.pistes}


def test_dockerfile_paquet_non_fige_et_openssh_10(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:13\nRUN apt-get update && apt-get install -y \\\n    openssl openssh-server=1:10.0p1-5\nCMD [\"sh\"]\n"
    )
    resultat = analyser_configuration("Dockerfile", racine=tmp_path)
    noms = _par_nom(resultat)
    assert noms["OpenSSL (version de l'image debian:13)"].proprietes["version"].startswith("non figée")
    assert noms["OpenSSH 10.0p1"].proprietes["kex_post_quantique_par_defaut"] == "mlkem768x25519-sha256"


# --- scripts shell ---

def test_script_de_sauvegarde(racine_si):
    resultat = _analyser(racine_si, "scripts/backup.sh")
    gpg = resultat.trouvailles[0]
    assert gpg.nom == "Chiffrement OpenPGP à clé publique" and gpg.exposition == "shor"
    assert gpg.proprietes["destinataire"] == "backup@lab.local"
    assert gpg.proprietes["duree_conservation_jours"] == 3650
    pistes = {p.vers: p.raison for p in resultat.pistes}
    assert pistes["scripts/keys/backup_pub.asc"].startswith("clé importée")
    assert "Mosca" in pistes["scripts/backup.sh"]


def test_script_autres_commandes(tmp_path):
    (tmp_path / "outils.sh").write_text(
        "#!/bin/bash\n"
        "openssl req -new -newkey rsa:2048 -nodes -keyout k.pem\n"
        "ssh-keygen -t rsa -b 1024 -f id\n"
        "md5sum fichier > somme.txt; gpg -c --cipher-algo AES256 secret.txt\n"
        "gpg --detach-sign doc.pdf\n"
    )
    noms = [t.nom for t in analyser_configuration("outils.sh", racine=tmp_path).trouvailles]
    assert noms == [
        "openssl req (rsa:2048)", "Génération de clé SSH RSA-1024", "MD5",
        "Chiffrement OpenPGP symétrique (AES256)", "Signature OpenPGP",
    ]


# --- nginx : grammaire, héritage, include ---

def _site(tmp_path, fichiers):
    for nom, contenu in fichiers.items():
        (tmp_path / nom).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / nom).write_text(contenu)


def test_nginx_deux_serveurs_ne_sont_pas_melanges(tmp_path):
    _site(tmp_path, {"nginx.conf": (
        "http {\n  ssl_protocols TLSv1.2 TLSv1.3;  # pour tous\n"
        "  server { listen 443 ssl; server_name a.test; }\n"
        "  server { listen 8443 ssl; server_name b.test; ssl_protocols TLSv1 TLSv1.2; }\n"
        "  server { listen 80; server_name clair.test; }\n}\n")})
    noms = _par_nom(analyser_configuration("nginx.conf", racine=tmp_path))
    assert noms["TLSv1.2 TLSv1.3"].proprietes["serveurs"] == ["a.test"]
    assert noms["TLSv1 TLSv1.2"].proprietes["serveurs"] == ["b.test"]
    assert "faiblesse_classique" in noms["TLSv1 TLSv1.2"].proprietes
    assert all("clair.test" not in t.proprietes.get("serveurs", []) for t in noms.values())


def test_nginx_include_relatif_motif_et_absolu(tmp_path):
    _site(tmp_path, {
        "etc/nginx/nginx.conf": "http { include conf.d/*.conf; }\n",
        "etc/nginx/conf.d/site.conf": "server { listen 443 ssl; include /etc/nginx/snippets/tls.conf; }\n",
        "etc/nginx/snippets/tls.conf": "ssl_protocols TLSv1.3;\nssl_ecdh_curve 'X25519MLKEM768:X25519';\n",
    })
    resultat = analyser_configuration("etc/nginx/nginx.conf", racine=tmp_path)
    groupes = _par_nom(resultat)["X25519MLKEM768:X25519"]
    assert groupes.fichier == "etc/nginx/snippets/tls.conf" and groupes.ligne == 2
    assert groupes.proprietes["hybride_post_quantique"] is True


def test_nginx_include_en_boucle_et_introuvable(tmp_path):
    _site(tmp_path, {
        "a.conf": "include b.conf;\ninclude absent.conf;\nserver { listen 443 ssl; }\n",
        "b.conf": "include a.conf;\nssl_session_tickets off;\n",
    })
    resultat = analyser_configuration("a.conf", racine=tmp_path)
    assert "Clé des tickets de session TLS" not in _par_nom(resultat)
    assert any("introuvable" in p.raison and p.vers == "absent.conf" for p in resultat.pistes)


def test_nginx_valeurs_par_defaut_et_guillemets(tmp_path):
    _site(tmp_path, {"site.conf": "server {\n  listen 443 ssl;\n  ssl_ciphers \"ECDHE-RSA-AES128-SHA:DES-CBC3-SHA\";  # ancien\n}\n"})
    noms = _par_nom(analyser_configuration("site.conf", racine=tmp_path))
    versions = noms["TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"]
    assert versions.implicite and "1.23.4" in versions.proprietes["source"]
    assert "ECDHE-RSA-AES128-SHA:DES-CBC3-SHA" in noms


def test_nginx_fragment_seul(tmp_path):
    _site(tmp_path, {"ssl-params.conf": "ssl_protocols TLSv1.3;\n"})
    resultat = analyser_configuration("ssl-params.conf", racine=tmp_path)
    assert _par_nom(resultat)["TLSv1.3"].proprietes["serveurs"] == ["fragment ssl-params.conf"]


# --- sshd : valeurs par défaut selon la version d'OpenSSH ---

def test_sshd_version_inconnue_est_une_hypothese(tmp_path):
    (tmp_path / "sshd_config").write_text("Port 22\nPermitRootLogin no\n")
    resultat = analyser_configuration("sshd_config", racine=tmp_path)
    kex = resultat.trouvailles[0]
    assert "HYPOTHÈSE" in kex.proprietes["source"] and kex.proprietes["version_openssh"].startswith("inconnue")
    assert any(p.vers == "version d'OpenSSH" for p in resultat.pistes)


@pytest.mark.parametrize(("version", "premier"), [("10.0p2", "mlkem768x25519-sha256"), ("9.6", "sntrup761x25519-sha512@openssh.com"), ("8.9p1", "curve25519-sha256")])
def test_sshd_version_donnee_par_l_agent(tmp_path, version, premier):
    (tmp_path / "sshd_config").write_text("Port 22\nPermitRootLogin no\n")
    kex = analyser_configuration("sshd_config", racine=tmp_path, version_openssh=version).trouvailles[0]
    assert kex.nom.split(",")[0] == premier and "indiquée par l'agent" in kex.proprietes["version_openssh"]


def test_sshd_regression_selon_la_version(tmp_path):
    (tmp_path / "sshd_config").write_text("KexAlgorithms curve25519-sha256\nHostKey /etc/ssh/k\n")
    (tmp_path / "Dockerfile").write_text("FROM debian:13\nRUN apt-get install -y openssh-server=1:10.0p1-5\n")
    kex = analyser_configuration("sshd_config", racine=tmp_path).trouvailles[0]
    assert "mlkem768x25519-sha256" in kex.proprietes["post_quantique_retire"]
