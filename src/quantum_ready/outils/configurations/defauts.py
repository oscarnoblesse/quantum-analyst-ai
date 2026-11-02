"""Valeurs par défaut des logiciels du SI : la source des actifs IMPLICITES.

Un actif implicite n'est écrit dans aucun fichier : c'est la valeur que le
logiciel applique quand la directive est absente. Pour l'inventorier, il faut
connaître ces valeurs. Chaque entrée cite sa source pour pouvoir être auditée,
et dépend de la version du logiciel (à confirmer par l'agent : Dockerfile, image...).
"""

from __future__ import annotations

# OpenSSL 3.x : suites TLS 1.3 activées par défaut (option -ciphersuites de s_server/s_client).
SUITES_TLS13_OPENSSL = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]
SOURCE_TLS13 = "valeur par défaut d'OpenSSL 3 (SSL_CTX_set_ciphersuites)"

# OpenSSL 3.0 à 3.4 : groupes d'échange de clés par défaut. OpenSSL 3.5 ajoute X25519MLKEM768 en tête.
GROUPES_OPENSSL_3 = ["X25519", "secp256r1", "X448", "secp521r1", "secp384r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"]

# PostgreSQL 12 à 17, documentation « Server Configuration : Connections and Authentication ».
POSTGRESQL = {
    "ssl_ciphers": "HIGH:MEDIUM:+3DES:!aNULL",
    "ssl_min_protocol_version": "TLSv1.2",
    "ssl_ecdh_curve": "prime256v1",
    "password_encryption": "scram-sha-256",
}
SOURCE_POSTGRESQL = "valeur par défaut de PostgreSQL 12 à 17"

# OpenSSH 9.6, page de manuel sshd_config(5).
OPENSSH_9_6 = {
    "KexAlgorithms": [
        "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
    ],
    "Ciphers": [
        "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    ],
    "MACs": [
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
        "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
    ],
    "HostKeyAlgorithms": [
        "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256",
    ],
}
OPENSSH_9_6["PubkeyAcceptedAlgorithms"] = list(OPENSSH_9_6["HostKeyAlgorithms"])
SOURCE_OPENSSH = "valeur par défaut d'OpenSSH 9.6 (sshd_config(5))"

# Échange de clés post-quantique hybride proposé par défaut, selon la version d'OpenSSH.
KEX_POST_QUANTIQUE_OPENSSH = [
    ((10, 0), "mlkem768x25519-sha256"),
    ((9, 0), "sntrup761x25519-sha512@openssh.com"),
]

# nginx, module ngx_http_ssl_module : valeurs par défaut documentées.
NGINX_SSL_PROTOCOLS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
SOURCE_NGINX_SSL_PROTOCOLS = "valeur par défaut de nginx depuis 1.23.4 (TLSv1 TLSv1.1 TLSv1.2 avant) ; OpenSSL 3 peut refuser TLS 1.0/1.1 à son niveau de sécurité par défaut"
NGINX_SSL_CIPHERS = "HIGH:!aNULL:!MD5"
SOURCE_NGINX = "valeur par défaut de nginx (ngx_http_ssl_module)"
SOURCE_GROUPES_OPENSSL = "valeur par défaut d'OpenSSL 3.0 à 3.4 ; OpenSSL 3.5 et plus propose X25519MLKEM768 en tête"
