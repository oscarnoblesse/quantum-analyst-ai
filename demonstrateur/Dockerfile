# Laboratoire TLS 1.3 hybride (X25519MLKEM768) : un serveur OpenSSL sans donnée réelle.
# Aucune clé n'est copiée dans l'image : le certificat est créé au démarrage, en mémoire.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
