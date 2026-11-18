# Serveur SSH du laboratoire : OpenSSH 10.0 (Debian trixie), échange hybride mlkem768x25519-sha256.
# Aucune clé n'est copiée dans l'image : la clé d'hôte est créée au démarrage, dans /run.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
