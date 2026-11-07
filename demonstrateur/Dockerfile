# Laboratoire TLS 1.3 hybride (X25519MLKEM768) : un serveur OpenSSL sans donnée réelle.
# Aucune clé n'est copiée dans l'image : le certificat est créé au démarrage, en mémoire.

# Étape 1 : compilation de l'outil de mesure, avec la même OpenSSL que le serveur.
FROM debian:trixie-slim AS constructeur
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY bench_pqc.c /src/bench_pqc.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/bench_pqc /src/bench_pqc.c -lssl -lcrypto
COPY bench_signatures.c /src/bench_signatures.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/bench_signatures /src/bench_signatures.c -lcrypto

# Étape 2 : image d'exécution (serveur et client de mesure).
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=constructeur /usr/local/bin/bench_pqc /usr/local/bin/bench_pqc
COPY --from=constructeur /usr/local/bin/bench_signatures /usr/local/bin/bench_signatures

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
