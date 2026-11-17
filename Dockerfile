# Image de reproduction de Quantum-Ready.
#
# Elle exécute la reproduction déterministe du projet (« make reproduce ») sur une machine vierge :
# environnement figé (uv.lock), vérité terrain, génération du SI fictif, vérification actif par
# actif, tests avec seuil de couverture de 70 %. Aucun modèle de langage n'est nécessaire.
#
#   docker build -t quantum-ready .
#   docker run --rm quantum-ready                      # make reproduce (~2 min)
#   docker run --rm quantum-ready make reproduce-small # environnement + tests seulement
#
# Hors périmètre de l'image (voir README) :
# - les agents avec modèle local : Ollama tourne sur l'hôte ; lancer `make agents` sur l'hôte ;
# - le laboratoire TLS hybride (`make demonstrateur`) : il pilote lui-même Docker, on ne
#   l'exécute pas dans un conteneur (pas de Docker dans Docker).

FROM python:3.12-slim-bookworm

# Outils externes utilisés par le projet :
# - openssl : développement des macros de suites TLS (actif caché QR-015), version consignée ;
# - openssh-client (ssh-keygen) : génération et contrôle des clés SSH du SI fictif ;
# - make : cibles du Makefile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl openssh-client make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv en version figée (installe l'environnement exact décrit par uv.lock).
RUN pip install --no-cache-dir uv==0.11.32

# Utilisateur non privilégié : sous root, les tests de droits POSIX (fichiers de clés
# lisibles par tous, etc.) ne seraient pas représentatifs.
RUN useradd --create-home --uid 1000 auditeur
WORKDIR /home/auditeur/quantum-ready
COPY --chown=auditeur:auditeur . .
USER auditeur

ENV PYTHONUTF8=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Dépendances installées à la construction : l'exécution ne télécharge plus rien.
RUN uv sync --locked

CMD ["make", "reproduce"]
