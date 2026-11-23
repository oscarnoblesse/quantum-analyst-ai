.PHONY: help install test verite-terrain si verifier-si verite-terrain-v2 cbom-attendu-v2 si-v2 verifier-si-v2 reproduce reproduce-complet reproduce-small reproduce-small-modele demonstrateur demonstrateur-agent reference agents agents-regles evaluer installer-modele metriques rejeu sommes verifier-sommes signer verifier-signature

GT_CSV  := data/ground_truth/verite_terrain_v1.csv
GT_JSON := data/ground_truth/si_v1.json
GT_CSV_V2   := data/ground_truth/verite_terrain_v2.csv
GT_JSON_V2  := data/ground_truth/si_v2.json
LEURRES_V2  := data/ground_truth/leurres_v2.csv
CBOM_ATTENDU_V2 := data/ground_truth/cbom_attendu_v2.json

# Signature de SHA256SUMS (minisign). La clé privée n'est JAMAIS dans le dépôt.
CLE_PUBLIQUE := cle_publique_minisign.pub
CLE_PRIVEE   ?= $(HOME)/.minisign/quantum-ready.key

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

install: ## Installe l'environnement figé (uv.lock)
	uv sync --locked

installer-modele: ## Installe Ollama et le modèle figé dans config/experiment.yaml
	uv run python -m quantum_ready.installation_modele

test: ## Lance les tests avec la couverture
	uv run pytest --cov=quantum_ready --cov-report=term-missing

verite-terrain: ## Valide le CSV de la vérité terrain et produit le JSON
	uv run python -m quantum_ready.verite_terrain $(GT_CSV) $(GT_JSON)

si: ## Génère le SI fictif dans si/generated/v1 (jamais commité)
	uv run python -m quantum_ready.si_fictif --variante v1 --ecraser

verifier-si: ## Compare le SI généré à la vérité terrain, actif par actif
	uv run python -m quantum_ready.si_fictif.controles si/generated/v1 $(GT_CSV)

verite-terrain-v2: ## Valide la vérité terrain du SI v2 et produit le JSON
	uv run python -m quantum_ready.verite_terrain $(GT_CSV_V2) $(GT_JSON_V2)

cbom-attendu-v2: ## Construit le CBOM attendu du SI v2 depuis sa vérité terrain et le valide (CycloneDX 1.6)
	uv run python scripts/cbom_attendu.py $(GT_CSV_V2) $(CBOM_ATTENDU_V2)

si-v2: ## Génère le SI d'évaluation v2 dans si/generated/v2 (jamais commité)
	uv run python -m quantum_ready.si_fictif --variante v2 --ecraser

verifier-si-v2: ## Compare le SI v2 généré à sa vérité terrain, actif par actif (100 contrôles)
	uv run python -m quantum_ready.si_fictif.controles_v2 si/generated/v2 $(GT_CSV_V2) $(LEURRES_V2)

reproduce: ## Reproduction complète : environnement, vérité terrain, SI, vérification, tests (scripts/reproduire.py)
	uv run python scripts/reproduire.py

demonstrateur: ## Construit et vérifie le laboratoire TLS hybride (Docker requis)
	uv run python scripts/demonstrateur.py

demonstrateur-agent: ## Agent Démonstrateur avec le modèle local (Docker et Ollama requis)
	uv run python -m quantum_ready.agents.demonstrateur --modele ollama

reproduce-complet: ## Reproduction complète : environnement, modèle, laboratoire, mesures, agents (traces/complet), évaluation, métriques (Ollama et Docker requis, plus d'une heure)
	$(MAKE) reproduce
	$(MAKE) installer-modele
	$(MAKE) demonstrateur
	uv run python scripts/bench_pqc.py
	uv run python scripts/bench_signatures.py
	uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele ollama --session traces/complet --validation accepter
	$(MAKE) evaluer SESSIONS="traces/complet"
	$(MAKE) metriques

reproduce-small-modele: ## Chaîne complète avec un très petit modèle (qwen3:0.6b, Ollama requis) : journal et rejeu
	uv run python scripts/reproduce_petit_modele.py

reproduce-small: ## Reproduction rapide : environnement et tests, sans régénérer le SI
	uv run python scripts/reproduire.py --petite

reference: ## Référence d'ablation : outils seuls, sans agent (traces/reference_outils_seuls)
	uv run python -m quantum_ready.evaluation.reference --racine si/generated/v1 --session traces/reference_outils_seuls

agents: ## Système multi-agents avec le modèle local (Ollama doit tourner)
	uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele ollama

agents-regles: ## Agents à règles fixes, sans modèle (ablation) (traces/regles)
	uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele regles --validation accepter --session traces/regles

metriques: ## Génère results/metrics.json, les figures et ENVIRONMENT.json à partir de results/raw/ (aucune valeur saisie à la main)
	uv run python -m quantum_ready.evaluation.metriques
	uv run python -m quantum_ready.evaluation.figures
	uv run python -m quantum_ready.evaluation.environnement

rejeu: ## Affiche une session et rejoue ses appels purs : make rejeu SESSION=traces/<dossier>
	uv run python -m quantum_ready.rejeu $(SESSION) --racine si/generated/v1

evaluer: ## Évalue et compare des sessions : make evaluer SESSIONS="traces/a traces/b"
	uv run python -m quantum_ready.evaluation $(SESSIONS)


sommes: ## Écrit SHA256SUMS : empreintes des artefacts publiés (results/, traces/, data/ground_truth/)
	uv run python -m quantum_ready.integrite generer

verifier-sommes: ## Vérifie chaque empreinte de SHA256SUMS
	uv run python -m quantum_ready.integrite verifier

signer: ## Signe SHA256SUMS avec la clé privée minisign de l'auteur (release seulement) : make signer CLE_PRIVEE=...
	minisign -S -s $(CLE_PRIVEE) -m SHA256SUMS -t "Quantum-Ready v1.0.0 - SHA256SUMS des artefacts publies"

verifier-signature: ## Vérifie la signature de SHA256SUMS avec la clé publique du dépôt, puis les empreintes
	minisign -V -p $(CLE_PUBLIQUE) -m SHA256SUMS
	$(MAKE) verifier-sommes
