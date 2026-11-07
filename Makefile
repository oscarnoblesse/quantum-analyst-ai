.PHONY: help install test verite-terrain si verifier-si reproduce reproduce-small demonstrateur reference agents agents-regles evaluer installer-modele

GT_CSV  := data/ground_truth/verite_terrain_v1.csv
GT_JSON := data/ground_truth/si_v1.json

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

reproduce: ## Reproduction complète : environnement, vérité terrain, SI, vérification, tests (scripts/reproduire.py)
	uv run python scripts/reproduire.py

demonstrateur: ## Construit et vérifie le laboratoire TLS hybride (Docker requis)
	uv run python scripts/demonstrateur.py

reproduce-small: ## Reproduction rapide : environnement et tests, sans régénérer le SI
	uv run python scripts/reproduire.py --petite

reference: ## Référence d'ablation : outils seuls, sans agent (traces/reference_outils_seuls)
	uv run python -m quantum_ready.evaluation.reference --racine si/generated/v1 --session traces/reference_outils_seuls

agents: ## Système multi-agents avec le modèle local (Ollama doit tourner)
	uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele ollama

agents-regles: ## Agents à règles fixes, sans modèle (ablation) (traces/regles)
	uv run python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele regles --validation accepter --session traces/regles

evaluer: ## Évalue et compare des sessions : make evaluer SESSIONS="traces/a traces/b"
	uv run python -m quantum_ready.evaluation $(SESSIONS)

