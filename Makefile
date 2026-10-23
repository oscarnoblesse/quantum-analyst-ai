.PHONY: help install test verite-terrain reproduce reproduce-small

GT_CSV  := data/ground_truth/verite_terrain_v1.csv
GT_JSON := data/ground_truth/si_v1.json

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

install: ## Installe l'environnement figé (uv.lock)
	uv sync --locked

test: ## Lance les tests avec la couverture
	uv run pytest --cov=quantum_ready --cov-report=term-missing

verite-terrain: ## Valide le CSV de la vérité terrain et produit le JSON
	uv run python -m quantum_ready.verite_terrain $(GT_CSV) $(GT_JSON)

reproduce: install verite-terrain test ## Reproduction complète (sera complétée au fil du projet)

reproduce-small: install verite-terrain test ## Reproduction réduite pour la CI (sera complétée au fil du projet)
