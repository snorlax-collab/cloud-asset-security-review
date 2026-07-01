# Plug-and-play entrypoints. Run `make` (or `make help`) to list targets.
# Everything works with zero config; set ANTHROPIC_API_KEY in .env for real LLM review.

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin
HOST ?= example.com
PORT ?= 8000

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PY) -m venv $(VENV)

.PHONY: setup
setup: $(BIN)/python ## Create venv + install the package (and dev/llm extras)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev,llm]"
	@[ -f .env ] || cp .env.example .env
	@echo "✓ Ready. Try: make demo   |   make scan HOST=scanme.nmap.org   |   make dashboard"

.PHONY: demo
demo: setup ## Replay bundled discovery events through the full pipeline
	$(BIN)/asset-review demo --out reports

.PHONY: scan
scan: setup ## Scan a live host:  make scan HOST=example.com
	$(BIN)/asset-review scan --host $(HOST)

.PHONY: dashboard
dashboard: demo ## Build reports + open the browsable findings dashboard
	$(BIN)/asset-review serve --out reports --port $(PORT)

.PHONY: serve
serve: setup ## Serve existing reports/ as an HTML dashboard
	$(BIN)/asset-review serve --out reports --port $(PORT)

.PHONY: test
test: setup ## Run the test suite
	$(BIN)/pytest -q

.PHONY: info
info: setup ## List supported discovery events + registered checks
	$(BIN)/asset-review info

.PHONY: notify-test
notify-test: setup ## Send a sample finding to Slack (needs SLACK_WEBHOOK_URL in .env)
	$(BIN)/asset-review notify-test

.PHONY: stack
stack: ## Run the full scalable stack (LocalStack SQS + worker pool) in Docker -> localhost:8000
	docker compose up --build

.PHONY: stack-scale
stack-scale: ## Same, with a 6-worker pool to show horizontal scaling
	docker compose up --build --scale worker=6

.PHONY: stack-down
stack-down: ## Stop the stack and remove its volumes
	docker compose down -v

.PHONY: clean
clean: ## Remove venv, reports, and caches
	rm -rf $(VENV) reports .pytest_cache **/__pycache__ src/**/__pycache__ *.egg-info src/*.egg-info
