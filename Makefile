# Plug-and-play entrypoints. Run `make` (or `make help`) to list targets.
# Everything works with zero config; set ANTHROPIC_API_KEY in .env for real LLM review.

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin
HOST ?= example.com
PORT ?= 8000
TYPE ?= dns_record
AWS_REGION ?= ap-south-1
AWS_PROFILE ?=
TF_DIR := infra/terraform

# Infer AWS asset type from common hostname patterns for POC scans.
ifeq ($(findstring execute-api,$(HOST)),execute-api)
  TYPE := api_gateway
endif
ifeq ($(findstring lambda-url,$(HOST)),lambda-url)
  TYPE := lambda_url
endif
ifeq ($(findstring .elb.amazonaws.com,$(HOST)),.elb.amazonaws.com)
  TYPE := load_balancer
endif
ifeq ($(findstring .s3.amazonaws.com,$(HOST)),.s3.amazonaws.com)
  TYPE := s3_bucket
endif

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

.PHONY: poc-scan
poc-scan: setup ## POC: wipe demo reports, scan HOST (+ Slack), rebuild dashboard
	$(BIN)/asset-review scan --host $(HOST) --type $(TYPE) --fresh

.PHONY: poc
poc: poc-scan ## POC: clean scan then serve dashboard at :$(PORT)
	$(BIN)/asset-review serve --out reports --port $(PORT)

.PHONY: scan
scan: setup ## Scan a live host (+ Slack alerts if SLACK_WEBHOOK_URL is in .env)
	$(BIN)/asset-review scan --host $(HOST) --type $(TYPE)

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

.PHONY: sample-pdf
sample-pdf: setup ## Regenerate docs/sample-report.pdf from docs/sample-reports/
	$(BIN)/python scripts/build_sample_pdfs.py

AWS_CLI := aws $(if $(AWS_PROFILE),--profile $(AWS_PROFILE),)
ACCOUNT_ID := $(shell $(AWS_CLI) sts get-caller-identity --query Account --output text 2>/dev/null)
ECR_REPO := $(ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com/asset-review

.PHONY: deploy-init
deploy-init: ## Terraform init (infra/terraform)
	cd $(TF_DIR) && terraform init

.PHONY: deploy-build-lambda
deploy-build-lambda: ## Build dist/lambda.zip for Terraform (run before deploy-apply-base)
	bash scripts/build_lambda_zip.sh

.PHONY: deploy-apply-base
deploy-apply-base: deploy-init deploy-build-lambda ## Deploy control plane (no ECS workers yet)
	cd $(TF_DIR) && terraform apply \
	  -target=aws_ecr_repository.scanner \
	  -target=aws_sqs_queue.asset_scan \
	  -target=aws_sqs_queue.asset_scan_dlq \
	  -target=aws_sqs_queue.discovery_dlq \
	  -target=aws_s3_bucket.reports \
	  -target=aws_s3_bucket_public_access_block.reports \
	  -target=aws_s3_bucket_server_side_encryption_configuration.reports \
	  -target=aws_s3_bucket_versioning.reports \
	  -target=aws_s3_bucket_lifecycle_configuration.reports \
	  -target=aws_s3_object.dashboard_placeholder \
	  -target=aws_secretsmanager_secret.scanner \
	  -target=aws_iam_role.discovery \
	  -target=aws_iam_role_policy.discovery \
	  -target=aws_iam_role.dashboard_sync \
	  -target=aws_iam_role_policy.dashboard_sync \
	  -target=aws_lambda_function.discovery \
	  -target=aws_lambda_function.dashboard_sync \
	  -target=aws_cloudwatch_event_rule.tier1 \
	  -target=aws_cloudwatch_event_target.tier1_discovery \
	  -target=aws_cloudwatch_event_rule.dashboard_sync \
	  -target=aws_cloudwatch_event_target.dashboard_sync

.PHONY: set-scanner-secret
set-scanner-secret: ## Push .env secrets to AWS Secrets Manager (not Terraform)
	bash scripts/set_scanner_secret.sh

.PHONY: deploy-push-image
deploy-push-image: ## Build scanner image and push to ECR (run deploy-apply-base first)
	@test -n "$(ACCOUNT_ID)" || (echo "AWS CLI not configured"; exit 1)
	$(AWS_CLI) ecr get-login-password --region $(AWS_REGION) | \
	  docker login --username AWS --password-stdin $(ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
	docker build -t asset-scanner .
	docker tag asset-scanner:latest $(ECR_REPO):latest
	docker push $(ECR_REPO):latest
	@echo "✓ Pushed $(ECR_REPO):latest"
	@echo "  Add to $(TF_DIR)/terraform.tfvars: scanner_image = \"$(ECR_REPO):latest\""

.PHONY: deploy-apply
deploy-apply: deploy-init ## Full production deploy (requires scanner_image in terraform.tfvars)
	cd $(TF_DIR) && terraform apply

.PHONY: deploy-destroy
deploy-destroy: deploy-init ## Tear down production stack
	cd $(TF_DIR) && terraform destroy
