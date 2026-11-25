# Thin wrapper around ./run.sh and scripts/. Everything here is optional —
# the scripts work on their own.
.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help up render status verify-mcp codex-mcp flags chaos forward down clean check test

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-10s\033[0m %s\n", $$1, $$2}'

up: ## Create the cluster and deploy everything (safe to re-run)
	./run.sh

render: ## Generate .render/*.yaml from .env without deploying
	./run.sh --render-only

status: ## Pods, export errors, active flags
	scripts/status.sh

verify-mcp: ## Check the agent environment (MCP endpoints, API credentials)
	scripts/verify-mcp.sh

codex-mcp: ## Render the Codex MCP config from .env
	scripts/render-codex-mcp.sh

flags: ## Show current error-injection flags
	scripts/chaos.sh show

chaos: ## Switch to the high-failure profile
	scripts/chaos.sh apply chaos

forward: ## Re-open http://localhost:8080
	scripts/forward.sh

down: ## Uninstall releases, keep the cluster
	scripts/teardown.sh

clean: ## Uninstall releases and delete the cluster
	scripts/teardown.sh --cluster

test: ## Run the Python test suite
	python3 -m unittest discover -s tests

check: ## Lint the shell scripts (needs shellcheck)
	@for f in run.sh scripts/*.sh; do bash -n "$$f" || exit 1; done
	@command -v shellcheck >/dev/null && shellcheck -x run.sh scripts/*.sh || echo "shellcheck not installed; syntax check only"
