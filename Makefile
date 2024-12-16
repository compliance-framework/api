# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.26.1

BLUE         := $(shell printf "\033[34m")
YELLOW       := $(shell printf "\033[33m")
RED          := $(shell printf "\033[31m")
GREEN        := $(shell printf "\033[32m")
CNone        := $(shell printf "\033[0m")

INFO    = echo ${TIME} ${BLUE}[ .. ]${CNone}
WARN    = echo ${TIME} ${YELLOW}[WARN]${CNone}
ERR     = echo ${TIME} ${RED}[FAIL]${CNone}
OK      = echo ${TIME} ${GREEN}[ OK ]${CNone}
FAIL    = (echo ${TIME} ${RED}[FAIL]${CNone} && false)


# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: help
# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI catalog characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: all
all: build

##@ General

##@ Development
.PHONY: test
test: ## Run tests
	@if ! go test ./... -coverprofile cover.out; then \
		$(WARN) "Tests failed"; \
		exit 1; \
	fi ; \
	$(OK) Tests passed
##@ Development
.PHONY: test-integration
test-integration: ## Run tests
	@if ! go test ./... -coverprofile cover.out -v --tags integration; then \
		$(WARN) "Tests failed"; \
		exit 1; \
	fi ; \
	$(OK) Tests passed
.PHONY: lint.check
lint.check: ## Check install of golanci-lint
	@if ! golangci-lint --version 2>&1 >> /dev/null; then \
		echo -e "\033[0;33mgolangci-lint is not installed: run \`\033[0;32mmake lint.install\033[0m\033[0;33m\` or install it from https://golangci-lint.run\033[0m"; \
		exit 1; \
	fi

.PHONY: lint.install
lint.install: ## Install golangci-lint to the go bin dir
	@if ! golangci-lint --version  2>&1 >> /dev/null; then \
		$(INFO) "Installing golangci-lint"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.52.2; \
	fi

.PHONY: lint
lint: lint.check ## Run golangci-lint
	@if ! golangci-lint run; then \
		$(WARN) "golangci-lint found issues with your code. Please check and fix them before committing."; \
		exit 1; \
	fi ; \
	$(OK) No linting issues found

.PHONY: reviewable
reviewable: swag ## Ensure a PR is ready for review.
	@go mod tidy

.PHONY: check-diff
check-diff: reviewable ## Ensure branch is clean.
	@$(INFO) checking that branch is clean
	@test -z "$$(git status --porcelain)" || (echo "$$(git status --porcelain)" && $(FAIL))
	@$(OK) branch is clean


.PHONY: debug
debug: ## Run docker-compose with debug
	@docker compose -f ./tests/docker-compose.yml up -d --build

.PHONY: debug.stop
debug-stop: ## Run docker-compose with debug
	@docker compose -f ./tests/docker-compose.yml down

.PHONY: dev
dev: ## run docker compose up
	@docker compose -f docker-compose.dev.yml up -d

.PHONY: dev.stop
dev-stop: ## run docker compose down
	@docker compose -f docker-compose.dev.yml down

swag: ## swag setup and lint
	@swag init
	@swag fmt

build-local:   ## build an image that can be used by the compliance-framework/local_dev repository
	docker build -t ghcr.io/compliance-framework/configuration-service:latest_local .
