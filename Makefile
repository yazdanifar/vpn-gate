# Thin wrapper over scripts/. The scripts are the source of truth.
.DEFAULT_GOAL := help
.PHONY: lint format help build app pkg test test-each test-tsan test-asan coverage clean

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Universal binaries -> build/bin
	scripts/build.sh all
app: ## build/VPN Gate.app
	scripts/build-app.sh
pkg: ## build/VPN Gate.pkg
	scripts/build-pkg.sh
test: ## Run the test suite (no network, no root)
	scripts/test.sh
test-each: ## Run every test in its own process
	scripts/test.sh --each
test-tsan: ## Suite under ThreadSanitizer
	scripts/test.sh --tsan
test-asan: ## Suite under AddressSanitizer
	scripts/test.sh --asan
coverage: ## llvm-cov report with thresholds
	scripts/coverage.sh
clean: ## Remove build output
	rm -rf build .build

lint: ## Style check (swift-format)
	scripts/lint.sh
format: ## Apply swift-format in place
	scripts/lint.sh --fix
