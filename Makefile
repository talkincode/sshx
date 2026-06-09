# Default target
.DEFAULT_GOAL := help

# Variable definitions
BINARY_NAME=sshx
BUILD_DIR=bin
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# Version information (injected into the binary via -ldflags -X main.Version)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
RELEASE_LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

# Install locations
LOCAL_BIN_DIR=$(HOME)/.local/bin
SKILL_NAME=sshx
SKILLS_SRC_DIR=skills/$(SKILL_NAME)
SKILLS_INSTALL_DIR=$(HOME)/.agents/skills

# Go parameters
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/$(BUILD_DIR)
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

.PHONY: help build build-all test test-verbose test-coverage clean install uninstall run fmt vet lint deps version

version: ## Show the version string used for builds
	@echo "$(VERSION)"

help: ## Show help information
	@echo "Available Make targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

build: ## Build binary
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) ./cmd/sshx
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)"

build-all: ## Build binaries for all platforms
	@echo "Building all platforms ($(VERSION))..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building Linux (amd64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(RELEASE_LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 ./cmd/sshx
	@echo "Building Linux (arm64)..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(RELEASE_LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-arm64 ./cmd/sshx
	@echo "Building macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(RELEASE_LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 ./cmd/sshx
	@echo "Building macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(RELEASE_LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-arm64 ./cmd/sshx
	@echo "Building Windows (amd64)..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(RELEASE_LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sshx
	@echo "All platform builds complete!"

test: ## Run all tests
	@echo "Running tests..."
	$(GOTEST) -v ./...

test-short: ## Run unit tests (skip integration tests)
	@echo "Running unit tests..."
	$(GOTEST) -v -short ./...

test-verbose: ## Run verbose tests
	@echo "Running verbose tests..."
	$(GOTEST) -v -race ./...

test-coverage: ## Run tests and generate coverage report
	@echo "Running tests and generating coverage..."
	$(GOTEST) -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./internal/app/...
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Generating HTML coverage report..."
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

test-app: ## Test app package only
	@echo "Testing app package..."
	$(GOTEST) -v ./internal/app/...

test-sshclient: ## Test sshclient package only
	@echo "Testing sshclient package..."
	$(GOTEST) -v ./internal/sshclient/...

clean: ## Clean build files and test cache
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@echo "Clean complete!"

install: build ## Install binary to ~/.local/bin and skill to ~/.agents/skills
	@echo "Installing $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(LOCAL_BIN_DIR)
	@cp $(GOBIN)/$(BINARY_NAME) $(LOCAL_BIN_DIR)/$(BINARY_NAME) && chmod +x $(LOCAL_BIN_DIR)/$(BINARY_NAME)
	@echo "✓ Installed binary to $(LOCAL_BIN_DIR)/$(BINARY_NAME)"
	@mkdir -p $(SKILLS_INSTALL_DIR)/$(SKILL_NAME)
	@cp -R $(SKILLS_SRC_DIR)/. $(SKILLS_INSTALL_DIR)/$(SKILL_NAME)/
	@echo "✓ Installed skill to $(SKILLS_INSTALL_DIR)/$(SKILL_NAME)"
	@case ":$$PATH:" in \
		*":$(LOCAL_BIN_DIR):"*) ;; \
		*) echo "⚠  $(LOCAL_BIN_DIR) is not in your PATH; add it to use '$(BINARY_NAME)' directly" ;; \
	esac
	@echo "Installation complete! You can now use '$(BINARY_NAME)' command"

uninstall: ## Uninstall binary and skill
	@echo "Uninstalling..."
	@if [ -f $(LOCAL_BIN_DIR)/$(BINARY_NAME) ]; then \
		rm -f $(LOCAL_BIN_DIR)/$(BINARY_NAME); \
		echo "✓ Removed $(LOCAL_BIN_DIR)/$(BINARY_NAME)"; \
	fi
	@if [ -d $(SKILLS_INSTALL_DIR)/$(SKILL_NAME) ]; then \
		rm -rf $(SKILLS_INSTALL_DIR)/$(SKILL_NAME); \
		echo "✓ Removed skill $(SKILLS_INSTALL_DIR)/$(SKILL_NAME)"; \
	fi
	@echo "Uninstall complete!"

run: build ## Build and run (show help)
	@echo "Running $(BINARY_NAME)..."
	@$(GOBIN)/$(BINARY_NAME) --help

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "Format complete!"

vet: ## Run go vet checks
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "Check complete!"

lint: ## Run golangci-lint (requires installation)
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "Please install golangci-lint first: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...
	@echo "Lint check complete!"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	@echo "Dependencies downloaded!"

tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	$(GOMOD) tidy
	@echo "Dependencies tidied!"

vendor: ## Create vendor directory
	@echo "Creating vendor..."
	$(GOMOD) vendor
	@echo "Vendor created!"

check: fmt vet test ## Run all checks (format, vet, test)
	@echo "All checks passed!"

ci: deps check test-coverage ## CI/CD workflow (deps, check, coverage)
	@echo "CI workflow complete!"

tag:
	@echo "🏷️  Starting tag creation process..."
	@./scripts/tag.sh

renote:
	@echo "🏷️  开始更新release note..."
	@./scripts/release-note.sh

dev: ## Development mode (install deps, format, test, build)
	@echo "Development mode..."
	@$(MAKE) deps
	@$(MAKE) fmt
	@$(MAKE) test
	@$(MAKE) build
	@echo "Development environment ready!"

release: clean test-coverage build-all ## Prepare release (clean, test, build all platforms)
	@echo "Preparing release..."
	@echo "All binaries located at: $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/
	@echo "Release ready!"

info: ## Show project information
	@echo "Project information:"
	@echo "  Name: $(BINARY_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Go version: $(shell go version)"
	@echo "  Build directory: $(BUILD_DIR)"
	@echo "  Current path: $(GOBASE)"
	@echo ""
	@echo "Dependency statistics:"
	@go list -m all | wc -l | awk '{print "  Total dependencies: " $$1}'
	@echo ""
	@echo "Code statistics:"
	@find . -name "*.go" -not -path "./vendor/*" | wc -l | awk '{print "  Go files: " $$1}'
	@find . -name "*_test.go" -not -path "./vendor/*" | wc -l | awk '{print "  Test files: " $$1}'

setup-hooks: ## Install Git hooks for pre-commit checks
	@echo "Installing Git hooks..."
	@./scripts/setup-hooks.sh

watch: ## Watch file changes and auto-test (requires entr)
	@echo "Watching file changes..."
	@which entr > /dev/null || (echo "Please install entr first: brew install entr (macOS) or apt-get install entr (Linux)" && exit 1)
	@find . -name "*.go" -not -path "./vendor/*" | entr -c make test

.PHONY: all
all: clean deps fmt vet test build ## Complete build workflow
	@echo "Complete build done!"
