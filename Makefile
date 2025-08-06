.PHONY: build clean test lint fmt vet run help install deps dev
.DEFAULT_GOAL := help

# Build variables
BINARY_NAME=pcap-analyzer
BINARY_PATH=bin/$(BINARY_NAME)
CMD_PATH=./cmd/pcap-analyzer
GO_FILES=$(shell find . -name "*.go" -type f -not -path "./vendor/*")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOLINT=golint
GOVET=$(GOCMD) vet

# Build flags
BUILD_FLAGS=-ldflags="-s -w"
DEV_FLAGS=-race

## build: Build the binary
build: deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	$(GOBUILD) $(BUILD_FLAGS) -o $(BINARY_PATH) $(CMD_PATH)
	@echo "Binary built: $(BINARY_PATH)"

## build-dev: Build with race detection for development
build-dev: deps
	@echo "Building $(BINARY_NAME) with race detection..."
	@mkdir -p bin
	$(GOBUILD) $(DEV_FLAGS) -o $(BINARY_PATH) $(CMD_PATH)
	@echo "Development binary built: $(BINARY_PATH)"

## install: Install the binary to GOPATH/bin
install: deps
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(CMD_PATH)

## clean: Clean build files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf bin/
	@rm -rf dist/
	@echo "Cleaned"

## test: Run tests
test: deps
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

## test-coverage: Run tests with coverage report
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## bench: Run benchmarks
bench: deps
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w $(GO_FILES)

## fmt-check: Check if code is formatted
fmt-check:
	@echo "Checking code formatting..."
	@unformatted=$$($(GOFMT) -l $(GO_FILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## deps-update: Update dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

## run: Run the application (requires PCAP_FILE environment variable)
run: build
	@if [ -z "$(PCAP_FILE)" ]; then \
		echo "Usage: make run PCAP_FILE=path/to/file.pcap"; \
		exit 1; \
	fi
	./$(BINARY_PATH) -file $(PCAP_FILE)

## dev: Development mode - build and run with sample file
dev: build-dev
	@echo "Development mode..."
	@if [ -z "$(PCAP_FILE)" ]; then \
		echo "Usage: make dev PCAP_FILE=path/to/file.pcap"; \
		exit 1; \
	fi
	./$(BINARY_PATH) -file $(PCAP_FILE)

## check: Run all checks (format, vet, lint, test)
check: fmt-check vet lint test
	@echo "All checks passed!"

## release: Build release binaries for multiple platforms
release: clean
	@echo "Building release binaries..."
	@mkdir -p dist
	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)
	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)
	@echo "Release binaries built in dist/"

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME) .

## mod-verify: Verify dependencies
mod-verify:
	@echo "Verifying module dependencies..."
	$(GOMOD) verify

## mod-why: Explain why packages are needed
mod-why:
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make mod-why PKG=package-name"; \
		exit 1; \
	fi
	$(GOMOD) why $(PKG)

## tools: Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

## help: Show this help message
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

# Git hooks
## install-hooks: Install git hooks
install-hooks:
	@echo "Installing git hooks..."
	@cp scripts/pre-commit .git/hooks/pre-commit || echo "No pre-commit hook script found"
	@chmod +x .git/hooks/pre-commit || true

# Security
## security: Run security checks
security:
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install it with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi