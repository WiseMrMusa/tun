# Tun - Makefile for building and releasing
#
# Usage:
#   make              - Build debug binaries for current platform
#   make release      - Build release binaries for current platform
#   make release-all  - Build release binaries for all platforms
#   make clean        - Clean build artifacts
#   make help         - Show all available targets

.PHONY: all build release release-all release-linux release-macos release-windows \
        clean test fmt lint check install help docker-build docker-push

# Default shell
SHELL := /bin/bash

# Project info
PROJECT_NAME := tun
VERSION := $(shell grep -m1 'version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

# Directories
DIST_DIR := dist
TARGET_DIR := target

# Binaries
BINARIES := tun-server tun-client tun-token

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

# =============================================================================
# Default target
# =============================================================================

all: build

# =============================================================================
# Development
# =============================================================================

## build: Build debug binaries for current platform
build:
	@echo -e "$(BLUE)Building debug binaries...$(NC)"
	cargo build

## release: Build release binaries for current platform
release:
	@echo -e "$(BLUE)Building release binaries...$(NC)"
	cargo build --release
	@echo -e "$(GREEN)Release binaries built in target/release/$(NC)"
	@ls -la target/release/tun-*

## test: Run all tests
test:
	@echo -e "$(BLUE)Running tests...$(NC)"
	cargo test

## fmt: Format code
fmt:
	@echo -e "$(BLUE)Formatting code...$(NC)"
	cargo fmt

## lint: Run clippy lints
lint:
	@echo -e "$(BLUE)Running clippy...$(NC)"
	cargo clippy -- -D warnings

## check: Run cargo check
check:
	@echo -e "$(BLUE)Running cargo check...$(NC)"
	cargo check

# =============================================================================
# Cross-Platform Release Builds
# =============================================================================

## release-all: Build release binaries for all platforms
release-all:
	@echo -e "$(BLUE)Building for all platforms...$(NC)"
	./scripts/build-release.sh --all --clean --version v$(VERSION)

## release-linux: Build release binaries for Linux (x86_64 and ARM64)
release-linux:
	@echo -e "$(BLUE)Building for Linux platforms...$(NC)"
	./scripts/build-release.sh --linux --version v$(VERSION)

## release-macos: Build release binaries for macOS (x86_64 and ARM64)
release-macos:
	@echo -e "$(BLUE)Building for macOS platforms...$(NC)"
	./scripts/build-release.sh --macos --version v$(VERSION)

## release-windows: Build release binaries for Windows (x86_64)
release-windows:
	@echo -e "$(BLUE)Building for Windows...$(NC)"
	./scripts/build-release.sh --windows --version v$(VERSION)

## release-linux-x86_64: Build release binaries for Linux x86_64
release-linux-x86_64:
	./scripts/build-release.sh --target linux-x86_64 --version v$(VERSION)

## release-linux-arm64: Build release binaries for Linux ARM64
release-linux-arm64:
	./scripts/build-release.sh --target linux-arm64 --version v$(VERSION)

## release-darwin-x86_64: Build release binaries for macOS x86_64
release-darwin-x86_64:
	./scripts/build-release.sh --target darwin-x86_64 --version v$(VERSION)

## release-darwin-arm64: Build release binaries for macOS ARM64
release-darwin-arm64:
	./scripts/build-release.sh --target darwin-arm64 --version v$(VERSION)

## release-windows-x86_64: Build release binaries for Windows x86_64
release-windows-x86_64:
	./scripts/build-release.sh --target windows-x86_64 --version v$(VERSION)

# =============================================================================
# Installation
# =============================================================================

## install: Install binaries to ~/.cargo/bin
install: release
	@echo -e "$(BLUE)Installing binaries...$(NC)"
	@for bin in $(BINARIES); do \
		cp target/release/$$bin ~/.cargo/bin/; \
		echo -e "$(GREEN)Installed: $$bin$(NC)"; \
	done

## install-server: Install only tun-server
install-server: release
	cp target/release/tun-server ~/.cargo/bin/
	@echo -e "$(GREEN)Installed: tun-server$(NC)"

## install-client: Install only tun-client
install-client: release
	cp target/release/tun-client ~/.cargo/bin/
	@echo -e "$(GREEN)Installed: tun-client$(NC)"

# =============================================================================
# Docker
# =============================================================================

## docker-build: Build Docker images locally
docker-build: release-linux
	@echo -e "$(BLUE)Building Docker images...$(NC)"
	docker build -f docker/Dockerfile.server -t $(PROJECT_NAME)-server:$(VERSION) .
	docker build -f docker/Dockerfile.client -t $(PROJECT_NAME)-client:$(VERSION) .
	@echo -e "$(GREEN)Docker images built$(NC)"

## docker-push: Push Docker images to registry (requires REGISTRY env var)
docker-push:
ifndef REGISTRY
	$(error REGISTRY is not set. Use: make docker-push REGISTRY=ghcr.io/username)
endif
	docker tag $(PROJECT_NAME)-server:$(VERSION) $(REGISTRY)/$(PROJECT_NAME)-server:$(VERSION)
	docker tag $(PROJECT_NAME)-client:$(VERSION) $(REGISTRY)/$(PROJECT_NAME)-client:$(VERSION)
	docker push $(REGISTRY)/$(PROJECT_NAME)-server:$(VERSION)
	docker push $(REGISTRY)/$(PROJECT_NAME)-client:$(VERSION)

# =============================================================================
# Development Server
# =============================================================================

## run-server: Run the server in development mode
run-server:
	cargo run --bin tun-server -- --domain localhost --debug

## run-client: Run the client (requires TOKEN env var)
run-client:
ifndef TOKEN
	$(error TOKEN is not set. Use: make run-client TOKEN=your-token LOCAL_PORT=3000)
endif
ifndef LOCAL_PORT
	$(error LOCAL_PORT is not set. Use: make run-client TOKEN=your-token LOCAL_PORT=3000)
endif
	cargo run --bin tun-client -- --server localhost:8080 --local-port $(LOCAL_PORT) --token $(TOKEN) --debug

## gen-token: Generate a token using tun-token
gen-token:
ifndef SECRET
	$(error SECRET is not set. Use: make gen-token SECRET=your-hex-secret)
endif
	cargo run --bin tun-token -- --secret $(SECRET)

# =============================================================================
# Cleanup
# =============================================================================

## clean: Clean build artifacts
clean:
	@echo -e "$(BLUE)Cleaning build artifacts...$(NC)"
	cargo clean
	rm -rf $(DIST_DIR)
	@echo -e "$(GREEN)Clean complete$(NC)"

## clean-dist: Clean only distribution directory
clean-dist:
	@echo -e "$(BLUE)Cleaning dist directory...$(NC)"
	rm -rf $(DIST_DIR)

# =============================================================================
# Setup
# =============================================================================

## setup: Install development dependencies
setup:
	@echo -e "$(BLUE)Installing development dependencies...$(NC)"
	rustup component add clippy rustfmt
	@echo -e "$(BLUE)Installing cross-compilation tools...$(NC)"
	cargo install cross --git https://github.com/cross-rs/cross
	@echo -e "$(BLUE)Adding target triples...$(NC)"
	rustup target add x86_64-unknown-linux-gnu
	rustup target add aarch64-unknown-linux-gnu
	rustup target add x86_64-apple-darwin
	rustup target add aarch64-apple-darwin
	rustup target add x86_64-pc-windows-msvc
	@echo -e "$(GREEN)Setup complete$(NC)"

# =============================================================================
# Help
# =============================================================================

## help: Show this help message
help:
	@echo -e "$(BLUE)Tun - Secure Port Tunneling Service$(NC)"
	@echo ""
	@echo "Version: $(VERSION)"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/  /'
	@echo ""
	@echo "Examples:"
	@echo "  make release          # Build release for current platform"
	@echo "  make release-all      # Build for all platforms"
	@echo "  make install          # Install to ~/.cargo/bin"
	@echo "  make docker-build     # Build Docker images"
	@echo ""

# =============================================================================
# Version info
# =============================================================================

## version: Show version
version:
	@echo "$(PROJECT_NAME) v$(VERSION)"

