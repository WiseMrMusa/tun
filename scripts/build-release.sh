#!/usr/bin/env bash
#
# Build release binaries for all supported platforms
#
# Usage:
#   ./scripts/build-release.sh [OPTIONS]
#
# Options:
#   --target <target>    Build for specific target (e.g., x86_64-unknown-linux-gnu)
#   --all                Build for all platforms
#   --linux              Build for Linux platforms only
#   --macos              Build for macOS platforms only
#   --windows            Build for Windows platforms only
#   --version <version>  Set version for release archives (default: from Cargo.toml)
#   --clean              Clean dist directory before building
#   --help               Show this help message
#
# Requirements:
#   - Rust toolchain with required targets
#   - cross (cargo install cross) for cross-compilation
#   - Docker (required by cross for Linux ARM64)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_ROOT}/dist"

# Supported targets
declare -A TARGETS=(
    ["linux-x86_64"]="x86_64-unknown-linux-gnu"
    ["linux-arm64"]="aarch64-unknown-linux-gnu"
    ["darwin-x86_64"]="x86_64-apple-darwin"
    ["darwin-arm64"]="aarch64-apple-darwin"
    ["windows-x86_64"]="x86_64-pc-windows-msvc"
)

# Default options
BUILD_TARGETS=()
VERSION=""
CLEAN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            BUILD_TARGETS+=("$2")
            shift 2
            ;;
        --all)
            BUILD_TARGETS=("linux-x86_64" "linux-arm64" "darwin-x86_64" "darwin-arm64" "windows-x86_64")
            shift
            ;;
        --linux)
            BUILD_TARGETS+=("linux-x86_64" "linux-arm64")
            shift
            ;;
        --macos)
            BUILD_TARGETS+=("darwin-x86_64" "darwin-arm64")
            shift
            ;;
        --windows)
            BUILD_TARGETS+=("windows-x86_64")
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --help)
            head -30 "$0" | tail -27
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Get version from Cargo.toml if not specified
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep -m1 'version = ' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
    VERSION="v${VERSION}"
fi

# Print banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Tun Release Builder                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo ""

# Detect current platform
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$os" in
        linux) os="linux" ;;
        darwin) os="darwin" ;;
        mingw*|msys*|cygwin*) os="windows" ;;
    esac
    
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="arm64" ;;
    esac
    
    echo "${os}-${arch}"
}

CURRENT_PLATFORM=$(detect_platform)
echo -e "Current platform: ${YELLOW}${CURRENT_PLATFORM}${NC}"

# If no targets specified, build for current platform
if [[ ${#BUILD_TARGETS[@]} -eq 0 ]]; then
    BUILD_TARGETS=("$CURRENT_PLATFORM")
fi

echo -e "Build targets: ${GREEN}${BUILD_TARGETS[*]}${NC}"
echo ""

# Check if we can build for a target
can_build_native() {
    local target=$1
    [[ "$target" == "$CURRENT_PLATFORM" ]]
}

needs_cross() {
    local target=$1
    case "$target" in
        linux-arm64) return 0 ;;
        linux-x86_64)
            [[ "$CURRENT_PLATFORM" != "linux-x86_64" ]] && return 0
            return 1
            ;;
        windows-x86_64)
            [[ "$CURRENT_PLATFORM" != "windows-x86_64" ]] && return 0
            return 1
            ;;
        *) return 1 ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}Error: cargo not found. Please install Rust.${NC}"
        exit 1
    fi
    
    for target in "${BUILD_TARGETS[@]}"; do
        if needs_cross "$target"; then
            if ! command -v cross &> /dev/null; then
                echo -e "${YELLOW}Warning: cross not found. Installing...${NC}"
                cargo install cross --git https://github.com/cross-rs/cross
            fi
            if ! command -v docker &> /dev/null; then
                echo -e "${RED}Error: Docker required for cross-compilation but not found.${NC}"
                exit 1
            fi
            break
        fi
    done
    
    echo -e "${GREEN}Prerequisites OK${NC}"
    echo ""
}

# Build for a specific target
build_target() {
    local platform=$1
    local target=${TARGETS[$platform]}
    local binary_suffix=""
    
    [[ "$platform" == windows-* ]] && binary_suffix=".exe"
    
    echo -e "${BLUE}Building for ${platform} (${target})...${NC}"
    
    # Install target if needed
    if ! rustup target list --installed | grep -q "$target"; then
        echo -e "${YELLOW}Installing target ${target}...${NC}"
        rustup target add "$target" 2>/dev/null || true
    fi
    
    # Determine build command
    local build_cmd="cargo"
    if needs_cross "$platform"; then
        build_cmd="cross"
    fi
    
    # Check if we can build this target
    if [[ "$platform" == darwin-* && "$CURRENT_PLATFORM" != darwin-* ]]; then
        echo -e "${YELLOW}Skipping ${platform}: macOS targets can only be built on macOS${NC}"
        return 0
    fi
    
    if [[ "$platform" == windows-* && "$CURRENT_PLATFORM" != windows-* && "$build_cmd" != "cross" ]]; then
        echo -e "${YELLOW}Note: Building Windows target using cross...${NC}"
        build_cmd="cross"
    fi
    
    # Build
    cd "$PROJECT_ROOT"
    $build_cmd build --release --target "$target"
    
    # Create release directory
    local release_dir="${DIST_DIR}/tun-${VERSION}-${platform}"
    mkdir -p "$release_dir"
    
    # Copy binaries
    cp "target/${target}/release/tun-server${binary_suffix}" "$release_dir/"
    cp "target/${target}/release/tun-client${binary_suffix}" "$release_dir/"
    cp "target/${target}/release/tun-token${binary_suffix}" "$release_dir/"
    
    # Copy documentation
    cp README.md "$release_dir/"
    
    # Create archive
    cd "$DIST_DIR"
    if [[ "$platform" == windows-* ]]; then
        zip -r "tun-${VERSION}-${platform}.zip" "tun-${VERSION}-${platform}"
        echo -e "${GREEN}Created: tun-${VERSION}-${platform}.zip${NC}"
    else
        tar -czvf "tun-${VERSION}-${platform}.tar.gz" "tun-${VERSION}-${platform}"
        echo -e "${GREEN}Created: tun-${VERSION}-${platform}.tar.gz${NC}"
    fi
    
    echo ""
}

# Create checksums
create_checksums() {
    echo -e "${BLUE}Creating checksums...${NC}"
    cd "$DIST_DIR"
    
    if command -v sha256sum &> /dev/null; then
        sha256sum *.tar.gz *.zip 2>/dev/null > SHA256SUMS.txt || true
    elif command -v shasum &> /dev/null; then
        shasum -a 256 *.tar.gz *.zip 2>/dev/null > SHA256SUMS.txt || true
    fi
    
    if [[ -f SHA256SUMS.txt ]]; then
        echo -e "${GREEN}Created: SHA256SUMS.txt${NC}"
        cat SHA256SUMS.txt
    fi
}

# Main build process
main() {
    check_prerequisites
    
    # Clean dist directory if requested
    if [[ "$CLEAN" == true ]]; then
        echo -e "${YELLOW}Cleaning dist directory...${NC}"
        rm -rf "$DIST_DIR"
    fi
    
    mkdir -p "$DIST_DIR"
    
    # Build each target
    for target in "${BUILD_TARGETS[@]}"; do
        if [[ -n "${TARGETS[$target]:-}" ]]; then
            build_target "$target"
        else
            echo -e "${RED}Unknown target: ${target}${NC}"
            echo "Available targets: ${!TARGETS[*]}"
            exit 1
        fi
    done
    
    # Create checksums
    create_checksums
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Build Complete!                           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Release artifacts are in: ${BLUE}${DIST_DIR}${NC}"
    ls -la "$DIST_DIR"
}

main

