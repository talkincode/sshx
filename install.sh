#!/bin/bash
# sshx Automatic Installation Script
# Supports: Linux (amd64/arm64), macOS (amd64/arm64)

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="talkincode/sshx"
VERSION="${1:-latest}" # Use argument or default to latest
BINARY_NAME="sshx"
INSTALL_DIR="/usr/local/bin"
SKILL_INSTALL_DIR="${SSHX_SKILLS_DIR:-${HOME}/.agents/skills/sshx}"

# Functions
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Detect OS and Architecture
detect_platform() {
    local os=""
    local arch=""
    
    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
        ;;
    esac
    
    # Detect Architecture
    # On macOS, use sysctl to get the real hardware architecture (not affected by Rosetta 2)
    if [ "$os" = "darwin" ]; then
        local hw_arch
        hw_arch=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
        if echo "$hw_arch" | grep -q "Apple"; then
            # Apple Silicon
            arch="arm64"
        else
            # Intel Mac or fallback to uname
            local machine
            machine=$(uname -m)
            case "$machine" in
                x86_64|amd64)   arch="amd64" ;;
                arm64|aarch64)  arch="arm64" ;;
                *)              arch="amd64" ;; # Default to amd64 for Intel
            esac
        fi
    else
        # For Linux, use uname -m
        case "$(uname -m)" in
            x86_64|amd64)   arch="amd64" ;;
            aarch64|arm64)  arch="arm64" ;;
            *)
                print_error "Unsupported architecture: $(uname -m)"
                exit 1
            ;;
        esac
    fi
    
    echo "${os}-${arch}"
}

# Get latest version from GitHub
get_latest_version() {
    local latest_version
    latest_version=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$latest_version" ]; then
        print_error "Failed to fetch latest version" >&2
        exit 1
    fi
    
    echo "$latest_version"
}

verify_checksum() {
    local filename="$1"
    local version="$2"
    local checksums_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"
    local checksum_file="checksums.txt"

    print_info "Downloading checksums..."
    if command -v wget &> /dev/null; then
        wget -q -O "$checksum_file" "$checksums_url" || {
            print_error "Failed to download checksums"
            exit 1
        }
    else
        curl -fsSL -o "$checksum_file" "$checksums_url" || {
            print_error "Failed to download checksums"
            exit 1
        }
    fi

    local expected
    expected=$(grep " ${filename}$" "$checksum_file" | awk '{print $1}')
    if [ -z "$expected" ]; then
        print_error "Checksum for $filename not found"
        exit 1
    fi

    local actual
    if command -v sha256sum &> /dev/null; then
        actual=$(sha256sum "$filename" | awk '{print $1}')
    elif command -v shasum &> /dev/null; then
        actual=$(shasum -a 256 "$filename" | awk '{print $1}')
    else
        print_error "Neither sha256sum nor shasum found. Cannot verify download."
        exit 1
    fi

    if [ "$actual" != "$expected" ]; then
        print_error "Checksum verification failed"
        print_error "Expected: $expected"
        print_error "Actual:   $actual"
        exit 1
    fi

    print_success "Checksum verified"

    if command -v cosign >/dev/null 2>&1; then
        local bundle="${filename}.cosign.bundle"
        local bundle_url="https://github.com/${REPO}/releases/download/${version}/${bundle}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL -o "$bundle" "$bundle_url" || true
        elif command -v wget >/dev/null 2>&1; then
            wget -q -O "$bundle" "$bundle_url" || true
        fi
        if [ -f "$bundle" ]; then
            cosign verify-blob \
                --bundle "$bundle" \
                --certificate-identity-regexp 'https://github.com/talkincode/sshx/.*' \
                --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                "$filename"
            print_success "cosign signature verified"
        else
            print_warning "cosign bundle not found; skipping signature verification"
        fi
    fi
}

install_agent_skill() {
    local installed_binary="$1"

    # New releases carry the canonical skill inside the binary. Keep the
    # archive fallback only for older binaries that do not expose the command;
    # a supported command's safety failure must stop the installation.
    if "$installed_binary" --help 2>/dev/null | grep -q "sshx skill install"; then
        "$installed_binary" skill install \
            --dir="$SKILL_INSTALL_DIR" \
            --force \
            --no-audit >/dev/null
        print_success "Installed embedded agent skill to ${SKILL_INSTALL_DIR}/SKILL.md"
        return
    fi

    if [ -f "SKILL.md" ]; then
        if [ -L "$SKILL_INSTALL_DIR" ] || [ -L "${SKILL_INSTALL_DIR}/SKILL.md" ]; then
            print_error "Refusing to install the agent skill through a symlinked target"
            exit 1
        fi
        mkdir -p "$SKILL_INSTALL_DIR"
        cp "SKILL.md" "${SKILL_INSTALL_DIR}/SKILL.md"
        chmod 0644 "${SKILL_INSTALL_DIR}/SKILL.md"
        print_success "Installed archive agent skill to ${SKILL_INSTALL_DIR}/SKILL.md"
        return
    fi

    print_warning "This sshx version does not provide an installable agent skill"
}

# Download and install
install_sshx() {
    local platform
    platform=$(detect_platform)
    local version="$VERSION"
    
    if [ "$version" = "latest" ]; then
        print_info "Fetching latest version..."
        version=$(get_latest_version)
    fi
    
    print_info "Platform: $platform"
    print_info "Version: $version"
    
    # Construct download URL
    local filename="${BINARY_NAME}-${platform}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${filename}"
    
    print_info "Downloading from: $download_url"
    
    # Create temporary directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    cd "$tmp_dir"
    
    # Download
    if command -v wget &> /dev/null; then
        wget -q --show-progress "$download_url" || {
            print_error "Download failed"
            rm -rf "$tmp_dir"
            exit 1
        }
        elif command -v curl &> /dev/null; then
        curl -L -o "$filename" "$download_url" || {
            print_error "Download failed"
            rm -rf "$tmp_dir"
            exit 1
        }
    else
        print_error "Neither wget nor curl found. Please install one of them."
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    print_success "Downloaded successfully"
    verify_checksum "$filename" "$version"
    
    # Extract
    print_info "Extracting..."
    tar -xzf "$filename" || {
        print_error "Extraction failed"
        rm -rf "$tmp_dir"
        exit 1
    }
    
    # Find the extracted binary (handle both 'sshx' and platform-specific names)
    local binary_file=""
    if [ -f "$BINARY_NAME" ]; then
        binary_file="$BINARY_NAME"
        elif [ -f "${BINARY_NAME}-${platform}" ]; then
        binary_file="${BINARY_NAME}-${platform}"
    else
        # Try to find any executable file
        binary_file=$(find . -maxdepth 1 -type f -executable | head -n 1)
        if [ -z "$binary_file" ]; then
            print_error "Could not find binary in extracted archive"
            print_info "Contents: $(ls -la)"
            rm -rf "$tmp_dir"
            exit 1
        fi
    fi
    
    # Install
    print_info "Installing to ${INSTALL_DIR}..."
    
    if [ -w "$INSTALL_DIR" ]; then
        cp "$binary_file" "${INSTALL_DIR}/${BINARY_NAME}" && chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo cp "$binary_file" "${INSTALL_DIR}/${BINARY_NAME}" && sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    install_agent_skill "${INSTALL_DIR}/${BINARY_NAME}"
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$tmp_dir"
    
    print_success "Installation complete!"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" &> /dev/null; then
        local installed_version
        installed_version=$($BINARY_NAME --version 2>&1 || echo "unknown")
        print_success "${BINARY_NAME} installed successfully"
        print_info "Location: $(command -v "$BINARY_NAME")"
        print_info "Version: ${installed_version}"
        echo ""
        echo "Run '$BINARY_NAME --help' to get started"
    else
        print_error "Installation verification failed"
        print_warning "You may need to add ${INSTALL_DIR} to your PATH"
        exit 1
    fi
}

# Check for existing installation
check_existing() {
    if command -v "$BINARY_NAME" &> /dev/null; then
        print_warning "${BINARY_NAME} is already installed at: $(command -v "$BINARY_NAME")"
        read -p "Do you want to overwrite it? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi
}

# Main
main() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║   sshx Automatic Installer            ║"
    echo "║   Agent-native execution over SSH      ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    # Check requirements
    if ! command -v tar &> /dev/null; then
        print_error "tar is required but not installed"
        exit 1
    fi
    
    check_existing
    install_sshx
    verify_installation
    
    echo ""
    print_info "Quick Start:"
    echo "  # Execute remote command"
    echo "  sshx -h=192.168.1.100 -u=root 'uptime'"
    echo ""
    echo "  # Save password (optional)"
    echo "  sshx --password-set=master"
    echo ""
    print_info "Documentation: https://github.com/${REPO}"
}

# Run only when executed, so tests and shell tooling can safely source helpers.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main
fi
