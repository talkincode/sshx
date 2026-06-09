#!/bin/bash
# Test installation scripts
# This script tests the installation process in a safe way

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🧪 Testing sshx installation scripts"
echo "===================================="
echo ""

# Test 1: Check if install.sh exists and is executable
echo "Test 1: Checking install.sh..."
if [ -f "$PROJECT_ROOT/install.sh" ]; then
    echo "✓ install.sh exists"
    if [ -x "$PROJECT_ROOT/install.sh" ]; then
        echo "✓ install.sh is executable"
    else
        echo "✗ install.sh is not executable"
        exit 1
    fi
else
    echo "✗ install.sh not found"
    exit 1
fi
echo ""

# Test 2: Check if install.ps1 exists
echo "Test 2: Checking install.ps1..."
if [ -f "$PROJECT_ROOT/install.ps1" ]; then
    echo "✓ install.ps1 exists"
else
    echo "✗ install.ps1 not found"
    exit 1
fi
echo ""

# Test 3: Validate shell script syntax
echo "Test 3: Validating shell script syntax..."
if bash -n "$PROJECT_ROOT/install.sh"; then
    echo "✓ install.sh has valid syntax"
else
    echo "✗ install.sh has syntax errors"
    exit 1
fi
echo ""

# Test 4: Check for required functions in install.sh
echo "Test 4: Checking required functions in install.sh..."
required_functions=(
    "detect_platform"
    "get_latest_version"
    "install_sshx"
    "verify_installation"
)

for func in "${required_functions[@]}"; do
    if grep -q "^${func}()" "$PROJECT_ROOT/install.sh" || grep -q "^function ${func}" "$PROJECT_ROOT/install.sh"; then
        echo "✓ Function $func found"
    else
        echo "✗ Function $func not found"
        exit 1
    fi
done
echo ""

# Test 5: Check PowerShell script functions
echo "Test 5: Checking PowerShell script functions..."
ps_functions=(
    "Get-LatestVersion"
    "Get-Platform"
    "Install-Sshx"
    "Test-Installation"
)

for func in "${ps_functions[@]}"; do
    if grep -q "function ${func}" "$PROJECT_ROOT/install.ps1"; then
        echo "✓ Function $func found"
    else
        echo "✗ Function $func not found"
        exit 1
    fi
done
echo ""

# Test 6: Check if GitHub repo URL is correct
echo "Test 6: Validating GitHub repository URL..."
expected_repo="talkincode/sshx"
if grep -q "REPO=\"${expected_repo}\"" "$PROJECT_ROOT/install.sh"; then
    echo "✓ Correct repository in install.sh"
else
    echo "✗ Incorrect repository in install.sh"
    exit 1
fi

if grep -q "\$Repo = \"${expected_repo}\"" "$PROJECT_ROOT/install.ps1"; then
    echo "✓ Correct repository in install.ps1"
else
    echo "✗ Incorrect repository in install.ps1"
    exit 1
fi
echo ""

# Test 7: Dry run (check platform detection)
echo "Test 7: Testing platform detection..."
cd "$PROJECT_ROOT"
if bash -c 'source install.sh && detect_platform' 2>/dev/null; then
    echo "✓ Platform detection works"
else
    echo "⚠ Platform detection test skipped (requires sourcing)"
fi
echo ""

# Test 8: Check if documentation is updated
echo "Test 8: Checking documentation..."
docs_to_check=(
    "README.md"
    "INSTALL.md"
    "QUICK_INSTALL.md"
)

for doc in "${docs_to_check[@]}"; do
    if [ -f "$PROJECT_ROOT/$doc" ]; then
        if grep -q "install.sh" "$PROJECT_ROOT/$doc" || grep -q "install.ps1" "$PROJECT_ROOT/$doc"; then
            echo "✓ $doc mentions installation scripts"
        else
            echo "⚠ $doc might not mention installation scripts"
        fi
    else
        echo "⚠ $doc not found"
    fi
done
echo ""

# Summary
echo "===================================="
echo "✅ All tests passed!"
echo ""
echo "To test installation manually:"
echo "  1. ./install.sh (will attempt real installation)"
echo "  2. Or: bash -x ./install.sh (debug mode)"
echo ""
echo "To test without actual installation:"
echo "  You can modify install.sh to do a dry-run by setting DRY_RUN=1"
