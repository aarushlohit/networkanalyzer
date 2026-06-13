#!/usr/bin/env bash
# VulnSync pre-commit hook
# Scans changed hosts in staged config files for open vulnerabilities
set -euo pipefail

echo "🔍 VulnSync pre-commit scan..."

# Check if vulnsync is installed
if ! command -v vulnsync &>/dev/null; then
    echo "  ⚠️  vulnsync not found — run: pip install -e ."
    exit 0
fi

# Get staged files that might contain hosts
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(yml|yaml|json|toml|ini)$' || true)

if [ -z "$STAGED" ]; then
    echo "  ✓ No config files changed, skipping"
    exit 0
fi

# Extract IPs from changed files
HOSTS=$(grep -rhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' $STAGED 2>/dev/null | sort -u | head -5 || true)

if [ -z "$HOSTS" ]; then
    echo "  ✓ No host entries detected in changes"
    exit 0
fi

echo "  Scanning $(echo "$HOSTS" | wc -l) host(s) from changed files..."
vulnsync scan $HOSTS -p 22,80,443,8080,8443 --no-ping --no-cve 2>&1 | sed 's/^/  /'

echo "  ✅ Pre-commit scan complete"
