#!/bin/bash

# update-dependencies.sh
# Automatically updates Rust dependencies, runs tests, and reports results

set -e # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Dependency Update Script"
echo "=========================================="
echo ""

# Check if cargo is installed
if ! command -v cargo &>/dev/null; then
  echo "Error: cargo is not installed or not in PATH"
  exit 1
fi

# Check if we're in a Rust project
if [ ! -f "Cargo.toml" ]; then
  echo "Error: Cargo.toml not found. Are you in a Rust project directory?"
  exit 1
fi

echo "Step 1: Updating crates.io index..."
echo "------------------------------------------"
cargo update

echo ""
echo "Step 2: Building project with updated dependencies..."
echo "------------------------------------------"
cargo build

echo ""
echo "Step 3: Running tests..."
echo "------------------------------------------"
cargo test

echo ""
echo "Step 4: Running clippy linter..."
echo "------------------------------------------"
cargo clippy -- -W clippy::all

echo ""
echo "Step 5: Checking code formatting..."
echo "------------------------------------------"
cargo fmt --check || {
  echo "Warning: Code formatting issues detected. Run 'cargo fmt' to fix."
}

echo ""
echo "=========================================="
echo "✅ Dependency update completed successfully!"
echo "=========================================="
echo ""
echo "Summary of changes:"
cargo tree --depth 1 | head -20

echo ""
echo "Next steps:"
echo "  1. Review the dependency changes above"
echo "  2. Update CHANGELOG.md if needed"
echo "  3. Commit the updated Cargo.lock file"
echo "  4. Consider running 'cargo outdated' to see available major version updates"
echo ""
