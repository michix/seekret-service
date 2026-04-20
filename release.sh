#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version-number>"
  exit 1
fi

VERSION="$1"
TAG="v$VERSION"

# 1. Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Error: Tag $TAG already exists."
  exit 1
fi

# 2. Check if version is above the biggest version
LATEST_TAG=$(git tag -l 'v*' | sed 's/^v//' | sort -V | tail -n1)
if [[ -n "$LATEST_TAG" ]]; then
  if [[ "$(printf '%s\n' "$LATEST_TAG" "$VERSION" | sort -V | tail -n1)" != "$VERSION" ]]; then
    echo "Error: Version $VERSION is not greater than latest version $LATEST_TAG."
    exit 1
  fi
fi

# 3. Set version in Cargo.toml
cargo set-version "$VERSION"

# 4. Commit change
git add Cargo.toml
git commit -m "internal: prepares version $VERSION"

# 5. Ask user to confirm
read -pr "About to tag and push version $VERSION. Press <enter> to continue..."

# 6. Set git tag
git tag "$TAG"

# 7. Push commit and tag
git push
git push origin "$TAG"
