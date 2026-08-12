#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🏷️  Starting to fetch latest tag...${NC}"

# Fetch latest tags
git fetch --tags

# If no tags exist, return v0.0.0 as fallback
latest_ref=$(git rev-list --tags --max-count=1)
latest_tag=$(git describe --tags "$latest_ref" 2>/dev/null || echo "v0.0.0")
echo -e "${YELLOW}📋 Latest tag: ${latest_tag}${NC}"

# Use an explicit semantic version when supplied; otherwise preserve the
# historical patch-increment behavior.
requested_tag="${1:-}"
if [ -n "$requested_tag" ]; then
    if [[ ! "$requested_tag" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}❌ Invalid semantic version: ${requested_tag}${NC}"
        exit 1
    fi
    new_tag="v${requested_tag#v}"
else
    version=${latest_tag#v}
    IFS='.' read -r -a parts <<<"$version"
    last_idx=$((${#parts[@]} - 1))
    parts[last_idx]=$((parts[last_idx] + 1))
    new_version=$(IFS='.'; echo "${parts[*]}")
    new_tag="v$new_version"
fi

if git rev-parse "$new_tag" >/dev/null 2>&1; then
    echo -e "${RED}❌ Tag already exists: ${new_tag}${NC}"
    exit 1
fi

version_number=${new_tag#v}
if ! grep -Fq "## [${version_number}]" CHANGELOG.md; then
    echo -e "${RED}❌ CHANGELOG.md has no entry for ${version_number}${NC}"
    exit 1
fi

echo -e "${GREEN}🎯 New tag: ${new_tag}${NC}"

# Generate commit log
echo -e "${BLUE}📝 Generating commit log...${NC}"

# Get commits from last tag to current HEAD
if [ "$latest_tag" = "v0.0.0" ]; then
    # If no previous tag, get all commits
    commit_range="HEAD"
    echo -e "${YELLOW}💡 No previous tag found, will include all commits${NC}"
else
    # Commits from last tag to current HEAD
    commit_range="${latest_tag}..HEAD"
    echo -e "${YELLOW}📊 Getting commits from ${latest_tag} to current${NC}"
fi

# Generate commit log, format: - [commit_hash] commit_message
commit_log=$(git log "$commit_range" --pretty=format:"- [%h] %s" --reverse)

if [ -z "$commit_log" ]; then
    echo -e "${YELLOW}⚠️  No new commits found${NC}"
    tag_message="Release ${new_tag}"
else
    echo -e "${GREEN}📋 Commit log:${NC}"
    echo "$commit_log"
    echo ""

    # Build tag message
    tag_message="Release ${new_tag}

## Changes since ${latest_tag}

$commit_log"
fi

# Confirm tag creation
echo -e -n "${YELLOW}Confirm creating tag ${new_tag}? (y/n): ${NC}"
read -r confirm

if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    echo -e "${BLUE}🚀 Creating annotated tag ${new_tag}...${NC}"

    # Use -a parameter to create annotated tag, -m parameter to add message
    git tag -a "$new_tag" -m "$tag_message"

    echo -e "${BLUE}📤 Pushing tag to remote repository...${NC}"
    git push origin "$new_tag"

    echo -e "${GREEN}✅ Tag ${new_tag} created and pushed successfully!${NC}"
    echo -e "${GREEN}📄 Tag description includes $(echo "$commit_log" | wc -l | tr -d ' ') commits${NC}"
else
    echo -e "${RED}❌ Tag creation cancelled${NC}"
fi
