#!/bin/bash
# SHA1-HULUD Scanner - Complete version with 350+ packages
# Scans a Node.js project (or nested projects) to detect compromised packages

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Known false positives (legitimate packages with "sha1" in their name)
FALSE_POSITIVES=(
  "@aws-crypto/sha1-browser"
  "@aws-crypto/sha256-browser"
  "@aws-crypto/sha256-js"
  "sha1"
  "sha.js"
)

# Options
RECURSIVE=false

# Show help
show_help() {
  echo "Usage: $0 [options] <project_directory>"
  echo ""
  echo "Scans a Node.js project to detect packages compromised by SHA1-HULUD pt 2"
  echo ""
  echo "Options:"
  echo "  -r, --recursive    Scan all nested Node.js projects in the directory"
  echo "  -h, --help         Show this help message"
  echo ""
  echo "Example:"
  echo "  $0 /path/to/project"
  echo "  $0 -r ~/Projects/monorepo"
  echo "  $0 --recursive /path/to/workspace"
  echo ""
  echo "The script uses sha1-hulud-packages.txt file (288+ packages)"
}

# Parse options
while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--recursive)
      RECURSIVE=true
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    -*)
      echo -e "${RED}❌ Error: Unknown option '$1'${NC}"
      echo ""
      show_help
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

# Check if argument provided
if [ $# -eq 0 ]; then
  echo -e "${RED}❌ Error: No directory specified${NC}"
  echo ""
  show_help
  exit 1
fi

ROOT_DIR="$1"

# Check if directory exists
if [ ! -d "$ROOT_DIR" ]; then
  echo -e "${RED}❌ Error: Directory '$ROOT_DIR' does not exist${NC}"
  exit 1
fi

# File containing list of compromised packages
PACKAGES_FILE="$(dirname "$0")/sha1-hulud-packages.txt"

# Load package list
if [ ! -f "$PACKAGES_FILE" ]; then
  echo -e "${RED}❌ Error: Package file not found: $PACKAGES_FILE${NC}"
  echo ""
  echo "Create sha1-hulud-packages.txt in the same directory as this script."
  exit 1
fi

# Read packages (ignore empty lines and comments)
COMPROMISED_PACKAGES=()
while IFS= read -r line; do
  # Ignore comments and empty lines
  [[ "$line" =~ ^#.*$ ]] && continue
  [[ -z "$line" ]] && continue
  COMPROMISED_PACKAGES+=("$line")
done < "$PACKAGES_FILE"

# Global counters (across all projects)
GLOBAL_FOUND=0
GLOBAL_FOUND_PACKAGES=()
PROJECTS_SCANNED=0
COMPROMISED_PROJECTS=()

# Current project counters (reset per project)
FOUND=0
FOUND_PACKAGES=()
TOTAL_CHECKS=0
PROJECT_DIR=""

# Scan direct dependencies
scan_package_json() {
  local pkg_count=${#COMPROMISED_PACKAGES[@]}
  echo -e "🔎 [1/4] Scanning direct dependencies (package.json)... ${BLUE}[0/$pkg_count]${NC}\r\c"

  if [ ! -f "$PROJECT_DIR/package.json" ]; then
    echo ""
    return
  fi

  local i=0
  for package in "${COMPROMISED_PACKAGES[@]}"; do
    i=$((i + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Update progress every 50 packages
    if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
      echo -e "🔎 [1/4] Scanning direct dependencies (package.json)... ${BLUE}[$i/$pkg_count]${NC}\r\c"
    fi

    # Search in dependencies and devDependencies
    if grep -q "\"$package\"" "$PROJECT_DIR/package.json" 2>/dev/null; then
      echo ""
      echo -e "  ${RED}⚠️  FOUND: $package in package.json${NC}"
      FOUND=$((FOUND + 1))
      FOUND_PACKAGES+=("$package (direct)")
    fi
  done

  echo ""
  if [ $FOUND -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in direct dependencies${NC}"
  fi
}

# Scan node_modules
scan_node_modules() {
  local pkg_count=${#COMPROMISED_PACKAGES[@]}
  echo ""
  echo -e "🔎 [2/4] Scanning node_modules (transitive)... ${BLUE}[0/$pkg_count]${NC}\r\c"

  if [ ! -d "$PROJECT_DIR/node_modules" ]; then
    echo ""
    echo -e "  ${YELLOW}⚠️  node_modules not found (run 'npm install' first)${NC}"
    return
  fi

  local found_in_modules=0
  local i=0

  for package in "${COMPROMISED_PACKAGES[@]}"; do
    i=$((i + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Update progress every 50 packages
    if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
      echo -e "🔎 [2/4] Scanning node_modules (transitive)... ${BLUE}[$i/$pkg_count]${NC}\r\c"
    fi

    # For scoped packages (@xxx/), search exact folder
    if [[ "$package" == @*/* ]]; then
      if [ -d "$PROJECT_DIR/node_modules/$package" ]; then
        echo ""
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      fi
    else
      # For non-scoped packages
      if [ -d "$PROJECT_DIR/node_modules/$package" ]; then
        echo ""
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      fi
    fi
  done

  echo ""
  if [ $found_in_modules -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages installed${NC}"
  fi
}

# Scan lockfiles
scan_lockfiles() {
  local pkg_count=${#COMPROMISED_PACKAGES[@]}
  echo ""
  echo "🔎 [3/4] Scanning lockfiles..."

  local found_in_locks=0
  local i=0

  # package-lock.json
  if [ -f "$PROJECT_DIR/package-lock.json" ]; then
    i=0
    echo -e "  📄 Scanning package-lock.json... ${BLUE}[0/$pkg_count]${NC}\r\c"
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      i=$((i + 1))
      if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
        echo -e "  📄 Scanning package-lock.json... ${BLUE}[$i/$pkg_count]${NC}\r\c"
      fi
      if grep -q "\"$package\"" "$PROJECT_DIR/package-lock.json" 2>/dev/null; then
        echo ""
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
    echo ""
  fi

  # yarn.lock
  if [ -f "$PROJECT_DIR/yarn.lock" ]; then
    i=0
    echo -e "  📄 Scanning yarn.lock... ${BLUE}[0/$pkg_count]${NC}\r\c"
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      i=$((i + 1))
      if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
        echo -e "  📄 Scanning yarn.lock... ${BLUE}[$i/$pkg_count]${NC}\r\c"
      fi
      if grep -q "$package@" "$PROJECT_DIR/yarn.lock" 2>/dev/null; then
        echo ""
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
    echo ""
  fi

  # bun.lock (binary file - use strings)
  if [ -f "$PROJECT_DIR/bun.lock" ]; then
    i=0
    echo -e "  📄 Scanning bun.lock... ${BLUE}[0/$pkg_count]${NC}\r\c"
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      i=$((i + 1))
      if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
        echo -e "  📄 Scanning bun.lock... ${BLUE}[$i/$pkg_count]${NC}\r\c"
      fi
      if strings "$PROJECT_DIR/bun.lock" 2>/dev/null | grep -q "$package"; then
        echo ""
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
    echo ""
  fi

  # pnpm-lock.yaml
  if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
    i=0
    echo -e "  📄 Scanning pnpm-lock.yaml... ${BLUE}[0/$pkg_count]${NC}\r\c"
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      i=$((i + 1))
      if [ $((i % 50)) -eq 0 ] || [ $i -eq $pkg_count ]; then
        echo -e "  📄 Scanning pnpm-lock.yaml... ${BLUE}[$i/$pkg_count]${NC}\r\c"
      fi
      if grep -q "$package" "$PROJECT_DIR/pnpm-lock.yaml" 2>/dev/null; then
        echo ""
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
    echo ""
  fi

  if [ $found_in_locks -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in lockfiles${NC}"
  fi
}

# Check if a package is a false positive
is_false_positive() {
  local package="$1"
  for fp in "${FALSE_POSITIVES[@]}"; do
    if [[ "$package" == *"$fp"* ]]; then
      return 0  # True, it's a false positive
    fi
  done
  return 1  # False, not a false positive
}

# Search for SHA1-HULUD markers
scan_sha1_markers() {
  echo ""
  echo "🔎 [4/4] Scanning for SHA1-HULUD markers..."

  local found_markers=0
  local false_positive_count=0

  # Search for packages with "sha1" in their name in package-lock.json
  if [ -f "$PROJECT_DIR/package-lock.json" ]; then
    local sha1_packages=$(grep -oE '"[^"]*sha1[^"]*"' "$PROJECT_DIR/package-lock.json" 2>/dev/null | sed 's/"//g' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (package-lock.json):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - package-lock.json)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in yarn.lock
  if [ -f "$PROJECT_DIR/yarn.lock" ]; then
    local sha1_packages=$(grep -E "sha1" "$PROJECT_DIR/yarn.lock" 2>/dev/null | grep -oE '^[^@]*@[^@]+@|^@[^"]+@' | sed 's/@$//' | grep "sha1" | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (yarn.lock):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - yarn.lock)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in bun.lock
  if [ -f "$PROJECT_DIR/bun.lock" ]; then
    local sha1_packages=$(strings "$PROJECT_DIR/bun.lock" 2>/dev/null | grep "sha1" | grep -oE '@[a-zA-Z0-9_/-]+sha1[a-zA-Z0-9_-]*|sha1[a-zA-Z0-9_-]+' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (bun.lock):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - bun.lock)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in pnpm-lock.yaml
  if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
    local sha1_packages=$(grep "sha1" "$PROJECT_DIR/pnpm-lock.yaml" 2>/dev/null | grep -oE '[^/]+sha1[^:]*' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (pnpm-lock.yaml):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - pnpm-lock.yaml)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  if [ $found_markers -eq 0 ]; then
    if [ $false_positive_count -gt 0 ]; then
      echo -e "  ${GREEN}✓ No suspicious SHA1 markers (${false_positive_count} legitimate packages excluded)${NC}"
    else
      echo -e "  ${GREEN}✓ No SHA1-HULUD markers detected${NC}"
    fi
  fi
}

# Scan a single project directory
scan_project() {
  PROJECT_DIR="$1"
  local project_num="$2"
  local total_projects="$3"
  
  # Reset per-project counters
  FOUND=0
  FOUND_PACKAGES=()
  TOTAL_CHECKS=0
  
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ -n "$project_num" ] && [ -n "$total_projects" ]; then
    echo -e "📁 ${BLUE}[$project_num/$total_projects]${NC} Scanning: $PROJECT_DIR"
  else
    echo "📁 Scanning: $PROJECT_DIR"
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Run scans
  scan_package_json
  scan_node_modules
  scan_lockfiles
  scan_sha1_markers
  
  PROJECTS_SCANNED=$((PROJECTS_SCANNED + 1))
  
  # Add to global results
  if [ $FOUND -gt 0 ]; then
    GLOBAL_FOUND=$((GLOBAL_FOUND + FOUND))
    COMPROMISED_PROJECTS+=("$PROJECT_DIR")
    for pkg in "${FOUND_PACKAGES[@]}"; do
      GLOBAL_FOUND_PACKAGES+=("$PROJECT_DIR: $pkg")
    done
  fi
  
  # Per-project result
  echo ""
  if [ $FOUND -eq 0 ]; then
    echo -e "  ${GREEN}✓ Project clean${NC}"
  else
    echo -e "  ${RED}⚠️  $FOUND issue(s) found in this project${NC}"
  fi
}

# Find all Node.js projects in a directory
find_projects() {
  local search_dir="$1"
  
  # Find all package.json files, excluding node_modules
  find "$search_dir" -name "package.json" -type f \
    ! -path "*/node_modules/*" \
    ! -path "*/.git/*" \
    2>/dev/null | while read -r pkg_json; do
    dirname "$pkg_json"
  done
}

# Print header
echo ""
echo "🔍 SHA1-HULUD Scanner v2.2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📂 Root: $ROOT_DIR"
echo "🔄 Recursive mode: $RECURSIVE"
echo "📋 ${#COMPROMISED_PACKAGES[@]} packages to check"
echo "📋 ${#FALSE_POSITIVES[@]} known false positives to exclude"

# Main scanning logic
if [ "$RECURSIVE" = true ]; then
  # Recursive mode: find and scan all projects
  echo ""
  echo "🔎 Finding Node.js projects..."
  
  # Collect projects into array
  PROJECTS=()
  while IFS= read -r project; do
    [ -n "$project" ] && PROJECTS+=("$project")
  done < <(find_projects "$ROOT_DIR")
  
  if [ ${#PROJECTS[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No Node.js projects found in '$ROOT_DIR'${NC}"
    exit 0
  fi
  
  TOTAL_PROJECTS=${#PROJECTS[@]}
  echo "📦 Found $TOTAL_PROJECTS project(s)"
  
  # Scan each project with progress
  PROJECT_NUM=0
  for project in "${PROJECTS[@]}"; do
    PROJECT_NUM=$((PROJECT_NUM + 1))
    scan_project "$project" "$PROJECT_NUM" "$TOTAL_PROJECTS"
  done
else
  # Single project mode
  if [ ! -f "$ROOT_DIR/package.json" ]; then
    echo -e "${RED}❌ Error: No package.json found in '$ROOT_DIR'${NC}"
    echo ""
    echo "Tip: Use -r or --recursive to scan for nested projects"
    exit 1
  fi
  
  scan_project "$ROOT_DIR" "1" "1"
fi

# Final summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 SCAN SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $GLOBAL_FOUND -eq 0 ]; then
  echo -e "${GREEN}✅ NO COMPROMISE DETECTED${NC}"
  echo ""
  echo "All projects are clean — no SHA1-HULUD packages found."
  echo ""
  echo "📊 Statistics:"
  echo "   • $PROJECTS_SCANNED project(s) scanned"
  echo "   • ${#COMPROMISED_PACKAGES[@]} packages checked per project"
  echo "   • 0 compromised packages"
  echo ""
  exit 0
else
  echo -e "${RED}🚨 $GLOBAL_FOUND COMPROMISED PACKAGE(S) DETECTED${NC}"
  echo ""
  echo "📊 Statistics:"
  echo "   • $PROJECTS_SCANNED project(s) scanned"
  echo "   • ${#COMPROMISED_PROJECTS[@]} project(s) compromised"
  echo ""
  echo "📦 Affected projects:"
  for proj in "${COMPROMISED_PROJECTS[@]}"; do
    echo "   • $proj"
  done
  echo ""
  echo "📦 Packages found:"
  for pkg in "${GLOBAL_FOUND_PACKAGES[@]}"; do
    echo "   • $pkg"
  done
  echo ""
  echo "⚠️  IMMEDIATE ACTION REQUIRED:"
  echo ""
  echo "   1. 🛑 STOP all builds/CI immediately"
  echo "   2. 🔒 Isolate CI runners (if self-hosted)"
  echo "   3. 🔑 Rotate ALL sensitive keys:"
  echo "      • GitHub tokens (PAT, fine-grained, App)"
  echo "      • AWS credentials (if non-OIDC)"
  echo "      • NPM tokens"
  echo "      • API keys (PostHog, etc.)"
  echo "   4. 🗑  Delete node_modules and lockfiles"
  echo "   5. 📝 Update dependencies"
  echo "   6. 🔍 Audit CI logs from last 48 hours"
  echo ""
  echo "📚 More info: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24"
  echo ""
  exit 1
fi
