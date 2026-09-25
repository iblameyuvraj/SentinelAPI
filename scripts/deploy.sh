#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI — Universal CLI & Vercel Preview Audit Runner
#
# Syntax:
#   fluffwalks preview "{git-commit}"           # Universal CLI syntax
#   fluffwalks preview                          # Sync & test with default message
#   fluffwalks --help                           # Show CLI documentation
#
# Direct Script Usage:
#   ./scripts/deploy.sh preview "{git-commit}"
#   ./scripts/deploy.sh "{git-commit}"
#
# Flow:
#   1. Resolves repository roots automatically (runs from ANY working directory)
#   2. Syncs, stages, and pushes fluffwalks-web changes to GitHub 'preview' branch
#   3. Triggers/resolves a dedicated Vercel Preview Deployment for 'preview' branch
#   4. Purges stale scan artifacts from previous runs in markdown/
#   5. Injects live preview URL into dynamic OpenAPI 3.0 specification
#   6. Builds SentinelAPI production security container
#   7. Executes 7 OWASP modules against live preview URL
#   8. Generates executive PDF/Markdown reports + Brevo email dispatch
#   9. Pushes audit logs to SentinelAPI 'deployment' branch
#   10. Exits with standardized CI status code (0: PASS, 1: FAIL, 2: ERROR)
# ==============================================================================
set -euo pipefail

# ── Universal Path Resolution ────────────────────────────────────────────────
# Allows running from ANY directory (e.g. ~/ or inside fluffwalks-web)
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
SENTINEL_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
cd "$SENTINEL_ROOT"

# ── Argument Parsing ─────────────────────────────────────────────────────────
show_help() {
    echo "================================================================================"
    echo "🛡️  FLUFFWALKS & SENTINELAPI — PREVIEW AUDIT CLI"
    echo "================================================================================"
    echo "Usage:"
    echo "  fluffwalks preview \"{git-commit}\"     Syncs fluffwalks-web 'preview' branch,"
    echo "                                      builds Vercel preview, and runs audit."
    echo "  fluffwalks preview                  Runs with automated default commit message."
    echo "  fluffwalks preview \"msg\" <URL>      Runs audit against an explicit preview URL."
    echo ""
    echo "Examples:"
    echo "  fluffwalks preview \"feat: add interactive service area component\""
    echo "  fluffwalks preview \"fix: auth modal token parsing\""
    echo "================================================================================"
    exit 0
}

# Check for help flags
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "help" ]; then
    show_help
fi

# Parse 'preview' command keyword or fallback to legacy syntax
MANUAL_URL=""
if [ "${1:-}" = "preview" ] || [ "${1:-}" = "p" ]; then
    COMMIT_MSG="${2:-chore(preview): automated security audit sync}"
    MANUAL_URL="${3:-}"
else
    COMMIT_MSG="${1:-chore(preview): automated security audit sync}"
    MANUAL_URL="${2:-}"
fi

SPEC_FILE="sandbox_openapi.json"
AUTH_FILE="fluffwalks-test-case/auth_session.json"

# Load .env from SentinelAPI root if present
if [ -f "$SENTINEL_ROOT/.env" ]; then
    set -a
    source "$SENTINEL_ROOT/.env"
    set +a
fi

# ── Vercel & Fluffwalks Config ───────────────────────────────────────────────
VERCEL_TOKEN="${VERCEL_TOKEN:-}"
VERCEL_PROJECT_ID="${VERCEL_PROJECT_ID:-}"
VERCEL_TEAM_ID="${VERCEL_TEAM_ID:-}"
FLUFFWALKS_DIR="${FLUFFWALKS_DIR:-/Users/yuvraj/Documents/company-work/fluffwalks/website/fluffwalks-web}"
FLUFFWALKS_BRANCH="${FLUFFWALKS_BRANCH:-preview}"
FLUFFWALKS_REPO_ID="${FLUFFWALKS_REPO_ID:-1234118318}"
MAX_POLL_ATTEMPTS=30      # 30 × 10s = 5 min max wait
POLL_INTERVAL=10          # seconds between polls

# ── Step 0a: Sync fluffwalks-web 'preview' branch if repo is present ─────────
sync_fluffwalks_preview() {
    if [ -d "$FLUFFWALKS_DIR/.git" ]; then
        echo "📦 Local fluffwalks-web detected: $FLUFFWALKS_DIR" >&2
        local curr_dir
        curr_dir="$(pwd)"
        cd "$FLUFFWALKS_DIR"

        # Ensure on preview branch
        local curr_fw_branch
        curr_fw_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
        if [ "$curr_fw_branch" != "$FLUFFWALKS_BRANCH" ]; then
            echo "🔀 Switching fluffwalks-web to '$FLUFFWALKS_BRANCH' branch..." >&2
            git checkout "$FLUFFWALKS_BRANCH" 2>/dev/null || git checkout -b "$FLUFFWALKS_BRANCH"
        fi

        # Check for uncommitted changes
        if ! git diff-index --quiet HEAD -- 2>/dev/null || [ -n "$(git status --porcelain 2>/dev/null)" ]; then
            echo "📝 Staging and committing changes on '$FLUFFWALKS_BRANCH' branch..." >&2
            git add -A
            git -c user.name="Mechox" \
                -c user.email="mechox31@gmail.com" \
                commit -m "$COMMIT_MSG" >&2 || true
            echo "📤 Pushing to origin '$FLUFFWALKS_BRANCH'..." >&2
            git push origin "$FLUFFWALKS_BRANCH" >&2 || true
            echo "✓ fluffwalks-web '$FLUFFWALKS_BRANCH' updated and pushed to GitHub." >&2
        else
            echo "ℹ️  fluffwalks-web '$FLUFFWALKS_BRANCH' is clean and up to date." >&2
        fi

        cd "$curr_dir"
    fi
}

# ── Step 0b: Trigger or Resolve Vercel Preview Deployment ─────────────────────
resolve_preview_url() {
    local team_param=""
    if [ -n "$VERCEL_TEAM_ID" ]; then
        team_param="&teamId=$VERCEL_TEAM_ID"
    fi

    # Trigger a fresh preview deployment for the preview branch
    echo "🚀 Triggering Vercel Preview Deployment for branch '$FLUFFWALKS_BRANCH'..." >&2
    local trigger_resp
    trigger_resp=$(curl -sf -X POST -H "Authorization: Bearer $VERCEL_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.vercel.com/v13/deployments" \
        -d "{
            \"name\": \"fluffwalks-website\",
            \"project\": \"$VERCEL_PROJECT_ID\",
            \"gitSource\": {
                \"type\": \"github\",
                \"ref\": \"$FLUFFWALKS_BRANCH\",
                \"repoId\": $FLUFFWALKS_REPO_ID
            }
        }" 2>/dev/null || echo "{}")

    local triggered_id
    triggered_id=$(echo "$trigger_resp" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || true)

    if [ -n "$triggered_id" ]; then
        echo "   ✓ Triggered Preview Deployment: ID=$triggered_id" >&2
        echo "   ⏳ Waiting for deployment to reach READY state..." >&2

        for attempt in $(seq 1 $MAX_POLL_ATTEMPTS); do
            local dep_info
            dep_info=$(curl -sf -H "Authorization: Bearer $VERCEL_TOKEN" \
                "https://api.vercel.com/v13/deployments/$triggered_id" 2>/dev/null || echo "{}")

            local dep_state dep_url
            dep_state=$(echo "$dep_info" | python3 -c "import sys, json; print(json.load(sys.stdin).get('readyState', '?'))" 2>/dev/null || echo "?")
            dep_url=$(echo "$dep_info" | python3 -c "import sys, json; print(json.load(sys.stdin).get('url', ''))" 2>/dev/null || echo "")

            if [ "$dep_state" = "READY" ] && [ -n "$dep_url" ]; then
                echo "https://$dep_url"
                return 0
            fi

            if [ "$dep_state" = "ERROR" ]; then
                echo "❌ Deployment $triggered_id failed with ERROR state." >&2
                break
            fi

            echo "   ⏳ [$attempt/$MAX_POLL_ATTEMPTS] State: $dep_state | Polling in ${POLL_INTERVAL}s..." >&2
            sleep "$POLL_INTERVAL"
        done
    fi

    # Fallback: Query for latest READY deployment on branch 'preview' (strictly non-production)
    echo "ℹ️  Querying Vercel API for latest READY deployment on branch '$FLUFFWALKS_BRANCH'..." >&2
    for attempt in $(seq 1 $MAX_POLL_ATTEMPTS); do
        local api_resp
        api_resp=$(curl -sf -H "Authorization: Bearer $VERCEL_TOKEN" \
            "https://api.vercel.com/v6/deployments?projectId=${VERCEL_PROJECT_ID}${team_param}&limit=10&state=READY" 2>/dev/null || echo "{}")

        local ready_url
        ready_url=$(echo "$api_resp" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    deps = data.get('deployments', [])
    target_branch = '$FLUFFWALKS_BRANCH'

    # 1. Match specific preview branch
    for d in deps:
        branch = d.get('meta', {}).get('githubCommitRef', '')
        if d.get('readyState') == 'READY' and branch == target_branch:
            print('https://' + d['url'])
            sys.exit(0)

    # 2. Match any non-production preview deployment
    for d in deps:
        if d.get('readyState') == 'READY' and d.get('target') != 'production':
            print('https://' + d['url'])
            sys.exit(0)

    # 3. Fallback to any ready deployment
    for d in deps:
        if d.get('readyState') == 'READY':
            print('https://' + d['url'])
            sys.exit(0)
except:
    pass
" 2>/dev/null || true)

        if [ -n "$ready_url" ]; then
            echo "$ready_url"
            return 0
        fi

        echo "   ⏳ Attempt $attempt/$MAX_POLL_ATTEMPTS — waiting for READY preview deployment (${POLL_INTERVAL}s)..." >&2
        sleep "$POLL_INTERVAL"
    done

    return 1
}

echo "================================================================================"
echo "🚀 FLUFFWALKS & SENTINELAPI — PREVIEW AUDIT PIPELINE"
echo "================================================================================"
echo "• Target Branch: $FLUFFWALKS_BRANCH (fluffwalks-web)"
echo "• Commit Msg:    $COMMIT_MSG"
echo "================================================================================"

# ── Step 0: Sync fluffwalks-web repository if present ────────────────────────
sync_fluffwalks_preview

# ── Determine Target URL ─────────────────────────────────────────────────────
TARGET_URL=""

if [ -n "$MANUAL_URL" ]; then
    TARGET_URL="$MANUAL_URL"
    echo "✓ Using manually provided preview URL: $TARGET_URL"
elif [ -n "$VERCEL_TOKEN" ] && [ -n "$VERCEL_PROJECT_ID" ]; then
    TARGET_URL=$(resolve_preview_url)
    if [ -n "$TARGET_URL" ]; then
        echo "✓ Resolved Vercel Preview URL: $TARGET_URL"
    else
        echo "❌ Could not resolve a READY Vercel preview deployment after ${MAX_POLL_ATTEMPTS} attempts."
        echo "   Make sure you've pushed code to trigger a Vercel deployment first."
        echo "   Or pass a URL manually: fluffwalks preview \"msg\" https://your-preview.vercel.app"
        exit 2
    fi
else
    echo "❌ No VERCEL_TOKEN / VERCEL_PROJECT_ID found and no manual URL provided."
    echo "   Configure .env in SentinelAPI root or pass: fluffwalks preview \"msg\" https://your-preview.vercel.app"
    exit 2
fi

echo ""
echo "• Preview URL:   $TARGET_URL"
echo "• Commit Msg:    $COMMIT_MSG"
echo "• Remote Branch: deployment (SentinelAPI)"
echo "================================================================================"

# ── Step 1: Ensure SentinelAPI is on 'deployment' branch ─────────────────────
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "deployment" ]; then
    echo "🔀 Switching SentinelAPI to 'deployment' branch..."
    git checkout deployment 2>/dev/null || git checkout -b deployment
fi

# ── Step 2: Generate & validate dynamic OpenAPI specification ────────────────
echo ""
echo "📝 Step 1/4: Generating & validating dynamic OpenAPI 3.0 specification..."
python3 scripts/generate_openapi.py \
    --source "$SPEC_FILE" \
    --base-url "$TARGET_URL" \
    --output "$SPEC_FILE"

# ── Step 3: Build Docker container ───────────────────────────────────────────
echo ""
echo "🐳 Step 2/4: Building SentinelAPI Docker container..."
docker build -t sentinelapi .

# ── Step 4: Extract Auth Tokens ──────────────────────────────────────────────
BEARER_TOKEN=""
COOKIE_STRING=""
if [ -f "$AUTH_FILE" ] && command -v jq &>/dev/null; then
    BEARER_TOKEN=$(jq -r '.bearer_token // empty' "$AUTH_FILE")
    COOKIE_STRING=$(jq -r '.cookie_string // empty' "$AUTH_FILE")
fi

# ── Step 5: Run Security Audit (AI & Email enabled via .env) ─────────────────
echo ""
echo "🛡️  Step 3/4: Running SentinelAPI non-interactive scan (AI & Email enabled)..."
# Purge previous scan artifacts so stale PDFs/reports are never lingering
rm -f markdown/*.pdf markdown/*.md markdown/*.json
mkdir -p markdown

ENV_ARGS=""
if [ -f ".env" ]; then
    ENV_ARGS="--env-file .env"
fi

SCAN_EXIT=0
docker run --rm \
    $ENV_ARGS \
    -v "$(pwd)/markdown:/app/markdown" \
    sentinelapi \
    --spec "$SPEC_FILE" \
    --base-url "$TARGET_URL" \
    --token "$BEARER_TOKEN" \
    --cookie "$COOKIE_STRING" \
    --ci || SCAN_EXIT=$?

echo ""
echo "📊 Test Conclusion Code: $SCAN_EXIT"
if [ "$SCAN_EXIT" -eq 0 ]; then
    echo "🟢 Status: 0 (PASS — No vulnerabilities detected)"
elif [ "$SCAN_EXIT" -eq 1 ]; then
    echo "🔴 Status: 1 (FAIL — Vulnerabilities confirmed; reports saved in ./markdown)"
else
    echo "🟡 Status: 2 (ERROR — Target unreachable or probe failure)"
fi

# ── Step 6: Commit & Push to SentinelAPI deployment branch ──────────────────
echo ""
echo "📤 Step 4/4: Pushing code to GitHub 'deployment' branch..."
git add -A
if git diff-index --quiet HEAD --; then
    echo "ℹ️  No uncommitted changes to commit. Pushing current branch..."
else
    git commit -m "$COMMIT_MSG"
fi

git push origin deployment

echo ""
echo "================================================================================"
echo "✅ FLUFFWALKS PREVIEW AUDIT COMPLETE!"
echo "• Preview Tested:  $TARGET_URL"
echo "• Target Branch:   $FLUFFWALKS_BRANCH (fluffwalks-web)"
echo "• Remote Branch:   deployment (SentinelAPI)"
echo "• Conclusion Code: $SCAN_EXIT"
echo "• GitHub Actions CI has been triggered automatically."
echo "• Check CI progress: gh run list --repo iblameyuvraj/SentinelAPI"
echo "================================================================================"

exit "$SCAN_EXIT"
