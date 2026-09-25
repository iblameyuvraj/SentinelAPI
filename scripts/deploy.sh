#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI — All-in-One Deployment & Audit Runner (Vercel API Only)
#
# Flow:
#   1. Push code to GitHub main branch (triggers Vercel auto-deploy)
#   2. Poll Vercel REST API for latest READY preview deployment URL
#   3. Generate & validate dynamic OpenAPI specification with live URL
#   4. Build SentinelAPI Docker container
#   5. Run non-interactive master scan against the preview URL
#   6. Commit & push to 'deployment' branch
#
# Usage:
#   ./scripts/deploy.sh                          # auto-detect latest preview
#   ./scripts/deploy.sh "commit msg"             # custom commit message
#   ./scripts/deploy.sh "commit msg" https://... # override URL manually
#
# Required env vars (in .env or exported):
#   VERCEL_TOKEN        — Vercel API bearer token
#   VERCEL_PROJECT_ID   — Vercel project ID for fluffwalks-web
# Optional:
#   VERCEL_TEAM_ID      — Vercel team/org ID (skipped if not set)
# ==============================================================================
set -euo pipefail

COMMIT_MSG="${1:-deploy: automated test build and push to deployment branch}"
MANUAL_URL="${2:-}"
SPEC_FILE="sandbox_openapi.json"
AUTH_FILE="fluffwalks-test-case/auth_session.json"

# Load .env if present
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# ── Vercel API Config ────────────────────────────────────────────────────────
VERCEL_TOKEN="${VERCEL_TOKEN:-}"
VERCEL_PROJECT_ID="${VERCEL_PROJECT_ID:-}"
VERCEL_TEAM_ID="${VERCEL_TEAM_ID:-}"
MAX_POLL_ATTEMPTS=30      # 30 × 10s = 5 min max wait
POLL_INTERVAL=10          # seconds between polls

# ── Resolve Preview URL ─────────────────────────────────────────────────────
resolve_preview_url() {
    local team_param=""
    if [ -n "$VERCEL_TEAM_ID" ]; then
        team_param="&teamId=$VERCEL_TEAM_ID"
    fi

    echo "ℹ️  Querying Vercel API for latest preview deployment..."
    echo "   Project: $VERCEL_PROJECT_ID"

    for attempt in $(seq 1 $MAX_POLL_ATTEMPTS); do
        local api_resp
        api_resp=$(curl -sf -H "Authorization: Bearer $VERCEL_TOKEN" \
            "https://api.vercel.com/v6/deployments?projectId=${VERCEL_PROJECT_ID}${team_param}&limit=5&state=READY" 2>/dev/null || echo "{}")

        local ready_url
        ready_url=$(echo "$api_resp" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    deps = data.get('deployments', [])
    for d in deps:
        if d.get('readyState') == 'READY' and d.get('meta', {}).get('githubDeployment') != '1':
            print('https://' + d['url'])
            break
    else:
        # fallback: any READY deployment
        if deps:
            print('https://' + deps[0]['url'])
except:
    pass
" 2>/dev/null || true)

        if [ -n "$ready_url" ]; then
            echo "$ready_url"
            return 0
        fi

        echo "   ⏳ Attempt $attempt/$MAX_POLL_ATTEMPTS — no READY deployment yet, waiting ${POLL_INTERVAL}s..."
        sleep "$POLL_INTERVAL"
    done

    echo ""
    return 1
}

echo "================================================================================"
echo "🚀 SENTINELAPI — ONE-COMMAND DEPLOYMENT PIPELINE (Vercel API Mode)"
echo "================================================================================"

# ── Step 0: Determine Target URL ─────────────────────────────────────────────
TARGET_URL=""

if [ -n "$MANUAL_URL" ]; then
    TARGET_URL="$MANUAL_URL"
    echo "✓ Using manually provided URL: $TARGET_URL"
elif [ -n "$VERCEL_TOKEN" ] && [ -n "$VERCEL_PROJECT_ID" ]; then
    TARGET_URL=$(resolve_preview_url)
    if [ -n "$TARGET_URL" ]; then
        echo "✓ Resolved Vercel Preview URL via API: $TARGET_URL"
    else
        echo "❌ Could not resolve a READY Vercel preview deployment after ${MAX_POLL_ATTEMPTS} attempts."
        echo "   Make sure you've pushed code to trigger a Vercel deployment first."
        echo "   Or pass a URL manually: ./scripts/deploy.sh \"msg\" https://your-preview.vercel.app"
        exit 2
    fi
else
    echo "❌ No VERCEL_TOKEN / VERCEL_PROJECT_ID found and no manual URL provided."
    echo "   Set them in .env or pass a URL: ./scripts/deploy.sh \"msg\" https://your-preview.vercel.app"
    exit 2
fi

echo ""
echo "• Target URL:    $TARGET_URL"
echo "• Commit Msg:    $COMMIT_MSG"
echo "• Branch:        deployment"
echo "================================================================================"

# ── Step 1: Ensure on 'deployment' branch ────────────────────────────────────
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "deployment" ]; then
    echo "🔀 Switching to 'deployment' branch..."
    git checkout deployment 2>/dev/null || git checkout -b deployment
fi

# ── Step 2: Generate & validate dynamic OpenAPI specification ────────────────
echo ""
echo "📝 Step 1/4: Generating & validating OpenAPI 3.0 specification..."
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
echo "📊 Local Test Conclusion Code: $SCAN_EXIT"
if [ "$SCAN_EXIT" -eq 0 ]; then
    echo "🟢 Status: 0 (PASS — No vulnerabilities detected)"
elif [ "$SCAN_EXIT" -eq 1 ]; then
    echo "🔴 Status: 1 (FAIL — Vulnerabilities confirmed; reports saved in ./markdown)"
else
    echo "🟡 Status: 2 (ERROR — Target unreachable or probe failure)"
fi

# ── Step 6: Commit & Push to deployment branch ──────────────────────────────
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
echo "✅ DEPLOYMENT & PUSH COMPLETE!"
echo "• Preview Tested:  $TARGET_URL"
echo "• Remote Branch:   deployment"
echo "• Conclusion Code: $SCAN_EXIT"
echo "• GitHub Actions CI has been triggered automatically."
echo "• Check CI progress: gh run list --repo iblameyuvraj/SentinelAPI"
echo "================================================================================"
