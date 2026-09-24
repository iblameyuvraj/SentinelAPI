#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI — Automated Preview Deployment Security Audit Runner
# Deploys preview to Vercel (or fallback local preview), extracts preview URL,
# generates/enriches OpenAPI spec for N endpoints dynamically, and executes
# SentinelAPI non-interactive master scan with strict exit code conclusions (0, 1, 2).
# ==============================================================================
set -euo pipefail

SPEC_FILE="${1:-sandbox_openapi.json}"
AUTH_JSON="${2:-fluffwalks-test-case/auth_session.json}"

echo "================================================================================"
echo "🛡️  SENTINELAPI — PREVIEW AUDIT & OPENAPI GENERATION PIPELINE"
echo "================================================================================"

# 1. Trigger Vercel Preview Deployment & Extract URL
PREVIEW_URL="${OVERRIDE_PREVIEW_URL:-}"

if [ -z "$PREVIEW_URL" ]; then
    if command -v vercel &>/dev/null; then
        echo "📦 Creating Vercel Preview Deployment..."
        VERCEL_DEPLOY_ARGS="--yes"
        if [ -n "${VERCEL_TOKEN:-}" ]; then
            VERCEL_DEPLOY_ARGS="$VERCEL_DEPLOY_ARGS --token=$VERCEL_TOKEN"
        fi

        DEPLOY_OUTPUT=$(vercel deploy $VERCEL_DEPLOY_ARGS 2>&1 || true)
        PREVIEW_URL=$(echo "$DEPLOY_OUTPUT" | grep -o 'https://[^ ]*\.vercel\.app' | tail -n 1 || true)

        if [ -z "$PREVIEW_URL" ]; then
            PREVIEW_URL=$(echo "$DEPLOY_OUTPUT" | tail -n 1 | tr -d '[:space:]')
        fi
    fi
fi

# Fallback if no Vercel deployment or URL is empty
if [ -z "$PREVIEW_URL" ] || [[ ! "$PREVIEW_URL" =~ ^https?:// ]]; then
    PREVIEW_URL="http://localhost:3000"
    echo "⚠️  No remote Vercel preview detected; defaulting to local preview: $PREVIEW_URL"
else
    echo "✓ Live Preview URL established: $PREVIEW_URL"
fi

# 2. Dynamically Generate & Validate OpenAPI Specification for the Target
echo ""
echo "📝 Generating and validating dynamic OpenAPI specification..."
if [ -f "scripts/generate_openapi.py" ]; then
    python3 scripts/generate_openapi.py \
        --source "$SPEC_FILE" \
        --base-url "$PREVIEW_URL" \
        --output "$SPEC_FILE"
fi

# 3. Extract Authentication Credentials if auth_session.json exists
BEARER_TOKEN=""
COOKIE_STRING=""
if [ -f "$AUTH_JSON" ] && command -v jq &>/dev/null; then
    echo "🔑 Loading auth credentials from $AUTH_JSON..."
    BEARER_TOKEN=$(jq -r '.bearer_token // empty' "$AUTH_JSON")
    COOKIE_STRING=$(jq -r '.cookie_string // empty' "$AUTH_JSON")
fi

# 4. Ensure Output Directory Exists
mkdir -p markdown

echo ""
echo "🚀 Launching SentinelAPI Non-Interactive Master Scan against Preview..."
echo "Target Base URL: $PREVIEW_URL"
echo "Specification:   $SPEC_FILE"
echo ""

# 5. Execute SentinelAPI (Docker or Local Python)
SCAN_EXIT_CODE=0

if command -v docker &>/dev/null && docker info &>/dev/null; then
    echo "🐳 Executing scan in Docker container..."
    docker run --rm \
        -v "$(pwd)/markdown:/app/markdown" \
        sentinelapi \
        --spec "$SPEC_FILE" \
        --base-url "$PREVIEW_URL" \
        --token "$BEARER_TOKEN" \
        --cookie "$COOKIE_STRING" \
        --ci \
        --no-ai \
        --no-email || SCAN_EXIT_CODE=$?
else
    echo "🐍 Executing scan via local python environment..."
    python3 -m sentinelapi.main \
        --spec "$SPEC_FILE" \
        --base-url "$PREVIEW_URL" \
        --token "$BEARER_TOKEN" \
        --cookie "$COOKIE_STRING" \
        --ci \
        --no-ai \
        --no-email || SCAN_EXIT_CODE=$?
fi

echo ""
echo "================================================================================"
echo "📊 AUDIT CONCLUSION"
echo "================================================================================"

case "$SCAN_EXIT_CODE" in
    0)
        echo "🟢 [CONCLUSION 0: PASS]"
        echo "All security probes passed cleanly! Zero critical/high vulnerabilities confirmed."
        echo "PR / Preview Deployment is APPROVED for merge."
        ;;
    1)
        echo "🔴 [CONCLUSION 1: FAIL / VULNERABILITIES CONFIRMED]"
        echo "Security vulnerabilities were detected (BOLA, Exposure, Auth, BFLA, etc.)."
        echo "Check generated PDF reports in ./markdown/ for detailed reproduction curl commands."
        echo "PR / Preview Deployment is BLOCKED."
        ;;
    2)
        echo "🟡 [CONCLUSION 2: ERROR / UNREACHABLE]"
        echo "Execution failed or the Preview host was unreachable / zero probes succeeded."
        echo "Verify that the preview URL is live, CORS is configured, and route paths exist."
        ;;
    *)
        echo "⚠️  [CONCLUSION $SCAN_EXIT_CODE: UNKNOWN ERROR]"
        SCAN_EXIT_CODE=2
        ;;
esac

echo "================================================================================"
echo "Exit Code: $SCAN_EXIT_CODE"
exit "$SCAN_EXIT_CODE"
