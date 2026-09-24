#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI — All-in-One Deployment & Audit Runner
# 1. Generates & validates dynamic OpenAPI specification
# 2. Builds the SentinelAPI production Docker container
# 3. Executes non-interactive master scan against preview target
# 4. Stages, commits, and pushes code to 'deployment' branch on GitHub
# ==============================================================================
set -euo pipefail

COMMIT_MSG="${1:-deploy: automated test build and push to deployment branch}"
TARGET_URL="${2:-https://fluffwalks-website.vercel.app}"
SPEC_FILE="sandbox_openapi.json"
AUTH_FILE="fluffwalks-test-case/auth_session.json"

echo "================================================================================"
echo "🚀 SENTINELAPI — ONE-COMMAND DEPLOYMENT PIPELINE"
echo "================================================================================"
echo "• Target URL:    $TARGET_URL"
echo "• Commit Msg:    $COMMIT_MSG"
echo "• Branch:        deployment"
echo "================================================================================"

# 1. Ensure on 'deployment' branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "deployment" ]; then
    echo "🔀 Switching to 'deployment' branch..."
    git checkout deployment 2>/dev/null || git checkout -b deployment
fi

# 2. Generate and validate dynamic OpenAPI specification
echo ""
echo "📝 Step 1/4: Generating & validating OpenAPI 3.0 specification..."
python3 scripts/generate_openapi.py \
    --source "$SPEC_FILE" \
    --base-url "$TARGET_URL" \
    --output "$SPEC_FILE"

# 3. Build Docker container
echo ""
echo "🐳 Step 2/4: Building SentinelAPI Docker container..."
docker build -t sentinelapi .

# 4. Extract Auth Tokens if available
BEARER_TOKEN=""
COOKIE_STRING=""
if [ -f "$AUTH_FILE" ] && command -v jq &>/dev/null; then
    BEARER_TOKEN=$(jq -r '.bearer_token // empty' "$AUTH_FILE")
    COOKIE_STRING=$(jq -r '.cookie_string // empty' "$AUTH_FILE")
fi

# 5. Run Security Audit against Endpoints
echo ""
echo "🛡️  Step 3/4: Testing endpoints with SentinelAPI non-interactive scan..."
mkdir -p markdown

SCAN_EXIT=0
docker run --rm \
    -v "$(pwd)/markdown:/app/markdown" \
    sentinelapi \
    --spec "$SPEC_FILE" \
    --base-url "$TARGET_URL" \
    --token "$BEARER_TOKEN" \
    --cookie "$COOKIE_STRING" \
    --ci \
    --no-ai \
    --no-email || SCAN_EXIT=$?


echo ""
echo "📊 Local Test Conclusion Code: $SCAN_EXIT"
if [ "$SCAN_EXIT" -eq 0 ]; then
    echo "🟢 Status: 0 (PASS - No vulnerabilities detected)"
elif [ "$SCAN_EXIT" -eq 1 ]; then
    echo "🔴 Status: 1 (FAIL - Vulnerabilities confirmed; reports saved in ./markdown)"
else
    echo "🟡 Status: 2 (ERROR - Target unreachable or probe failure)"
fi

# 6. Commit & Push to deployment branch
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
echo "• Remote Branch: deployment"
echo "• GitHub Actions CI has been triggered automatically."
echo "• Check CI progress: gh run list --repo iblameyuvraj/SentinelAPI"
echo "================================================================================"
