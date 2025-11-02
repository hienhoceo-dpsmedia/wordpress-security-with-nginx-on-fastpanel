#!/bin/bash

# GitHub Topics Setter for WordPress Security Repository
# This script helps add relevant topics to your GitHub repository
# Usage: ./set-topics.sh [your-github-token]

set -euo pipefail

# Repository information
REPO_OWNER="hienhoceo-dpsmedia"
REPO_NAME="wordpress-security-with-nginx-on-fastpanel"

# Topics to add (max 20 per GitHub limits)
TOPICS=(
    "wordpress-security"
    "nginx"
    "fastpanel"
    "web-security"
    "wordpress"
    "security-hardening"
    "server-security"
    "php-security"
    "web-server"
    "nginx-configuration"
    "wordpress-protection"
    "cybersecurity"
    "security-tools"
    "web-hardening"
    "server-hardening"
    "penetration-testing"
    "security-audit"
    "wordpress-hardening"
    "nginx-security"
    "hosting-security"
)

# Convert array to comma-separated string
TOPICS_STRING=$(IFS=','; echo "${TOPICS[*]}")

echo "🏷️  Setting GitHub topics for $REPO_OWNER/$REPO_NAME"
echo "Topics: $TOPICS_STRING"
echo

# Check if token is provided
if [[ $# -eq 0 ]]; then
    echo "❌ Error: GitHub token required"
    echo
    echo "Usage: $0 <your-github-token>"
    echo
    echo "To get a token:"
    echo "1. Go to https://github.com/settings/tokens"
    echo "2. Click 'Generate new token'"
    echo "3. Select 'public_repo' scope"
    echo "4. Copy the token and run this script with it"
    echo
    echo "Or add topics manually in GitHub Settings → Topics"
    exit 1
fi

TOKEN="$1"

# API call to set topics
echo "🔄 Setting topics via GitHub API..."
response=$(curl -s -X PUT \
    -H "Authorization: token $TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/topics" \
    -d "{\"names\":[$TOPICS_STRING]}")

# Check response
if echo "$response" | grep -q '"names"'; then
    echo "✅ Topics set successfully!"
    echo
    echo "📋 Applied topics:"
    echo "$response" | grep -o '"names":\[[^]]*\]' | sed 's/"names":\[/  /' | sed 's/","/\n  /g' | sed 's/"//g' | sed 's/\]$//' | head -20
else
    echo "❌ Failed to set topics"
    echo "Response: $response"
    exit 1
fi

echo
echo "🎉 Repository decoration complete!"
echo "📈 Your repository should now be more discoverable!"