#!/usr/bin/env bash
# update-linked-issues.sh
#
# Called by the "update-pr-status" job in project-board.yml.
# For every issue that a PR closes (via "Closes #N" keywords), this script:
#   1. Determines the target project-board status from the PR's draft state.
#   2. Fetches the linked (closing) issues using GitHub's GraphQL API.
#   3. Looks up the project board's "Status" field and the desired option ID.
#   4. Moves each linked issue to that status on the board.
#   5. Assigns the PR author to the linked issue.
#
# Required environment variables (set by the workflow):
#   GH_TOKEN        – GitHub PAT with project write permissions
#   PR_NODE_ID      – GraphQL node ID of the pull request
#   PR_DRAFT        – "true" if the PR is a draft, "false" otherwise
#   PR_AUTHOR       – GitHub login of the PR author
#   REPO_OWNER      – Repository owner (org or user)
#   REPO_NAME       – Repository name
#   PROJECT_ORG     – GitHub organisation that owns the project board
#   PROJECT_NUMBER  – Project board number (e.g. "179")

set -euo pipefail

# -------------------------------------------------------------------
# Step 1: Determine target status based on the PR's draft state
#   - Draft PRs   → "On hold"   (work is not ready for review)
#   - Ready PRs   → "In review" (work is ready for review)
# -------------------------------------------------------------------
if [ "$PR_DRAFT" = "true" ]; then
  TARGET_STATUS="On hold"
else
  TARGET_STATUS="In review"
fi
echo "PR is draft=$PR_DRAFT → target status: '$TARGET_STATUS'"

# -------------------------------------------------------------------
# Step 2: Fetch linked issues via GitHub's closingIssuesReferences API
#   This leverages GitHub's built-in keyword parser (e.g. "Closes #42")
#   so we don't need any custom regex matching.
# -------------------------------------------------------------------
echo "Querying closing issue references for PR ..."

LINKED_ISSUES=$(gh api graphql -f query='
  query($prId: ID!) {
    node(id: $prId) {
      ... on PullRequest {
        closingIssuesReferences(first: 20) {
          nodes {
            id
            number
          }
        }
      }
    }
  }
' -f prId="$PR_NODE_ID" \
  --jq '.data.node.closingIssuesReferences.nodes[]' 2>/dev/null || true)

# Exit early if the PR has no closing keywords pointing to issues
if [ -z "$LINKED_ISSUES" ]; then
  echo "No closing issue references found — nothing to do."
  exit 0
fi

# Split the JSON objects into parallel arrays of node IDs and issue numbers
ISSUE_NODE_IDS=$(echo "$LINKED_ISSUES" | jq -r '.id')
ISSUE_NUMBERS=$(echo "$LINKED_ISSUES" | jq -r '.number')

echo "Linked issues found: $(echo "$ISSUE_NUMBERS" | tr '\n' ' ')"

# -------------------------------------------------------------------
# Step 3: Fetch project board metadata via GraphQL
#   We need three pieces of information:
#     - The project's node ID
#     - The "Status" single-select field ID
#     - The option ID that matches our target status name
# -------------------------------------------------------------------
echo "Querying project board: $PROJECT_ORG/projects/$PROJECT_NUMBER ..."

PROJECT_DATA=$(gh api graphql -f query='
  query($org: String!, $number: Int!) {
    organization(login: $org) {
      projectV2(number: $number) {
        id
        field(name: "Status") {
          ... on ProjectV2SingleSelectField {
            id
            options {
              id
              name
            }
          }
        }
      }
    }
  }
' -f org="$PROJECT_ORG" -F number="$PROJECT_NUMBER")

PROJECT_ID=$(echo "$PROJECT_DATA" | jq -r '.data.organization.projectV2.id')
STATUS_FIELD_ID=$(echo "$PROJECT_DATA" | jq -r '.data.organization.projectV2.field.id')
TARGET_OPTION_ID=$(echo "$PROJECT_DATA" | jq -r --arg name "$TARGET_STATUS" \
  '.data.organization.projectV2.field.options[] | select(.name == $name) | .id')

# Validate that we successfully resolved all three IDs
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "null" ]; then
  echo "::error::Could not find project board $PROJECT_ORG/projects/$PROJECT_NUMBER."
  exit 1
fi

if [ -z "$STATUS_FIELD_ID" ] || [ "$STATUS_FIELD_ID" = "null" ]; then
  echo "::error::Could not find a 'Status' single-select field on the project board."
  exit 1
fi

if [ -z "$TARGET_OPTION_ID" ] || [ "$TARGET_OPTION_ID" = "null" ]; then
  echo "::error::The 'Status' field has no '$TARGET_STATUS' option. Available options:"
  echo "$PROJECT_DATA" | jq -r '.data.organization.projectV2.field.options[].name'
  exit 1
fi

echo "Project board resolved (project=$PROJECT_ID, statusField=$STATUS_FIELD_ID, targetOption=$TARGET_OPTION_ID)"

# -------------------------------------------------------------------
# Step 4: Iterate over each linked issue and update its board status
#   For each issue we:
#     a) Look up its item ID on the project board
#     b) Set the "Status" field to the target value
#     c) Assign the PR author to the issue (idempotent)
# -------------------------------------------------------------------
UPDATED=0
SKIPPED=0

# Read node IDs and issue numbers in lockstep (tab-separated).
# Use process substitution (< <(...)) instead of a pipeline to avoid running
# the loop in a subshell, which would prevent UPDATED/SKIPPED from propagating.
while IFS=$'\t' read -r ISSUE_NODE_ID ISSUE_NUMBER; do
  echo ""
  echo "--- Issue #$ISSUE_NUMBER ---"

  # 4a. Check whether the issue exists on the project board
  echo "  Checking if issue is on the project board ..."
  ITEM_ID=$(gh api graphql -f query='
    query($itemId: ID!) {
      node(id: $itemId) {
        ... on Issue {
          projectItems(first: 100) {
            nodes {
              id
              project {
                id
              }
            }
          }
        }
      }
    }
  ' -f itemId="$ISSUE_NODE_ID" \
    --jq ".data.node.projectItems.nodes[] | select(.project.id == \"$PROJECT_ID\") | .id" 2>/dev/null || true)

  if [ -z "$ITEM_ID" ] || [ "$ITEM_ID" = "null" ]; then
    echo "::warning::Issue #$ISSUE_NUMBER exists but is not on the project board. Skipping."
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  # 4b. Update the item's "Status" field on the project board
  echo "  Setting status to '$TARGET_STATUS' ..."
  gh api graphql -f query='
    mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
      updateProjectV2ItemFieldValue(input: {
        projectId: $projectId
        itemId: $itemId
        fieldId: $fieldId
        value: { singleSelectOptionId: $optionId }
      }) {
        projectV2Item {
          id
        }
      }
    }
  ' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$STATUS_FIELD_ID" -f optionId="$TARGET_OPTION_ID"

  # 4c. Assign the PR author to the issue (no-op if already assigned)
  echo "  Assigning $PR_AUTHOR to issue #$ISSUE_NUMBER ..."
  gh issue edit "$ISSUE_NUMBER" --add-assignee "$PR_AUTHOR" -R "$REPO_OWNER/$REPO_NAME" 2>/dev/null || \
    echo "::warning::Could not assign $PR_AUTHOR to issue #$ISSUE_NUMBER."

  echo "  Issue #$ISSUE_NUMBER moved to '$TARGET_STATUS' and assigned to $PR_AUTHOR."
  UPDATED=$((UPDATED + 1))
done < <(paste <(echo "$ISSUE_NODE_IDS") <(echo "$ISSUE_NUMBERS"))

# -------------------------------------------------------------------
# Step 5: Print a summary of what was done
# -------------------------------------------------------------------
echo ""
echo "Done. Target status: '$TARGET_STATUS'. Updated: $UPDATED, Skipped: $SKIPPED."
