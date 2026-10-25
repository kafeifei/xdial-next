#!/usr/bin/env bash
# 配置 GitHub 仓库：合并方式、标签、main 的分支保护和审核环境。可以重复执行。
# 需要仓库管理员的 gh 登录。规则见 docs/agent/loop.md 的"仓库设置"。
# 审核用的订阅 token 不在这里设置，由用户自己执行：
#   gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo kafeifei/xdial-next --env review

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

export REPO="${REPO:-kafeifei/xdial-next}"

# 只用合并提交，和旧仓库一致，以后要并回去时历史完整。
gh api -X PATCH "repos/$REPO" \
  -F allow_auto_merge=true -F allow_merge_commit=true -F allow_squash_merge=false \
  -F allow_rebase_merge=false -F delete_branch_on_merge=true -F has_wiki=false > /dev/null

bash scripts/ensure-labels.sh

gh api -X PUT "repos/$REPO/branches/main/protection" --input - > /dev/null << 'EOF'
{
  "required_status_checks": {"strict": true, "contexts": ["go", "risk-gate", "ai-review", "security-review"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

# 订阅 token 放在 review 环境里，只有 main 上的运行能用；PR 自己的工作流读不到。
# 用明确的分支规则，不依赖分支保护是否已经建好。
gh api -X PUT "repos/$REPO/environments/review" --input - > /dev/null << 'EOF'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
EOF
# 收敛到只有 branch:main 一条规则：多余的删掉，缺的补上。
policies="$(gh api --paginate "repos/$REPO/environments/review/deployment-branch-policies" \
  --jq '.branch_policies[] | "\(.id) \(.type) \(.name)"')"
has_main=false
while read -r id type name; do
  [[ -z "$id" ]] && continue
  if [[ "$type" == branch && "$name" == main ]]; then
    has_main=true
  else
    gh api -X DELETE "repos/$REPO/environments/review/deployment-branch-policies/$id" > /dev/null
  fi
done <<< "$policies"
if [[ "$has_main" != true ]]; then
  gh api -X POST "repos/$REPO/environments/review/deployment-branch-policies" -f name=main -f type=branch > /dev/null
fi

echo "repository configured: $REPO"
