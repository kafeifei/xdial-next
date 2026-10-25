#!/usr/bin/env bash
# 建好项目循环用到的标签；已存在的只更新颜色和说明。见 docs/agent/loop.md。
# 输入环境变量：GH_TOKEN REPO

set -euo pipefail

while IFS='|' read -r name color description; do
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" --force > /dev/null
done << 'EOF'
risk:low|0e8a16|低风险：关卡全过后自动合并
risk:medium|fbca04|中风险：等仓库所有者加 owner-approved
risk:high|d93f0b|高风险：等仓库所有者加 owner-approved，另需换模型复审和 e2e 证据
owner-approved|1d76db|仓库所有者批准合并；只对批准时的代码有效；agent 不得添加
needs-rethink|b60205|审了 3 轮仍未通过：停下复盘，由用户决定
allow-more-rounds|5319e7|仓库所有者允许继续审核；agent 不得添加
re-review|c5def5|代码没变，请审核复核作者对意见的回复；审完自动去掉
EOF
