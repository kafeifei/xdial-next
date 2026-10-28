# 项目循环

依据 [方案 §5](../plan.md#5-项目循环)，这里是可执行的规则。改这个文件属于高风险。

## 威胁模型

关卡防的是 agent 的失误，不防恶意 agent。agent 用的是用户的 GitHub 身份，用户能做的事它都能做：加标签、写状态、改工作流。规则靠 AGENTS.md 约束，关卡负责把常见的失误挡在合并之前。

- 批准类标签只认仓库所有者本人加的，机器人加的不算；但 agent 以所有者身份加的，分辨不出来。
- 以后给 agent 换成独立的 GitHub App 身份，再用 GitHub 原生的审批，并把必需状态钉到可信的来源上。
- 外部 fork 的 PR 不做 AI 审核，也不会自动合并，由用户决定怎么处理。

## 关卡

| 阶段 | 关卡 | 实现 | 结论写在哪 |
|---|---|---|---|
| 提 PR 前 | 自己验证 | `make check`；改动涉及运行时行为的，再跑 `make e2e` | PR 证据 |
| 提 PR 前 | 换个新上下文审 | 全新的 agent 只看 issue 目标和 diff；高风险改动换一个模型 | PR 证据 |
| PR 中 | CI | `ci.yml` 的 `go` 任务（`pull_request`） | 检查 `go` |
| PR 中 | 风险定档与批准 | `risk.yml` + [risk-gate.sh](../../scripts/risk-gate.sh) | 状态 `risk-gate` |
| PR 中 | AI 审核 | `review.yml` + claude-code-action | 状态 `ai-review` |
| PR 中 | 安全审核 | 同上，只在高风险档真正审 | 状态 `security-review` |
| 合并时 | 与 main 同步 | 分支保护要求分支与 main 同步 | — |

`risk.yml` 和 `review.yml` 用 `pull_request_target`，只处理指向 main 的 PR：

- 工作流、程序、提示词和审核规则都取自 main，PR 改不了自己的档和审核。
- PR 的代码只当数据读，不执行其中的任何东西。
- 结论写成 PR head 提交上的状态。推了新提交，旧结论就不作数。
- 事件到达时如果 PR 已经有了更新的 head，这次事件直接跳过，交给后面的事件处理。

`ci.yml` 跑的是 PR 自己的代码和工作流，所以改了工作流的 PR，`go` 的绿灯不能当证据，要看工作流的 diff。这类 PR 都是高风险，需要用户批准。

## 仓库设置

由 [scripts/setup-repo.sh](../../scripts/setup-repo.sh) 配置，可以重复执行：

- **合并方式**：只用合并提交；允许自动合并；合并后删除分支。
- **main 的分支保护**：
  - 必须经 PR 合入；
  - `go`、`risk-gate`、`ai-review`、`security-review` 四项必须通过；
  - 分支必须与 main 同步；
  - 所有对话解决后才能合并；
  - 管理员也不例外；
  - 禁止强推和删除。
- **标签**：`risk:low`、`risk:medium`、`risk:high`、`owner-approved`、`needs-rethink`、`allow-more-rounds`、`re-review`。`risk.yml` 每次运行也会补建。
- **`review` 环境**：审核用的订阅 token 放在这里，部署分支规则明确只允许 main，PR 自己的工作流读不到。由用户执行 `claude setup-token` 生成 token，把它完整复制下来，再执行：

  ```sh
  T=$(pbpaste | tr -d '[:space:]'); echo "读到 ${#T} 个字符"; [ -n "$T" ] && CLAUDE_CODE_OAUTH_TOKEN="$T" claude -p "回复 ok" && printf '%s' "$T" | gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo kafeifei/xdial-next --env review; unset T; pbcopy < /dev/null
  ```

  - `claude setup-token` 打印的 token 会折成两行。用 `read` 或 `gh secret set` 的输入提示粘贴，都只会读到第一行，所以这里从剪贴板读，再去掉空白。
  - 先用这个 token 让 Claude 回复一次，通过了才写进 GitHub。
  - 没有 token 时，审核直接失败，不会跳过。

紧急情况下要绕开关卡，只能由用户临时关掉分支保护里的"管理员也不例外"，合并后再打开。

## 风险档

由 [tools/risktier](../../tools/risktier) 按 [.github/risk-tiers.json](../../.github/risk-tiers.json) 计算。路径来自 files API，包括重命名前的旧路径；匹配不区分大小写。

- 任一路径命中 high，就是高风险；
- 其余路径全部命中 low，才是低风险；全部命中 low 或 medium、而且有 medium，才是中风险；
- 其余都是高风险（default）。

low 和 medium 都是白名单：没列出来的路径落到高风险，等所有者批准。中风险关卡全过就自动合并、不经人审，所以它只能是"漏列即从严"，不能是"漏列即放行"。

| 档 | 当前范围 | 怎么合并 |
|---|---|---|
| 低 | 文档（`docs/agent` 和 `docs/plan.md` 除外）、README、测试文件、testdata | 关卡全过后自动合并 |
| 中 | `medium` 白名单，目前是空的；以后放菜单栏 App 的界面目录这类确定无害的路径 | 关卡全过后自动合并（2026-10-28 用户决定，原为用户批准） |
| 高 | 白名单之外的一切，包括产品代码 `cmd/`、`internal/`（含其中的测试）、`e2e/`（脚本会在 mbp64k 上运行）、`ARCHITECTURE.md`、工作流与 `.github` 下的配置、脚本、`tools/`、各种 agent 指令文件、go.mod、Makefile、lint 配置 | 用户批准后自动合并；另需不同模型的复审和 e2e 证据 |

`high` 列表仍然保留：其中 `docs/agent`、`docs/plan.md` 这类路径同时命中 low，要靠 high 优先把它们留在高风险。往 `medium` 或 `low` 白名单里加路径属于高风险改动。

## 什么算"作者有改动"

批准和审核轮数都要回答同一个问题：自某个提交以来，作者有没有改代码？由 [changes-since.sh](../../scripts/changes-since.sh) 按树来判断：

- 把那个提交和 head 所含的 main 自动合并一次，结果和 head 的树完全相同，才算"只同步了 main"。
- 合并 main 时手工改了东西、解了冲突，或者用 `-s ours` 之类丢掉了 main 的改动，都算作者有改动。
- 那个提交已经不是 head 的祖先（比如强推过）时，算"说不清"，按有改动处理。
- 作者的改动就是"自动合并结果到 head"的 diff，第 3 轮起的增量审核看的就是它。

## 批准

高风险的 PR，由仓库所有者加 `owner-approved` 标签来批准：

- 所有者也可以给中风险的 PR 加这个标签，但它不影响是否合并：中风险不加也会合并。

- 加标签的那一刻，风险工作流在 PR 上记下当时的提交和风险档（"批准记录"评论）。
- 之后每次运行都核对，不看是什么事件触发的：作者有改动、风险档升高，或者标签最近一次不是所有者本人加的，就撤掉标签，高风险 PR 的 `risk-gate` 回到等待。只同步 main 不撤销。
- 批准有效时，`risk-gate` 通过并开启自动合并，其余关卡一过就合并。
- 高风险 PR 没有有效批准时，`risk-gate` 停在等待，自动合并保持关闭；关不掉时 `risk-gate` 失败。

agent 不加 `owner-approved` 和 `allow-more-rounds`，不开自动合并，也不直接合并高风险的 PR。

## AI 审核

**流程**：`review.yml` 分三个任务。

1. **scope**：判断要不要审、审什么，并把两项状态标成审核中。草稿不审，转为可审后再审。
2. **claude**：在 `review` 环境里跑，只有这里拿得到订阅 token。
   - 审核者没有 shell，不能写文件，也不能上网。
   - 它要看的 diff 和材料都提前生成好。PR 的检出放在工作区外，经设置里的 `additionalDirectories` 授权读取；这样其中的 CLAUDE.md、AGENTS.md、`.claude/` 不会被当成指令或配置加载（`--add-dir` 会加载 skills、commands 和 subagents，所以不用它）。
   - 它只能读材料、发行内意见，没有写状态的权限。
3. **finish**：写最终结论。它发本轮总结、更新审核记录，最后写 `ai-review` 和 `security-review`。scope 只会把状态标成审核中、草稿或失败，从不写通过。

**审核失败时**：finish 会在状态说明里写明原因。claude-code-action 本身不打印失败原因，审核会在初始化后立刻结束，所以由 [review-diagnose.sh](../../scripts/review-diagnose.sh) 从执行记录里取出 API 状态码：

- 没有 token：按上面“仓库设置”里的命令设置，再在 Actions 里重跑失败的任务。
- token 无效或已过期（HTTP 401）：重新执行 `claude setup-token`，同样设置后重跑。
- 订阅用量到上限（HTTP 429）：等用量重置，再重跑。

**审核分三步**：

- **发现**：是否达成 issue 的目标；和现有代码、AGENTS.md 的边界是否一致；会不会影响别处；PR 证据和改动是否对得上。
- **过滤**：按 [review-filters.md](review-filters.md) 去掉不值得报的。
- **处理**：意见发成行内对话，分为 [重要]、[小问题]、[既有问题]；安全审核用 [安全]。

**结论**：

- 还有没解决的 [重要] 或 [安全] 问题时，结论是"需要修改"，对应的状态失败。本轮新报了这类问题却给"通过"的，也按"需要修改"处理。
- 否则结论是"通过"。[小问题] 和 [既有问题] 不影响结论，但同样要回复处理。
- 审核读的材料：PR 描述；关联的 issue（只收仓库所有者写的）；以往的对话（只收仓库所有者和审核机器人的）。第三方的评论不进审核上下文。

**作者处理意见**：

1. 先把本轮的全部修复合在一起推送；
2. 再逐条回复下面的标签之一；
3. 最后 resolve。

顺序不能反：低风险 PR 的对话全部 resolve 后，可能在修复推上去之前就被自动合并。

| 标签 | 含义 | 算不算无效意见 |
|---|---|---|
| `[fixed]` | 改了 | 不算 |
| `[wrong]` | 意见本身错了，附理由 | 算 |
| `[intended]` | 是故意这么写的，附理由 | 算 |
| `[wontfix]` | 意见成立但不值得改，附理由 | 算 |

只靠回复理由处理 [重要] 意见、没有改代码时，回复完加 `re-review` 标签。审核会在同一个提交上只复核这些回复，不算新的一轮，审完自动去掉标签。

**轮数**：

- 审核工作流在 PR 上维护一条"AI 审核记录"评论（机器人发的、以标记开头的最早一条）。
- 只有作者有改动才算新的一轮。只同步 main、重开 PR、重跑都沿用上一轮的结论，不再调用 Claude。
- 前两轮审整个 PR；从第 3 轮起，只审上一轮之后作者的改动。说不清时，重新审整个 PR。
- 风险档第一次升到高时，安全审核审整个 PR，不论第几轮。
- 同一类问题一次指全，提过的不再提。
- 第 3 轮仍是"需要修改"时，作者再推改动，审核会打上 `needs-rethink` 并让两项状态失败，交给用户决定：要么由仓库所有者加 `allow-more-rounds` 继续审，要么关掉 PR 重来。

**回复和 resolve 的命令**（`<PR>` 换成 PR 号）：

```sh
# 回复一条行内意见
gh api repos/kafeifei/xdial-next/pulls/<PR>/comments/<comment-id>/replies -f body='[fixed] 已改，见 <commit>'

# 列出所有对话（含 thread id 和第一条意见）
gh api graphql -F n=<PR> -f query='query($n:Int!){repository(owner:"kafeifei",name:"xdial-next"){pullRequest(number:$n){reviewThreads(first:100){nodes{id isResolved comments(first:1){nodes{databaseId body}}}}}}}'

# resolve 一个对话
gh api graphql -F id=<thread-id> -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}'
```

## 合并

- **低、中风险**：risk 工作流开启自动合并。PR 落后 main 时，执行 `gh pr update-branch <PR>`；只同步 main 不会重新审核，CI 重跑通过后就合并。
- **高风险**：agent 把证据写全后，在 PR 里说明"等用户批准"，然后停手。
- 由 GITHUB_TOKEN 完成的自动合并不会触发 main 上的 `ci.yml`。分支保护要求合并前与 main 同步，所以合并后的代码和测过的一样。以后在 push main 上挂发版之类的任务时要注意这一点。

## 公开内容

仓库是公开的，推上去就公开了，所以 `make check` 在推送前就跑公开内容门禁，有 `origin/main` 时连本分支的历史一起查。CI 再查一次 PR 的全部历史：新增的行（含合并提交带进来的）、改动过的路径、提交说明，以及作者和提交者的名字与邮箱。

## 指标

- **无效意见比例**：`[wrong]`、`[intended]`、`[wontfix]` 的条数，除以全部已回复的意见数。
- **一轮通过率**：第 1 轮审核后没有再推送就合并的 PR 数，除以全部已合并的 PR 数。
- **审核评测集**：第一次调审核提示词或换模型之前建立，放在 `docs/agent/review-evals/`，起步时用旧仓库的 fix 记录。

## 问题回流

每个线上问题（包括用户日常用 Debug 时发现的）都要留下：

1. 事故记录，放在 `docs/incidents/`；
2. 回归测试；
3. 审核评测用例：问题描述，加上引入它的那个 PR；
4. 能归纳成一类问题的，加一道门禁，并写清什么情况下可以退役。
