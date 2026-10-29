# xdial-next

XDial 的下一代：macOS 网络分流工具，CLI 是核心，只用上游 sing-box。M0（项目循环骨架）已完成，现在处于 M1（CLI 与配置），还没有产品功能。

- 方案：[docs/plan.md](docs/plan.md)
- 已定的架构（配置格式、凭据）：[ARCHITECTURE.md](ARCHITECTURE.md)
- 项目循环的完整规则：[docs/agent/loop.md](docs/agent/loop.md)
- 测试虚拟机与 e2e：[docs/agent/e2e.md](docs/agent/e2e.md)

这个仓库以后可能并回 [kafeifei/XDial](https://github.com/kafeifei/XDial)；旧仓库的文档描述的是旧产品，不适用于这里。

## 边界

- sing-box 独占 DNS、规则匹配、出口选择和转发；xdial 只负责表达、编译和托管。
- `xdial daemon`（root）持有配置、sing-box 生命周期、运行状态和事件日志。CLI 和菜单栏 App 只通过本地 API 调用它，不放业务逻辑。
- 只用上游 sing-box：不打补丁，不 vendor 上游源码，`go.mod` 不写 `replace`。新增直接依赖要先由用户批准，加进 [白名单](.github/deps-allowlist.txt)。
- 只做 macOS。

## 工作循环

分工：用户定做什么、审高风险改动和架构样板、看证据、为发版负责；其余由 agent 完成。

1. 一个 issue、一个 worktree、一个 PR。分支从最新的 main 拉出，命名为 `claude/*` 或 `codex/*`。
2. 提 PR 之前：
   - 自己验证：跑 `make check`；改动涉及运行时行为的，再跑 `make e2e`。不在用户日常用的机器上跑 TUN，也不改它的系统网络。
   - 换个新上下文审一遍：只把 issue 目标和 diff 交给一个全新的 agent。高风险改动再换一个模型审：Claude 写的交给 Codex，反过来也一样。
3. PR 按 [模板](.github/pull_request_template.md) 附上证据。
4. 处理审核意见：先把本轮的全部修复合在一起推送，再逐条回复 `[fixed]`、`[wrong]`、`[intended]`、`[wontfix]` 之一，最后 resolve。只靠回复理由处理 [重要] 意见、没有改代码时，回复完加 `re-review` 标签请审核复核。
5. 同一个 PR 审了 3 轮还不通过（出现 `needs-rethink` 标签）：停止打补丁，在 PR 里写思路复盘，交给用户。
6. 合并：
   - 低、中风险 PR 由 risk 工作流开启自动合并；PR 落后 main 时，执行 `gh pr update-branch`，再等 CI。
   - 高风险 PR 由用户加 `owner-approved` 批准后自动合并。agent 写全证据后说明"等用户批准"，然后停手。
   - agent 不加 `owner-approved` 和 `allow-more-rounds`，不开自动合并，也不直接合并高风险的 PR。
7. 不碰 secrets、环境、分支保护和风险定档。确实需要改时，告诉用户。

## 命令

| 命令 | 作用 |
|---|---|
| `make check` | 依次跑 gofmt、vet、golangci-lint（本机装了才跑）、`go test -race`、依赖白名单和公开内容门禁 |
| `make e2e` | 在 mbp64k 的测试虚拟机里跑 e2e |
| `make build` | 构建本机的 `build/xdial` |
