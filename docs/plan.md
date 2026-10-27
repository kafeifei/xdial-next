# XDial 重写方案

**目标：** 在新仓库重写 XDial，要求核心功能明确、只依赖上游 sing-box、以 CLI 为核心且对 AI 友好，再按核心功能重新设计界面。新版达标后接管 XDial 的名字和更新源。

状态：方向和项目循环已于 2026-10-25 对齐；M0 于 2026-10-27 完成，M1 进行中。

> 本文从 kafeifei/XDial 的 `docs/plans/rewrite.md`（#56）迁来，之后以本仓库为准。

依据：
- [精简重构盘点](https://github.com/kafeifei/XDial/blob/main/docs/plans/refactor-inventory.md)
- 2026-10-25 与用户的对齐
- 本地模块缓存里 sing-box v1.14.0-beta.2 的源码
- Anthropic 的文章《How the Claude Code team does code review》。原文链接没找到，要点以[视频解读](https://www.youtube.com/watch?v=h0ALH6qBb7k)为准。

标【未实测】的结论没有实际运行过；标【推断】的结论是从代码或文档推出来的。

---

## 1. 为什么重写

用户提出四条目标：

1. 核心功能要非常明确。
2. 软件要精简：只用 sing-box，不引入其他项目。
3. 按核心功能重新设计界面。
4. CLI 是核心，要对 AI 友好。

旧代码的问题集中在四处（摘自盘点，2026-10-25 复核）：

- 复杂度堆在 macOS 编排层。`TransparentProxyManager.swift` 在 10-15 盘点时有 4211 行，到 10-25 的 main 上已涨到 5642 行。
- Swift 把 Go 的校验、tag、就绪判定又实现了一遍。
- 补丁栈只增不减：本地补丁有 sing-box 15 个、tailscale 10 个、sslcon 2 个，`third_party/sslcon` 另有 5.9k 行。
- 盘点里列出的"现在就能删"的约 5.5k 行，至今没删。

重写不推翻旧架构里的所有判断。下面这些继续有效：sing-box 独占 DNS 和转发裁决；Line / RuleSet / Scenario 的领域划分；事故档案里的经验。要变的是三样：接入方式、依赖，以及控制面放在哪里。

## 2. 已拍板的决定

| 主题 | 决定 | 代价或前提 |
|---|---|---|
| 数据面 | 由 root daemon 运行 sing-box 原生 TUN 入站；不再用 System Extension 和 Transparent Proxy | XDial 成为本机唯一的全局 VPN。和其他全局 VPN 客户端同时连接会冲突，旧架构"叠在不透明 Underlay 之上"的原则不再沿用 |
| 依赖 | 只用上游 sing-box，不打本地补丁，不引入 sslcon 等其他项目 | 上游缺陷先提交给上游；确实需要本地变通时，单独找用户批准 |
| AnyConnect | 用 sing-box 自带的 `openconnect` endpoint（`flavor: anyconnect`） | 【未实测】能否连上公司版用的 AnyConnect 服务器 |
| Tailscale | 必须有，功能可以取舍；用上游 `tailscale` endpoint | 范围见 3.2 |
| 场景切换 | 重新生成配置并重载 sing-box，现有连接会断一次；组内换线路走 selector，不重载 | 不再有候选切换事务 |
| 平台 | 只做 macOS | iOS / tvOS 不跟进 |
| 交付 | 在新仓库从零写；旧仓库冻结，只修严重问题；达标后接管名字和更新源，首次启动只读导入旧配置库 | 接管条件见第 8 节 |
| 测试虚拟机 | 在 mbp64k 上新建一台专用 macOS 测试虚拟机，每次从干净镜像克隆 | 占用 mbp64k 剩下的那个 macOS 虚拟机名额；不用 vm4 |
| CI 审核凭据 | 用户用 `claude setup-token` 生成 Claude 订阅 token，自己放进 `review` 环境的 secret `CLAUDE_CODE_OAUTH_TOKEN`（只有 main 上的运行能用） | 消耗订阅额度；`anthropics/claude-code-action` 支持 `claude_code_oauth_token` 输入 |
| 仓库归属 | 公开仓库 `kafeifei/xdial-next`（以后可能并回 kafeifei/XDial）；用"必须与 main 同步 + agent 按顺序合并"代替合并队列 | PR 多到需要排队时，再把仓库转到组织下，改用合并队列 |
| 低风险 PR | 所有关卡通过后自动合并 | 低风险范围见 5.4 |

## 3. 核心功能

### 3.1 保留

1. **线路**：sing-box 原生协议的代理线路、AnyConnect、Tailscale；订阅的导入和更新。
2. **规则集**：本地和远程。
3. **场景**：把规则集绑到线路，并指定默认线路；线路组支持自动选优和手动选择。
4. **连接**：连接、断开、切换场景、切换组内线路。
5. **诊断**：状态；某个域名或 URL 走哪条线路、为什么；日志；测速。
6. **安装、更新、卸载**；种子配置导入（预置配置包要用）。

本机 SOCKS / HTTP 入口就是 sing-box 原生的 `mixed` 入站，作为配置项保留，不算核心功能。

### 3.2 Tailscale 的范围

- **保留**：
  - 登录：CLI 打印登录链接，或使用 auth key。
  - 选择 exit node。
  - 子网路由。
  - 解析 Tailnet 里的名字。
- **不做**：HomeDERP 重选、DERP 诊断、MagicDNS 系统接入，也不带旧仓库的 10 个 tailscale 补丁。
- **名字解析**：【推断】在 TUN 下，系统 DNS 会全部进入 sing-box，用上游 `tailscale` 类型的 DNS 服务器就能解析 Tailnet 名字，不再需要旧版那套 destination-domain 捕获规则。这一点【未实测】。
- **风险**：旧补丁修过一个 peer DERP 状态失效的问题（见 [D35 证据 §4](https://github.com/kafeifei/XDial/blob/main/docs/incidents/d35-transparent-proxy-evidence.md)），去掉补丁后可能复现。复现了先提交给上游。

### 3.3 不做

- 候选切换（新配置准备好之前，旧连接继续承载流量）。
- 自动恢复里的预算、门户网络和 network epoch；只保留"网络变化后重连"。
- 按 SSID 自动切换场景。
- iOS / tvOS。
- 远程功能开关。
- 旧界面里那些针对系统的修补，比如菜单栏条目丢失后的恢复、Control Center 修复。重做界面时按需重新评估。

## 4. 架构

### 4.1 组件与所有权

daemon 和 CLI 打在同一个 Go 二进制 `xdial` 里。

| 组件 | 负责 | 不负责 |
|---|---|---|
| `xdial daemon`（launchd，root） | 配置的存储、校验和编译；sing-box 生命周期；运行状态；结构化事件日志；本地 API | 不在 sing-box 之外裁决 DNS、路由或出口 |
| `xdial` CLI | 所有能力的命令行入口，通过本地 API 调用 daemon | 不直接改配置文件，也不直接改系统网络 |
| 菜单栏 App | 展示状态、收集用户意图，通过同一套本地 API 调用 daemon | 不放业务逻辑，不重复实现 daemon 的校验或格式 |
| sing-box | DNS、规则匹配、出口选择和转发 | 不向系统散落产品级的 DNS 或路由策略 |

### 4.2 本地 API

- 用 Unix socket 传 JSON。CLI 和 App 调同一套接口；接口带版本号，只做增量变更。
- 这套接口就是 root 权限的边界。daemon 必须核验调用方身份，并限制谁能连接、谁能改配置。旧仓库的 root daemon 出过本地提权面问题（盘点 P034），所以它属于高风险档。

### 4.3 数据面

- 用 sing-box 的 `tun` 入站加 `auto_route`，路由规则 `hijack-dns` 接管 DNS，direct 出站跟随系统默认接口。stack 和 strict_route 怎么选，M2 实测后再定。
- 构建 tag 至少要有 `with_gvisor`、`with_openconnect` 和 `with_tailscale`。上游源码里，这两个 endpoint 都受 tag 控制。
- 场景切换时，daemon 重新编译配置并重载 sing-box。组内切线路走 selector，不重载。
- 断开、卸载或 daemon 异常退出之后，不能留下路由、DNS 或接口残留。M2 在虚拟机里逐项检查。

### 4.4 CLI 对 AI 友好的约定

- 每个命令都支持 `--json`，输出带 schema 版本。字段只增不改，变更要过契约测试。
- 出错时固定输出 `code`、`message` 和下一步建议 `hint`；退出码另有一张约定表。
- 不做交互式提问，所有输入都能用参数或文件给出。
- `xdial schema`：列出命令、参数和 JSON 结构，AI 不读文档也能发现有哪些能力。
- `xdial config apply --dry-run`：应用之前先给出会生效的差异。
- `xdial explain <域名|URL>`：说明命中哪条场景规则、走哪条线路、DNS 怎么解析。
- `xdial doctor --json`：读取事件日志和运行状态，给出诊断。
- `xdial logs --json --follow`：持续输出结构化日志。
- MCP 以后再定。

### 4.5 配置与凭据

2026-10-27 与用户对齐，定稿见 [ARCHITECTURE.md](../ARCHITECTURE.md) 的"配置"和"凭据"两节。要点：

- **配置格式**：一个 JSON 文件。线路、线路组、规则集直接写 sing-box 的原生对象，`tag` 换成 `id`；XDial 只增加场景、凭据引用和少量全局项。会让 root daemon 读文件、执行程序或改系统网络的字段一律拒绝。
- **凭据**：和配置分开，只写不读，存在 daemon 的 root 专属文件里，并排除出 Time Machine。
- **订阅**：拉下来的节点放在 daemon 的缓存里，不进配置。
- **导入旧配置**：首次启动时只读导入。
  - 旧库在 `~/.xdial/configuration/profiles.enc`，用 AES-256-GCM 加密，密钥放在用户的 Keychain 里，见 [Profile 配置库](https://github.com/kafeifei/XDial/blob/main/docs/agent/profiles.md)。
  - 由用户身份的 CLI 读旧库，再通过本地 API 交给 daemon；root daemon 不读用户 Keychain。
  - 旧文件不写回，也不删除。
- **种子配置**：保留"构建时注入首次启动配置"这个通用能力。公司版的配置内容仍然只放在独立的私有仓库，不进主仓库。

### 4.6 安装、更新、卸载

- **安装**：
  - daemon 用 `SMAppService.daemon` 注册（和旧仓库一样），需要用户在系统设置里批准。
  - 旧仓库的 [Launch Constraint 事故](https://github.com/kafeifei/XDial/blob/main/docs/incidents/2026-10-13-fresh-registration-launch-constraint.md) 和 [AppTranslocation 事故](https://github.com/kafeifei/XDial/blob/main/docs/incidents/2026-09-08-download-install-translocation.md) 的教训直接适用。
- **更新**：沿用 stable / beta 两份清单，另外补上回退能力。
  - 旧发布器的 `operation=withdraw` 只会把清单改成 `release: null`，已经装上的 App 不会降级（见 [更新与发布](https://github.com/kafeifei/XDial/blob/main/docs/agent/updates.md)）。
  - 新清单要能为撤回的版本指定一个回退目标，让已经装了撤回版本的客户端退回上一个好版本。
  - 这一点从第一天就设计进安装和更新。
- **卸载**：移除 daemon，以及 TUN 和 DNS 设置；可以选择同时删除数据，包括旧配置和凭据。

### 4.7 和现行架构的差异

旧仓库 kafeifei/XDial 的 CLAUDE.md、AGENTS.md 和 ARCHITECTURE 描述的都是旧产品。本仓库在 M0 和 M1 另写自己的架构文档。

| 主题 | 旧 | 新 |
|---|---|---|
| 接入 | NETransparentProxyProvider 加回环 SOCKS relay | sing-box 原生 TUN |
| 和其他 VPN 的关系 | 叠在不透明 Underlay 之上 | 本机唯一的全局 VPN |
| 控制面在哪 | Swift 宿主编排，Go 负责编译 | Go daemon 全部负责，App 只是客户端 |
| 场景切换 | 候选切换，旧连接继续承载 | 重载，连接断一次 |
| AnyConnect | sslcon（third_party）加 2 个补丁 | sing-box `openconnect` |
| Tailscale | 上游 endpoint 加 10 个补丁，再加 MagicDNS 系统接入 | 上游 endpoint，不打补丁 |
| sing-box | 15 个本地补丁 | 不打补丁 |
| 恢复 | 预算、network epoch、门户网络 | 网络变化后重连 |
| 平台 | macOS，加上 iOS / tvOS 草稿 | 只做 macOS |

## 5. 项目循环

参照 Anthropic 的做法：一段代码到用户手里要过四段关卡，人只在关键的地方出手。下面按"一个人维护、多个 agent 并行"调整过。

### 5.1 分工

用户只做五件事：

1. **定做什么**：核心功能清单、界面品味、每个 issue 的目标和验收标准。
2. **审高风险改动**：范围见 5.4 的高风险档。
3. **把关架构样板**：第一个 CLI 命令的语法和 JSON 约定、错误码表、daemon API、配置格式、App 和 daemon 之间的接口。这些会被照抄到所有地方，第一版由用户亲自审。
4. **看证据**：看 PR 附带的命令、输出、虚拟机测试报告和截图，不逐行读代码。
5. **为发版负责**：发版前先对齐内容。

其余的事都由 agent 和机器完成：写代码、跑检查、找问题、修问题、合并低风险改动。

### 5.2 立项

- 用户在 issue 里写目标和验收标准。agent 按"一个 issue、一个 worktree、一个 PR"来做。
- main 只能通过 PR 合入；工作分支从 main 拉出。

### 5.3 提 PR 之前（agent 自己完成）

1. **自己验证**：在测试虚拟机里，用 CLI 把改动涉及的路径跑通（见第 6 节）。只改编译层的，跑单元测试，并让生成的配置通过 `sing-box check`。
2. **换个新上下文审一遍**：只把目标和 diff 交给一个全新的 agent。高风险改动再换一个模型审：Claude 写的交给 Codex，反过来也一样。
3. **PR 正文附证据**：执行过的命令、关键的 `--json` 输出、虚拟机测试结果、界面改动的截图、风险档。

### 5.4 PR 中

**CI（机器）**

- 格式、vet、golangci-lint、`go test -race`。
- 生成的 sing-box 配置全部要通过 `sing-box check` 级别的校验。
- 给 `--json` 输出做 schema 契约测试。
- 依赖白名单：go.mod 新增直接依赖，必须先由用户批准加进白名单；只要出现 `replace` 或补丁目录，CI 就失败。这样"只用 sing-box"就由机器来守。
- 边界检查：菜单栏 App 只调用本地 API，不放业务逻辑。
- 公开内容门禁沿用旧仓库的做法，主仓库里不能出现公司配置等私有内容。

**AI 审核（机器和 agent）**

- **发现**：看三件事：是否达成了 issue 的目标，是否和现有系统一致，会不会影响别的地方。
- **过滤**：可以忽略的意见类别写成仓库里的规则文件（M0 建立），审核时按它过滤。
- **处理**：
  - 剩下的意见分成三类：重要问题、小问题、既有问题。
  - 每条都必须由作者回复 `[fixed]`、`[wrong]`、`[intended]`、`[wontfix]` 之一。这些标签同时用来统计无效意见的比例。
  - 打开"所有对话解决后才能合并"。
- **控制轮数**：
  - 前两轮看改动本身和受它影响的代码，之后只看上一轮以来的新改动。
  - 同一类问题一次全部指出。
  - 提过的意见不再重复提。
  - 同一个 PR 审了 3 轮还不通过，agent 就停止打补丁，在 PR 里写一份思路复盘，交给用户。

**安全审核（机器）**

改动涉及下面任何一类就触发，没处理完的意见同样会挡住合并：

- daemon 的本地 API 和权限；
- TUN、路由或 DNS 接管；
- 凭据存储；
- 安装、更新、卸载；
- CI 和发布配置。

**按风险审批**

按改动的路径自动定档：

| 档 | 范围 | 审批 |
|---|---|---|
| 低 | 文档、测试、界面文案 | 所有关卡通过后自动合并 |
| 中 | 普通功能 | 用户看过证据后批准 |
| 高 | 会触发安全审核的那几类；CLI JSON schema、配置格式、本地 API 的变更 | 用户批准，另外还要一个不同模型的复审和虚拟机测试证据 |

### 5.5 合并时

- 分支必须和最新的 main 同步才能合并。由 agent 按顺序做"同步、等 CI、合并"，保证每个 PR 都是在最新的 main 上测过的。
- 并行的 PR 多到需要排队时，把仓库转到组织下，用 GitHub 合并队列。GitHub 在 2023 年正式发布合并队列时，只对组织名下的公开仓库和 Enterprise Cloud 开放；现行文档没写清楚，也没有实测过。

### 5.6 合并后

- **分层发布**：用户日常用的 Debug 相当于文章里的"内部员工"那一层，然后是 beta，一周没出问题再进 stable。
- **功能开关**：不做远程开关。实验功能用本地配置开关，默认关闭。
- **出问题时**：先撤回版本，让客户端退回上一个好版本（见 4.6），再修复后重新发布。
- **事件日志**：daemon 从第一天起写结构化事件日志，`xdial doctor --json` 读取它。

### 5.7 问题回流

每个线上问题（包括用户在日常使用 Debug 时发现的）都要留下：

1. **事故记录**：沿用旧仓库 `docs/incidents/` 的写法。
2. **回归测试**。
3. **审核评测用例**：问题描述，加上引入它的那个 PR。
4. **CI 门禁**：能归纳成一类问题的，加一道门禁，并写清楚什么情况下可以退役，避免门禁只增不减。

**审核评测集**：起步时用旧仓库的 fix 记录，配上引入问题的那次提交。以后改审核提示词或换模型时，用它比较两个数字：找到的真问题数量、无效意见的比例。只有两项都没有变差才采用。

jev 那种"观察、生成问题卡、出修复 Draft PR"的闭环，等事件日志稳定之后再考虑。旧仓库的实现留在 `cindy/quirky-newton` 分支。

## 6. 测试环境

- 用户日常用的机器上跑着旧 XDial（Transparent Proxy），新版用 TUN，两者同时连接会冲突。所以新版接管之前，数据面只在虚拟机里验证。
- 在 mbp64k 上新建一台专用的 macOS 测试虚拟机：
  - 苹果的虚拟化框架限制每台 Mac 最多同时运行 2 个 macOS 虚拟机，vm4 已经占了 1 个。vm4 上跑着 OpenClaw 的 Telegram 机器人，不拿来做 TUN 测试。
  - 先做一份干净镜像（装好 SSH、关掉自动更新等）。每次测试用 `lume clone` 克隆一台新的，用 `lume ssh` 执行命令，测完删掉。Lume 0.6.1 自带 `clone`、`ssh`、`delete` 等子命令。
  - 动 mbp64k 之前，先读 `~/Codes/lume-mbp64k/CLAUDE.md`。
- 测试线路：
  - 代理线路用虚拟机里自建的 sing-box 服务端，不用真实凭据。
  - 【待定】AnyConnect 可以用开源的 ocserv 当测试服务端，它只用于测试，不进产品。
  - Tailscale 怎么测，在 M3 决定。
- 真实的公司 AnyConnect 和真实的 Tailnet，由用户按清单验证。

## 7. 里程碑

先把循环搭起来，再写功能。

| 里程碑 | 内容 | 完成标准 |
|---|---|---|
| M0 循环骨架 | 新仓库和分支规则；CI 门禁；AI 审核和安全审核；风险定档；PR 证据模板；测试虚拟机和 e2e 骨架 | 一个示例 PR 走完全部关卡并自动合并 |
| M1 CLI 与配置 | 配置格式、校验、编译成 sing-box 配置；`--json` 约定、错误码；`xdial schema` 和 `config apply --dry-run` | 架构样板经用户审过；编译出的配置全部通过 `sing-box check` |
| M2 daemon 与 TUN | daemon 注册和本地 API；连接、断开、状态、卸载 | 在虚拟机里连接后，流量和 DNS 都进入 sing-box；断开和卸载后没有残留 |
| M3 线路 | 代理协议和订阅导入；AnyConnect；Tailscale | 用户在真实环境验证过 AnyConnect 和 Tailnet |
| M4 场景与诊断 | 规则集、场景、线路组；重载切换和 selector；`explain`、`doctor`、事件日志、测速 | 场景切换和诊断用例在虚拟机里通过 |
| M5 菜单栏 App | 按核心功能重新设计界面，只调用本地 API | 用户确认界面 |
| M6 发布与接管 | 签名和公证；更新清单与回退；导入旧配置；种子配置；beta | 满足第 8 节的接管条件 |

## 8. 接管条件（建议，接管前再和用户对齐）

- 3.1 列出的核心功能全部可用。
- 用户把日常机器切到新版 Debug 或 beta，连续使用至少两周，期间没有需要回滚的问题。
- 导入用户真实配置库的结果，经用户确认无误。
- 预置配置包的种子配置在新版上验证通过。
- 卸载能把系统网络恢复原样；退回旧版的路径验证过。

## 9. 待验证和风险

- 【未实测】sing-box 的 `openconnect` 能否连上公司的 AnyConnect 服务器。
- 【未实测】在 TUN 下，上游 tailscale endpoint 的登录、exit node、子网路由和名字解析是否都能用。
- 现在依赖的是 sing-box 的 beta 版（v1.14.0-beta.2），1.14 正式版发布后跟进。
- 新版和其他全局 VPN 客户端会冲突，安装或连接时要给出明确提示。
- daemon 注册需要用户在系统设置里批准，首次安装的体验在 M2 验证。
- 导入旧配置需要访问用户的 Keychain，由用户身份的 CLI 做，不放在 root daemon 里（已定，见 [ARCHITECTURE.md](../ARCHITECTURE.md) 2.6）。

## 10. 旧仓库怎么处理

- 冻结：只修严重问题，不加新功能，也不再做盘点里的结构性重构。
- 新版接管之前，预置配置包继续从旧仓库发布，遵守现行发版规则。
- 接管后归档旧仓库。[精简重构盘点](https://github.com/kafeifei/XDial/blob/main/docs/plans/refactor-inventory.md) 和 `docs/incidents/` 留作新仓库的参考资料。
