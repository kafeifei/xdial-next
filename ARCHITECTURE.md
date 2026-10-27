# 架构

本文记录已经定下、据以实现的架构。还没写到这里的部分，以 [方案](docs/plan.md) 为准。

组件和所有权见 [AGENTS.md 的边界](AGENTS.md#边界)。这里先写配置和凭据，2026-10-27 与用户对齐；本地 API、数据面等在 M2 补上。

文中对 sing-box 的说法，都对照 v1.14.0-beta.2 的源码核实过。标【推断】的结论是从代码或文档推出来的，没有实际运行过。

## 1. 配置

### 1.1 原则

- **只描述三件事**：线路怎么连、匹配什么、场景怎么绑。
- **原生对象**：线路、线路组、规则集都直接写 sing-box 的原生对象。`tag` 换成 `id`，可以再加一个显示用的 `name`。XDial 自己只增加场景、凭据引用和少量全局项。
- **不含凭据**：配置里没有凭据，可以 diff，也可以交给 AI 读。但它含有服务器地址、用户名和内部域名，分享之前要自己看一遍。
- **不含运行状态**：当前场景、selector 手选的成员由 daemon 另存，切场景不改配置。
- **配置是 root 权限的边界**：能提交配置，不等于能让 root daemon 做以下这些事：
  - 读写本机文件或 socket；
  - 执行程序；
  - 监听端口；
  - 创建或修改系统接口、路由、DNS、系统代理；
  - 使用 root 专属的能力；
  - 把本机暴露给远端。

  这些都由 XDial 生成或禁止，见 1.4 和 1.5。凭据是例外：能提交配置的人能使用凭据，见 2.1。

### 1.2 示例

```jsonc
{
  "version": 1,
  "mixed_port": 7890,
  "lines": [
    { "id": "hk", "name": "香港", "type": "trojan",
      "server": "hk.example.com", "server_port": 443,
      "password": { "secret": "hk" },
      "tls": { "enabled": true, "server_name": "hk.example.com" } },
    { "id": "jp", "name": "日本", "type": "vless",
      "server": "jp.example.com", "server_port": 443,
      "uuid": { "secret": "jp" },
      "tls": { "enabled": true, "server_name": "jp.example.com" } },
    { "id": "corp", "name": "公司 VPN", "type": "openconnect", "flavor": "anyconnect",
      "server": "https://vpn.corp.example", "username": "alice",
      "password": { "secret": "corp" } },
    { "id": "tailnet", "name": "Tailnet", "type": "tailscale", "accept_routes": true }
  ],
  "groups": [
    { "id": "proxy", "name": "代理", "type": "urltest", "outbounds": ["hk", "jp"] }
  ],
  "rule_sets": [
    { "id": "corp-domains", "name": "公司域名", "type": "inline",
      "rules": [{ "domain_suffix": ["corp.example"] }] },
    { "id": "cn-ip", "name": "国内 IP", "type": "remote", "format": "binary",
      "url": "https://example.com/geoip-cn.srs", "download_via": "proxy" }
  ],
  "scenarios": [
    { "id": "office", "name": "办公",
      "rules": [
        { "rule_set": "corp-domains", "line": "corp" },
        { "rule_set": "cn-ip", "line": "direct" }
      ],
      "final": "proxy" }
  ],
  "subscriptions": [
    { "id": "airport", "name": "机场", "url": { "secret": "airport-url" } }
  ]
}
```

### 1.3 各部分

| 部分 | 写法 | XDial 额外检查 |
|---|---|---|
| `version` | 整数，现在是 1 | 必填 |
| `mixed_port` | 本机 SOCKS / HTTP 入口的端口，即 sing-box 的 `mixed` 入站；不写或写 0 表示不开 | 只监听回环地址，监听地址不能配 |
| `lines` | sing-box 的出站或 endpoint 对象，类型必须在允许清单里 | 字段分类见 1.4；`detour` 只能指向线路或线路组 |
| `groups` | sing-box 的 `selector` 或 `urltest` | `outbounds`、`default` 只能指向线路或线路组 |
| `rule_sets` | sing-box 的 `inline` 或 `remote` 规则集 | 不允许 `local`（读本机文件），本地规则写成 `inline`。`remote` 的 `url` 只能是 https；经哪条线路下载由 XDial 的 `download_via` 指定，不写则走 `direct` |
| `scenarios` | `rules`：有序的"规则集 → 线路"列表；`final`：其余流量走的线路 | 场景里不能写匹配条件，匹配只写在规则集里；`final` 必填 |
| `subscriptions` | 订阅来源：`url`，以及 `download_via` | `url` 必须是凭据引用，只能是 https；其余字段在 M3 定 |

**id 和引用**

- **id 的格式**：由小写字母、数字和连字符组成，以字母或数字开头，最长 63 个字符。
- **命名空间**：线路和线路组共用一个，因为它们都会被当作出口引用。规则集、场景、订阅、凭据各自一个。
- **内置线路**：`direct` 和 `block` 是内置的，名字保留。
  - `direct` 编译成 sing-box 的直连出站。
  - `block` 编译成路由规则的 `action: reject`，所以只能当场景规则的目标或 `final`，不能做组成员或 `detour`。
- **生成的 tag**：编译生成的其他 tag（入站、DNS server、HTTP 客户端、订阅节点）都带 `xdial:` 前缀。这个前缀在 id 的字符集之外，不会和用户的 id 撞名。endpoint 的 tag 也落在 sing-box 的入站命名空间里，撞名时 sing-box 不会报错。
- **不许成环**：`detour` 和组成员合起来，构成一张引用图，XDial 自己检查有没有环。sing-box 只在启动时才发现环，`sing-box check` 查不出来。

**其他**

- **name**：任意文字，只用来显示。
- **允许的线路类型**：清单写在代码里，先放 [方案 §3.1](docs/plan.md#31-保留) 需要的类型：常见代理协议、`openconnect` 和 `tailscale`。
  - 会执行外部程序的类型不收。例如 `tor`：它不受构建 tag 控制，一启动就会拉起外部进程。
  - 每种类型需要的构建 tag 要进构建，例如 hysteria2 和 tuic 要 `with_quic`，reality 要 `with_utls`。
  - 以后新增类型属于高风险改动。
- **订阅节点**：
  - 从订阅拉下来的节点是派生数据，放在 daemon 的订阅缓存里，不写进配置。
  - 节点要过同一份允许清单和字段分类。唯一的例外：凭据字段在缓存里可以是明文，按凭据对待，存放见 2.3，也不出现在任何输出里。
  - 线路组和场景怎么引用订阅节点，在 M3 定。
- **表达不了的匹配**：规则集里的规则没有 `protocol`、`ip_is_private` 这类条件，"BT 直连""拦截 QUIC"这类需求在第一版里表达不了。

### 1.4 字段分类

允许的每种类型，它的每个字段都必须登记在分类表里，分为五类：

| 类 | 含义 | 例子 |
|---|---|---|
| 普通 | 用户直接写 | `server`、`server_port`、`tls.server_name` |
| 凭据 | 必须写成凭据引用，写明文直接拒绝 | `password`、`uuid`、`private_key`、openconnect 的 `cookie` 和 `token.secret`、`tls.client_key` |
| 可为凭据 | 明文和凭据引用都接受 | openconnect 的 `form_entries[].value`、传输层 `headers` 的值 |
| XDial 生成 | 由 XDial 统一生成，配置里写了就拒绝 | `tag`；tailscale 的 `state_directory`、`auth_key`；remote 规则集的 `http_client`；dialer 里选择接口、地址或 DNS 的字段，如 `bind_interface`、`inet4_bind_address`、`domain_resolver`、`network_strategy` |
| 禁止 | 1.1 列出的那些能力，配置里写了就拒绝 | 各种 `*_path`（证书、密钥、`token.secret_path`、`initial_path`）；openconnect 的 `wrapper_path`；dialer 的 `protect_path`（会把每个连接的 socket 交给这个 Unix socket 的监听者）；`tls.spoof`（用原始套接字，需要 root）；创建系统接口或绑定端口的 `system`、`name`、`listen_port`、`dtls_local_port`、`system_interface`、`relay_server_port`；tailscale 的 `ssh_server`、`advertise_routes`、`advertise_exit_node`；所有已弃用的字段 |

**怎么登记**

- 分类按字段逐个登记，不按字段名去猜。比如规则里的 `process_path` 是匹配条件，属于普通字段；证书的 `certificate_path` 会读文件，属于禁止。
- 需要证书或密钥时，用内联内容写；属于凭据的，写成凭据引用。
- 分类表和允许清单所在的包，路径在 M1 实现时定，要加进高风险档。

**怎么校验**

daemon 处理提交的配置时，下面两层都在 `box.New` 之前完成。`box.New` 构造协议时就会读证书和私钥文件。

1. **在原始 JSON 上检查键名**：只接受登记过的键，大小写必须完全一致，同一个对象里不许有重复的键。
   - 这一层不能省：sing 的 JSON 解析器在键名精确匹配不上时，会按大小写折叠再匹配一次。所以写成 `Certificate_Path`，甚至 `ſsh_server`（U+017F）都会生效。
2. **在 sing-box 解析后的结构上再查一遍**：XDial 生成类和禁止类的字段必须是零值。

**覆盖测试**

测试对着 sing-box 的选项类型，逐个检查允许类型的所有字段。

- 字段同时从反射和 sing-box 自带的 schema 两边枚举。只看反射会漏掉用 `json:"-"` 声明、靠合并解析的变体字段；只看 schema 会漏掉标了 `schema:"omit"` 的弃用字段。
- 升级 sing-box 时出现了没登记的字段，测试就失败，必须先分类才能升级。新增的敏感字段和危险字段，都不会悄悄漏过去。

**第二道防线**

daemon 向 sing-box 注册两样东西：

- **拒绝一切的 `SecurityPolicy`**：sing-box 在 tailscale `ssh_server`、tor `executable_path`、NTP `write_to_system` 处会查询它。
- **只允许 daemon 自己目录的 `filemanager`**：TLS 和 SSH 的 `*_path` 经它读取。

它们只是兜底：openconnect 的路径字段直接交给它的协议库读取，不经过 filemanager。

### 1.5 编译生成的部分

配置不描述的部分，由编译生成。下面这些现在就定下；带"编译 PR 定"的，在 M1 编译配置的 PR 里定，同样属于高风险。

- **只编译用得到的对象**：只编译当前场景能到达的线路、组和规则集。场景用不到的线路不会被实例化，例如 tailscale 线路，没被用到就不会上线。
- **入站**：TUN（M2）和 `mixed`（只监听回环），由 XDial 生成。
- **路由规则的顺序**：
  1. 从 endpoint 进来的连接一律拒绝：`{"inbound": [所有 endpoint], "action": "reject"}`。
     - tailscale、openconnect 和 wireguard 会把对端发往本端隧道地址的连接，改写成发往 127.0.0.1，再交给路由。不拒绝的话，对端就能访问本机只监听回环的服务。
     - wireguard 的判定范围是整个本端地址段。
  2. 嗅探和 DNS 接管（hijack-dns）。
  3. VPN 推送的网段和域名，用 `preferred_by` 匹配对应的 endpoint。它和场景规则谁在前，在 M3 定。
  4. 场景规则，然后是 `final`。
- **tailscale 自己的服务**：MagicDNS（100.100.100.100）和 peerapi 由 tailscale 自己处理，不经过路由规则，上面那条拒绝管不到。在 M3 实测，并尽量关掉。
- **DNS**：
  - DNS 不能配置。
  - 原则：先按场景确定目标走哪条线路，再经这条线路解析。
    - `direct` 用系统 DNS；
    - 代理线路经它自己解析；
    - endpoint 线路用它对应的 DNS server 类型（`openconnect` / `tailscale`），解析 VPN 推送的域名和 Tailnet 名字。
  - 具体规则编译 PR 定。
- **编译 PR 定的其他事**：
  - 目的地是域名（例如来自 `mixed` 入口）时，IP 类规则集要不要先解析、经哪个 DNS 解析；
  - 私有地址和局域网流量默认走哪里。
  - 编译不悄悄加"私有地址直连"这类规则。公司网段多半也是私有地址。

### 1.6 存放与修改

- **谁持有**：配置由 daemon 持有，存为数据目录里的 `config.json`，root 所有，权限 0600。
- **怎么读写**：CLI 和 App 只通过本地 API 读写。
  - `xdial config export` 导出。
  - `xdial config apply <文件> [--dry-run]` 提交。文件由 CLI 以调用者的身份读取，API 只接收内容，daemon 不打开调用方给的路径。
- **注释**：输入可以带注释和尾逗号，sing 的 JSON 解析器默认支持。daemon 保存规范化后的 JSON，不保留注释。sing-box 能保留注释，这是我们的选择，不是限制。
- **revision**：每份配置有一个 revision，即规范化内容的摘要。
  - `export` 输出 revision。
  - `apply --if-match <revision>` 在配置已被别人改过时拒绝；App 每次都带。
- **apply 是整份替换**：
  - 先完整校验：字段分类，引用和环，并对每个场景单独编译、通过 sing-box 自己的检查（`box.New` 加 `Close`）。全部通过才原子写入；任何一项失败，现有配置都不动。
  - 检查用的是格式合法的占位值，不用凭据的真值，见 2.2。
  - `--dry-run` 输出：和现有配置的差异、受影响的场景、缺少的凭据、凭据流向的变化（见 2.1）。
- **连接中 apply**：
  - 当前场景受影响时，先用新配置重载，成功才写入。重载失败就恢复旧配置继续运行，apply 报错，配置不变。
  - 不允许删掉当前场景，要先切到别的场景。
  - selector 手选的成员被删掉时，回到组的默认值。
- **缺凭据**：引用了还没设置的凭据，可以 apply，输出里会列出缺哪些。真正连接、或者切到用到它的场景时，才因为缺凭据而拒绝。
- **版本**：
  - `version` 只增不减。daemon 拒绝读比自己新的版本；比自己旧的版本在读入时迁移，每个迁移都有测试。
  - 升级 sing-box 时，上游弃用的字段也由版本迁移改写。
  - 分类表新增用户可写的字段时，`version` 必须加一，旧 daemon 才能认出这是新格式。
- **回退**：
  - 迁移后写回之前，原文件保留为 `config.v<旧版本>.json`。
  - 退回旧版之后，daemon 遇到比自己新的版本，就改用和自己版本对应的副本，并在状态里说明。这一点对应 [方案 §4.6](docs/plan.md#46-安装更新卸载) 的回退要求。
- **变更档位**：格式和分类表的变更都属于高风险。

## 2. 凭据

### 2.1 原则

- **凭据和配置分开**：配置里只有凭据引用。
- **只写不读**：本地 API 和 CLI 都没有读出凭据值的接口。
- **只有一个入口**：值只经本地 API 的 `secret set` 进入 daemon，来源可以是 CLI 的 stdin、App 的安全输入框，或者导入旧库。
- **值不出现在别处**：命令行参数、环境变量、日志、`--json` 输出、错误信息、导出文件里都没有。
  - 来自 sing-box、HTTP 客户端和订阅解析的错误与日志，在输出或写盘之前，先把所有凭据值替换成 `<secret:名字>`。
  - 订阅拉取失败的错误里不带 URL。
- **只在内存里使用**：
  - daemon 只在编译时把引用替换成真值。sing-box 跑在 daemon 进程里，带凭据的编译结果只在内存里交给它，不写盘。
  - 调试用的编译输出，把凭据换成占位符。
- **只写不读的边界**：
  - 它挡的是无意的泄露：日志、导出、AI 的对话记录、共享屏幕。
  - 它挡不住有权提交配置的人：只要把凭据引用填进一条指向自己服务器的线路（例如 SOCKS5 或带用户名的 HTTP 代理），连接时凭据就发过去了。
  - 所以 M2 授权时，提交配置和设置凭据按同一级别管。
- **凭据流向要显式确认**：
  - 流向 = 引用方的 id、类型，以及决定凭据发往哪里的目的地字段（`server`、`server_port` 等，按类型在分类表里登记）。
  - `secret set` 时记下当时的流向。之后某次 apply 让已设置的凭据出现新的引用方，或者引用方的类型、目的地变了，就要加 `--confirm-secret-flow` 才能提交，输出里逐条列出变化。
  - 这一条防的是：照着别人分享的配置或 AI 生成的配置 apply 时，凭据被悄悄引到别的服务器。

### 2.2 凭据引用

- 写法是 `{"secret": "<名字>"}`，名字的规则同 id。
- 只能写在分类为"凭据"或"可为凭据"的字段，以及订阅的 `url` 里。
- 一个凭据可以被多处引用。
- **格式校验**：每个凭据字段登记一个格式校验器和一个占位值生成器。
  - `secret set` 时，按这个凭据现有的所有引用方校验格式；apply 时，对已设置的凭据按新的引用方再校验。校验失败的报错不带值。
  - 不能依赖 sing-box 来校验：vmess 和 vless 遇到不合法的 uuid 不报错，会悄悄换成别的值；tuic 报错时会把原值带进错误信息。
- **占位值**：apply 的 sing-box 检查用占位值。占位值格式合法，不同字段各不相同（uuid、base64 私钥、ss2022 密码……）。

### 2.3 存放

- **位置**：daemon 数据目录下一个 root 专属的子目录（0700），凭据存在其中的 `secrets.json`（0600）。
  - 订阅缓存（含节点密码）和 Tailscale 的登录状态目录也放在这个子目录里。
  - 写入用临时文件加 rename，原子替换，权限保持不变。
- **备份**：整个子目录排除出 Time Machine；磁盘层面靠 FileVault。
- **换机后要重新设置**：
  - 从备份恢复之后，配置还在，凭据需要重新设置。`xdial secret list` 会列出缺哪些。
  - 【推断】用迁移助理直接从旧 Mac 迁过来时，也会跳过这个子目录。
  - 排除是否生效、迁移助理是否跳过，都在 M2 实测。
- **没选系统钥匙串**：root 照样能读，读写 Security 框架还要用 cgo。它比 root 文件多出的保护在备份和磁盘层面，而这两层已经分别由"排除备份"和 FileVault 承担。
- **没选用户钥匙串**：daemon 重启后，要等 CLI 或 App 补交凭据才能重连，和"daemon 持有一切"冲突。

### 2.4 命令

本地 API 提供同样的三个操作，没有读取凭据值的接口。

| 命令 | 作用 |
|---|---|
| `xdial secret set <名字>` | 从 stdin 读值。stdin 是终端时关闭回显；只去掉末尾的一个 `\n` 或 `\r\n` |
| `xdial secret list [--json]` | 列出名字、是否已设置、更新时间、被哪些对象引用；也列出被引用了但还没设置的名字 |
| `xdial secret rm <名字>` | 删除凭据；仍被引用时拒绝，提示里列出引用方 |

### 2.5 各类凭据

| 凭据 | 处理 |
|---|---|
| 代理线路的密码、uuid 等 | 凭据引用 |
| AnyConnect 的密码、cookie、TOTP 种子 | 凭据引用。需要浏览器登录的方式，在 M3 定 |
| 订阅 URL | 凭据引用。拉下来的节点进订阅缓存，不进配置 |
| Tailscale auth key | 只在 `xdial tailscale login` 时从 stdin 读一次，用完不保存。登录要重载一次 sing-box，现有连接会断一次 |
| Tailscale 登录状态（节点密钥） | sing-box 写在 root 专属子目录里，不复制，也不导出 |

### 2.6 导入和种子配置

- **导入旧配置库**：
  - 由用户身份的 CLI 读旧库 `~/.xdial/configuration/profiles.enc`，密钥在用户的钥匙串里。读出后转成新格式，再通过本地 API 交给 daemon：配置走 apply，凭据走 `secret set`。
  - root daemon 不读用户的钥匙串。
  - 旧文件不写回，也不删除。
  - 【推断】旧版的部分绑定（`condition_ids`）和交错顺序（`match_order`），可以拆成多个规则集来表达，语义不丢，只是结构变平。导入在 M6 实测。
- **种子配置**：只含配置，不含凭据。

## 3. 留给后面的

- **M1 编译 PR**：DNS 规则的细节；域名目的地是否先解析；私有地址的默认去向；分类表和允许清单的包路径。
- **M2**：
  - 数据目录的具体路径，Debug 和正式版怎么分开；
  - 本地 API 怎么核验调用方身份，以及谁能提交配置、设置凭据（两者同级，见 2.1）；
  - Time Machine 排除和迁移助理的实测。
- **M3**：
  - 订阅节点怎么被线路组和场景引用；
  - VPN 推送规则和场景规则谁在前；
  - AnyConnect 需要浏览器登录时怎么办；
  - tailscale 自己的服务能不能关。
