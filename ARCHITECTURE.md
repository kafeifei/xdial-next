# 架构

本文记录已经定下、据以实现的架构。还没写到这里的部分，以 [方案](docs/plan.md) 为准。改这个文件属于高风险。

组件和所有权见 [AGENTS.md 的边界](AGENTS.md#边界)。这里先写配置和凭据，2026-10-27 与用户对齐；本地 API、数据面等在 M2 补上。

标【推断】的结论是从代码或文档推出来的，没有实际运行过。

## 1. 配置

### 1.1 原则

- 配置只描述三件事：线路怎么连、匹配什么、场景怎么绑。
- 线路、线路组、规则集都直接写 sing-box 的原生对象：`tag` 换成 `id`，可以再加一个显示用的 `name`。XDial 自己只增加场景、凭据引用和少量全局项。
- 配置里不含凭据，可以 diff、交给 AI 读、拿去分享。
- 运行状态不进配置。当前场景、selector 手选的成员由 daemon 另存，切场景不改配置。
- 配置是 root 权限的边界。能提交配置，不等于能让 root daemon 读写本机文件、执行程序、监听端口，或者改系统接口和 DNS。这些字段一律由 XDial 生成或禁止，规则见 1.4。

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
      "url": "https://example.com/geoip-cn.srs" }
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
| `groups` | sing-box 的 `selector` 或 `urltest` | `outbounds`、`default` 只能指向线路或线路组，不能成环 |
| `rule_sets` | sing-box 的 `inline` 或 `remote` 规则集 | 不允许 `local`（读本机文件），本地规则写成 `inline` |
| `scenarios` | `rules`：有序的"规则集 → 线路"列表；`final`：其余流量走的线路 | 场景里不能写匹配条件，匹配只写在规则集里；`final` 必填 |
| `subscriptions` | 订阅来源 | `url` 必须是凭据引用；其余字段在 M3 定 |

- **id**：
  - 由小写字母、数字和连字符组成，以字母或数字开头，最长 63 个字符。
  - 线路和线路组共用一个命名空间，因为它们都会被当作出口引用。规则集、场景、订阅、凭据各自一个命名空间。
  - `direct` 和 `block` 是内置线路，保留不用。
- **name**：任意文字，只用来显示。
- **订阅节点**：从订阅拉下来的节点是派生数据，放在 daemon 的订阅缓存里（含节点密码，存放见 2.3），不写进配置。线路组和场景怎么引用订阅节点，在 M3 定。
- **允许的线路类型**：清单写在代码里。先放 [方案 §3.1](docs/plan.md#31-保留) 需要的：常见代理协议、`openconnect` 和 `tailscale`。具体清单在 M1 实现时按构建 tag 定，以后新增类型属于高风险改动。

### 1.4 字段分类

允许的每种类型，它的每个字段都必须登记在分类表里，分为四类：

| 类 | 含义 | 例子 |
|---|---|---|
| 普通 | 用户直接写 | `server`、`server_port`、`tls.server_name` |
| 凭据 | 必须写成凭据引用，写明文直接拒绝 | `password`、`uuid`、`private_key`、`token.secret`、`tls.client_key` |
| XDial 生成 | 由 XDial 统一生成，配置里写了就拒绝 | `tag`、tailscale 的 `state_directory`；dialer 里选择接口、地址或 DNS 的字段，如 `bind_interface`、`inet4_bind_address`、`domain_resolver`、`network_strategy` |
| 禁止 | 会让 root daemon 读文件、执行程序、对外开放本机的字段，配置里写了就拒绝 | 各种 `*_path`（证书、密钥、`initial_path`）、openconnect 的 `wrapper_path`、tailscale 的 `ssh_server`、`advertise_routes`、`advertise_exit_node` |

- 分类按字段逐个登记，不按字段名去猜。比如规则里的 `process_path` 是匹配条件，属于普通字段；证书的 `certificate_path` 会读文件，属于禁止。
- 测试会对着 sing-box 的选项类型，逐个检查允许类型的所有字段。升级 sing-box 时出现了没登记的字段，测试就失败，必须先分类才能升级。
- 这样一来，新增的敏感字段和新增的危险字段，都不会悄悄漏过去。
- 需要证书或密钥时，用内联内容写；属于凭据的，写成凭据引用。

### 1.5 存放与修改

- **谁持有**：配置由 daemon 持有，存为数据目录里的 `config.json`，root 所有，权限 0600。CLI 和 App 只通过本地 API 读写：`xdial config export` 导出，`xdial config apply <文件> [--dry-run]` 提交。
- **注释**：输入里可以带注释，daemon 保存规范化后的 JSON，注释不保留。【推断】依据是 sing 的 JSON 解析器能读注释，这一点读源码所得，没有实测。
- **运行状态**：当前场景和 selector 手选的成员另存为 `state.json`。
- **apply 是整份替换**：
  - 先完整校验，包括编译成 sing-box 配置并通过 sing-box 自己的检查；全部通过，才原子写入。
  - 任何一项失败，现有配置都不动。
  - `--dry-run` 输出和现有配置的差异、受影响的场景，以及缺少哪些凭据。
- **缺凭据**：引用了还没设置的凭据，可以 apply，输出里会列出缺哪些。真正连接、或者切到用到它的场景时，才因为缺凭据而拒绝。
- **版本**：
  - `version` 只增不减。daemon 拒绝读比自己新的版本；比自己旧的版本在读入时迁移，每个迁移都有测试。
  - 升级 sing-box 时，上游弃用的字段也由版本迁移改写。
- **变更档位**：格式和字段分类表的变更都属于高风险。

## 2. 凭据

### 2.1 原则

- **凭据和配置分开**：配置里只有凭据引用。
- **只写不读**：本地 API 和 CLI 都没有读出凭据值的接口。
- **值只走两条路进 daemon**：stdin，或者 App 的安全输入框。
- **值不出现在别处**：不出现在命令行参数、环境变量、日志、`--json` 输出、错误信息和导出文件里。
- **只在内存里使用**：daemon 只在编译 sing-box 配置时，把引用替换成值。sing-box 跑在 daemon 进程里，带凭据的编译结果只在内存里交给它，不写盘。调试用的编译输出把凭据换成占位符。

### 2.2 凭据引用

- 写法是 `{"secret": "<名字>"}`，名字的规则同 id。
- 只能写在分类为"凭据"的字段和订阅的 `url` 里。
- 一个凭据可以被多处引用。

### 2.3 存放

- **位置**：daemon 数据目录下一个 root 专属的子目录（0700），凭据存在其中的 `secrets.json`（0600）。
  - 订阅缓存（含节点密码）和 Tailscale 的登录状态目录也放在这个子目录里。
  - 写入用临时文件加 rename，原子替换，权限保持不变。
- **备份**：整个子目录排除出 Time Machine；磁盘层面靠 FileVault。排除是否生效，在 M2 实测。
- **换机后要重新设置**：迁移到新 Mac 或从备份恢复之后，配置还在，凭据需要重新设置。`xdial secret list` 会列出缺哪些。
- **没选系统钥匙串**：root 照样能读，读写 Security 框架还要用 cgo。它比 root 文件多出的保护在备份和磁盘层面，而这两层已经分别由"排除备份"和 FileVault 承担。
- **没选用户钥匙串**：daemon 重启后，要等 CLI 或 App 补交凭据才能重连，和"daemon 持有一切"冲突。

### 2.4 命令

本地 API 提供同样的三个操作，没有读取凭据值的接口。

| 命令 | 作用 |
|---|---|
| `xdial secret set <名字>` | 从 stdin 读值，去掉末尾的换行 |
| `xdial secret list [--json]` | 列出名字、是否已设置、更新时间、被哪些对象引用；也列出被引用了但还没设置的名字 |
| `xdial secret rm <名字>` | 删除凭据；仍被引用时拒绝，提示里列出引用方 |

### 2.5 各类凭据

| 凭据 | 处理 |
|---|---|
| 代理线路的密码、uuid 等 | 凭据引用 |
| AnyConnect 的密码、TOTP 种子 | 凭据引用。需要浏览器登录的方式，在 M3 定 |
| 订阅 URL | 凭据引用。拉下来的节点进订阅缓存，不进配置 |
| Tailscale auth key | 只在 `xdial tailscale login` 时从 stdin 读一次，用完不保存 |
| Tailscale 登录状态（节点密钥） | sing-box 写在 root 专属子目录里，不复制，也不导出 |

### 2.6 导入旧配置库

- 由用户身份的 CLI 读旧库 `~/.xdial/configuration/profiles.enc`，密钥在用户的钥匙串里。读出后转成新格式，再通过本地 API 把配置和凭据交给 daemon。
- root daemon 不读用户的钥匙串。
- 旧文件不写回，也不删除。
- 【推断】旧版的部分绑定（`condition_ids`）和交错顺序（`match_order`），可以拆成多个规则集来表达，语义不丢，只是结构变平。导入在 M6 实测。

## 3. 留给后面的里程碑

- M2：数据目录的具体路径，以及 Debug 和正式版怎么分开；本地 API 怎么核验调用方身份，谁能提交配置、谁能设置凭据。
- M3：订阅节点怎么被线路组和场景引用；AnyConnect 需要浏览器登录时怎么办。
