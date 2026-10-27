# 架构

本文记录已经定下、据以实现的架构。还没写到这里的部分，以 [方案](docs/plan.md) 为准。

组件和所有权见 [AGENTS.md 的边界](AGENTS.md#边界)。这里先写配置和凭据，2026-10-27 与用户对齐；本地 API、数据面等在 M2 补上。

**核实依据**

- 文中对 sing-box 的说法，对照 v1.14.0-beta.2 和它依赖的 sagernet/tailscale fork 的源码核实过。
- 有几处实际编译、运行过：`ts_omit_*` 构建 tag、非 PEM 证书引发的 panic、负时长引发的 panic。
- sing-openconnect 和 sing-quic 的源码不在本地，凡是要靠它们的结论都没有核实。
- 标【推断】的结论是从代码或文档推出来的，没有实际运行过。

## 1. 配置格式

### 1.1 原则

- **只描述三件事**：线路怎么连、匹配什么、场景怎么绑。
- **原生对象**：线路、线路组、规则集都直接写 sing-box 的原生对象。`tag` 换成 `id`，可以再加一个显示用的 `name`。XDial 自己只增加场景、凭据引用和少量全局项。
- **凭据不进配置**：凭据字段只能写成引用。配置可以 diff，也可以交给 AI 读。但它含有服务器地址、用户名和内部域名，"可为凭据"类字段（见 2.3）也允许写明文，分享之前要自己看一遍。
- **不含运行状态**：当前场景、selector 手选的成员由 daemon 另存，切场景不改配置。
- **配置是 root 权限的边界**：提交配置的人能做什么、不能做什么，见第 2 节。

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

| 部分 | 写法 | XDial 额外规则 |
|---|---|---|
| `version` | 整数，现在是 1 | 必填 |
| `mixed_port` | 本机 SOCKS / HTTP 入口的端口，即 sing-box 的 `mixed` 入站；不写或写 0 表示不开 | 只监听回环地址，端口不小于 1024。这是"不能让 daemon 监听端口"的一个明确例外 |
| `lines` | sing-box 的出站或 endpoint 对象，类型必须在允许清单里 | 字段分类见 2.3；`detour` 只能指向线路或线路组 |
| `groups` | sing-box 的 `selector` 或 `urltest` | `outbounds` 只能指向线路或线路组；selector 的 `default` 必须是自己 `outbounds` 里的成员 |
| `rule_sets` | `inline`，或 `remote` | 不允许 `local`（读本机文件），本地规则写成 `inline`。`remote` 由 daemon 自己下载（见 3.4），`url` 只能是 https，可以是凭据引用；`download_via` 指定经哪条线路下载，不写则走 `direct` |
| `scenarios` | `rules`：有序的规则列表，每条是 `{"rule_set", "line", "invert"?}`；`final`：其余流量走的线路 | 场景里不能写匹配条件，匹配只写在规则集里；`final` 必填 |
| `subscriptions` | 订阅来源：`url`，以及 `download_via` | `url` 必须是凭据引用，只能是 https；其余字段在 M3 定 |

- **XDial 自己的键**：`id`、`name`、`download_via`、凭据引用。
  - 它们在交给 sing-box 之前就被剥离，永远不进入原生选项。
  - 和这些键同名的原生字段（如 openconnect、wireguard 的系统接口名 `name`）因此无法设置，好在它们本来就属于禁止类。
  - 测试保证 XDial 的键不会遮住任何普通字段或凭据字段。
- **`invert`**：对规则集的匹配结果取反，编译成 sing-box 路由规则的 `invert`。
  - 用来表达旧版的"海外 IP = 国内 IP 取反"。
  - 注意：IP 类规则集遇到还没解析的域名目的地时，判为"没匹配上"，取反后反而成立。所以它的语义依赖 3.3 里"域名目的地是否先解析"的决定。

### 1.4 id 和引用

- **id 的格式**：由小写字母、数字和连字符组成，以字母或数字开头，最长 63 个字符。
- **命名空间**：线路和线路组共用一个，因为它们都会被当作出口引用。规则集、场景、订阅、凭据各自一个。
- **内置线路**：`direct` 和 `block` 是 XDial 内置的，名字保留。
  - `direct` 编译成直连出站。
  - `block` 编译成路由规则的 `action: reject`，所以只能当场景规则的目标或 `final`。
- **生成的 tag**：编译生成的 tag（入站、DNS server、订阅节点等）都带 `xdial:` 前缀。这个前缀在 id 的字符集之外，不会撞名。
- **XDial 自己检查引用**：引用都要存在；`detour` 和组成员合起来不许成环；所有 tag 不许重名。sing-box 在这几件事上都靠不住：
  - 环要到启动时才查出来，`sing-box check` 查不出；
  - 直接用结构体构造配置时，重复的 tag 会被静默替换；
  - selector 的 `default` 不合法时，如果缓存里有手选值，会被静默接受。

### 1.5 订阅节点

- **不进配置**：从订阅拉下来的节点是派生数据，放在 daemon 的订阅缓存里，不写进配置。
- **过同一套分类**：节点要过同一份允许清单和字段分类（2.3），另外再收紧三条：
  - 只允许代理协议，不允许 endpoint；
  - 不允许 `detour`；
  - 不允许凭据引用，否则恶意订阅就能把用户已设置的凭据引到自己的服务器。
- **节点自带的凭据**：凭据字段在缓存里可以是明文，按凭据对待，存放见 4.3，也不出现在任何输出里。
- **留到 M3**：线路组和场景怎么引用订阅节点。

### 1.6 第一版表达不了的

- **规则条件不全**：规则集里的规则没有 `protocol`、`ip_is_private` 这类条件，"BT 直连""拦截 QUIC"这类需求表达不了。
- **AnyConnect 的一次性密码**：只支持 TOTP，不支持 HOTP。sing-box 只把 HOTP 计数器放在内存里，重载后会回到配置里的值，导致重复使用已经用过的密码。

## 2. 配置的安全边界

### 2.1 目标

能提交配置的人，不能借此让 root daemon 做到以下这些事：

- 读写本机文件或 socket；
- 执行程序；
- 监听端口（`mixed_port` 除外）；
- 创建或修改系统接口、路由、DNS、系统代理，或者改动网关（端口映射）；
- 使用 root 专属的能力；
- 把本机暴露给远端；
- 让 daemon 崩溃。

凭据是例外：能提交配置的人能使用凭据，见 4.2。

### 2.2 XDial 组装 sing-box 配置

- **用户只提供三类对象**：用户配置只贡献线路、线路组、规则集。sing-box 配置的其余部分都由 XDial 生成，包括入站、DNS、路由、`experimental`、`ntp`、证书、`http_clients` 等。
- **交给 sing-box 的是结构**：交给 sing-box 的是 XDial 组装好的类型化结构，不是用户的原文。凭据引用也在结构上替换成真值，不做文本替换。
- **受限 registry**：daemon 用 `box.Context` 传入自己构造的 registry，只注册允许清单里的类型，以及 XDial 生成配置要用到的类型，不注册任何 service。
  - 上游的 `include` 无条件注册了 tor、bridge、snell 等类型，以及 api、ssmapi 等服务。不用它，这些东西就从根上进不来。
- **允许清单**：先放 [方案 §3.1](docs/plan.md#31-保留) 需要的类型：常见代理协议、`openconnect` 和 `tailscale`。
  - 每种类型需要的构建 tag 要进构建，例如 hysteria2 和 tuic 要 `with_quic`，reality 要 `with_utls`，`tailscale` 要 `with_gvisor`。
  - 新增类型属于高风险改动。

### 2.3 字段分类

允许的每种类型，它的每个字段都必须登记在分类表里。

| 类 | 含义 | 例子 |
|---|---|---|
| 普通 | 用户直接写 | `server`、`server_port`、`tls.server_name`、tailscale 的 `control_url`、`exit_node` |
| 凭据 | 必须写成凭据引用，写明文直接拒绝 | `password`、`uuid`、`private_key`、openconnect 的 `cookie` 和 `token.secret`、`tls.client_key` |
| 可为凭据 | 明文和凭据引用都接受 | openconnect 的 `form_entries[].value` |
| XDial 生成 | 由 XDial 统一生成，配置里写了就拒绝 | `tag`；tailscale 的 `state_directory`、`auth_key`；dialer 里选择接口、地址或 DNS 的字段，如 `bind_interface`、`inet4_bind_address`、`domain_resolver`、`network_strategy` |
| 禁止 | 2.1 列出的那些能力，配置里写了就拒绝 | 见下 |

**禁止类的例子**

- **读文件**：各种 `*_path`（证书、密钥、`token.secret_path`、`initial_path`）。
- **执行程序**：openconnect 的 `wrapper_path`。
- **交出 socket**：dialer 的 `protect_path`，它会把每个连接的 socket 交给这个 Unix socket 的监听者。
- **使用 root 专属能力**：`tls.spoof`，它要用原始套接字。
- **建接口、开端口、动网关**：
  - `system`、`listen_port`、`dtls_local_port`、`system_interface`、`relay_server_port`；
  - hysteria2 的 `realm.port_mapping`，它会在网关上做端口映射。
- **对外开放本机**：tailscale 的 `ssh_server`、`advertise_routes`、`advertise_exit_node`、`advertise_tags`。
- **其他**：shadowsocks 的 `plugin_opts` 里没登记的键，以及所有已弃用的字段。

**登记规则**

- **按字段登记，不猜名字**：分类按字段逐个登记，不按字段名去猜。比如规则里的 `process_path` 是匹配条件，属于普通字段；证书的 `certificate_path` 会读文件，属于禁止。
- **值域和约束**：每个字段同时登记值域，跨字段的约束单独登记。例如：
  - 时长必须为正；
  - 证书和密钥必须是能解析的 PEM；
  - ss2022 的密码长度要和 `method` 对得上。
  - 上游在这些地方会 panic 或者行为不对：时长写成负值，第一次有流量时 panic；证书不是合法 PEM，`box.New` 时 panic。
- **字符串里的第二层语法**：有些字段的值本身就是另一种配置语法，例如 shadowsocks 的 `plugin_opts`，`v2ray-plugin` 的 `cert` 会读文件。这类字段按内部语法逐键登记，没登记的键一律拒绝；做不到逐键登记的，整个字段禁止。
- **证书和密钥写内联**：需要证书或密钥时，用内联内容写；属于凭据的，写成凭据引用。
- **包路径**：分类表和允许清单所在的包，路径在 M1 实现时定，要加进高风险档。

**覆盖测试**

测试对着 sing-box 的选项类型，逐个检查允许类型的所有字段。

- 字段同时从反射和 sing-box 自带的 schema 两边枚举。只看反射会漏掉用 `json:"-"` 声明、靠合并解析的变体字段；只看 schema 会漏掉标了 `schema:"omit"` 的弃用字段。
- 升级 sing-box 时出现了没登记的字段，测试就失败，必须先分类才能升级。
- 测试管不到字符串里的第二层语法（如 `plugin_opts`），升级 sing-box 时要人工审查。

### 2.4 校验的顺序

都在 `box.New` 之前完成。`box.New` 构造协议时就会读文件，也可能 panic。

1. **在原始 JSON 上检查键名**：只接受登记过的键，大小写必须完全一致，同一个对象里不许有重复的键。
   - 解析用的是和 sing 一样的规则：允许注释和尾逗号，键名先解转义再比较。
   - 这一层不能省：sing 的 JSON 解析器在键名精确匹配不上时，会按大小写折叠再匹配一次。所以写成 `Certificate_Path`，甚至 `ſsh_server`（U+017F）都会生效。
2. **解析成 sing-box 的类型化结构**：剥离 XDial 自己的键之后再解析。然后检查 XDial 生成类和禁止类的字段都是零值，再检查值域和跨字段约束。
3. **替换凭据**：在结构上把凭据引用替换成值，然后把第 2 步的检查再跑一遍。

### 2.5 运行时的暴露面

- **endpoint 的入站一律拒绝**：
  - tailscale、openconnect、wireguard 会把对端发往本端隧道地址的连接，改写成发往 127.0.0.1，再交给路由。wireguard 的判定范围是整个本端地址段。
  - 所以编译生成的路由规则和 DNS 规则，第一条都是 `{"inbound": [所有 endpoint], "action": "reject"}`。
  - DNS 那条挡的是 tailscale peerapi 的 DoH：同一用户的其他设备能经它让本机解析域名。
- **tailscale 去掉不经过路由的能力**：构建时加上以下 tag。全部加上之后 `protocol/tailscale` 能编译，已实测；运行行为在 M3 验证。

  | tag | 去掉什么 |
  |---|---|
  | `ts_omit_peerapiserver` | peerapi，其中 `/v0/env` 会返回进程的环境变量和参数 |
  | `ts_omit_c2n`、`ts_omit_debug` | 控制端到节点的调试和 pprof 通道 |
  | `ts_omit_portmapper` | 网关上的 UPnP、NAT-PMP、PCP 端口映射 |
  | `ts_omit_logtail`、`ts_omit_netlog` | 写进 state 目录的明文日志，里面有登录链接和注册错误 |

  - 要用 `exit_node`，就不能去掉 peerapi 的客户端（`peerapiclient`、`useexitnode`）。
  - 这个 fork 已经关掉了日志上传。
- **tailscale 控制端去不掉的权力**：控制端能经 `Debug.Exit` 让进程直接退出。所以 `control_url` 指向谁，就信任谁。`xdial tailscale login` 要显示控制端地址。

### 2.6 第二道防线

只是兜底，不替代 2.2 到 2.4：

- **拒绝一切的 `SecurityPolicy`**：sing-box 在 tor `executable_path`、tailscale `ssh_server`、NTP `write_to_system` 三处会查询它。
- **受限的 `filemanager`**：只放行 XDial 生成的那几个确切路径，即订阅和规则集缓存、tailscale state 目录，不放行凭据文件。
  - TLS 和 SSH 的 `*_path` 经它读取。
  - openconnect 的路径字段由协议库直接读，tsnet 也直接用 os 写文件，都不经过它。

### 2.7 崩溃

- **上游不兜底**：sing-box 在构造和运行时都可能 panic，上游在这些路径上都没有 recover。2.3 的值域校验是第一道防线。
- **daemon 自己兜一层**：daemon 调 `box.New` 和 `Start` 的地方加 recover。
- **兜不住的情况**：运行时 goroutine 里的 panic 兜不住，进程会退出；tailscale 控制端也能让进程退出。
- **sing-box 放在哪个进程**：在 daemon 进程里跑，还是放进子进程，由 daemon 监管、子进程崩了 daemon 照样能回应 API，在 M2 定。两种做法下，带凭据的配置都不写盘，子进程的话经管道传。

## 3. 编译生成的部分

下面这些现在就定。带"编译 PR 定"的，在 M1 编译配置的 PR 里定，同样属于高风险。

### 3.1 编译范围

- **只编译当前场景用得到的对象**：只编译当前场景能到达的线路、组和规则集。场景用不到的线路不会被实例化，例如 tailscale 线路，没被用到就不会上线。
- **apply 时的检查范围**：每个场景单独编译检查一次，所有对象再整体检查一次，保证用不到的线路也经过检查。
- **入站**：TUN（M2）和 `mixed`（只监听回环）。

### 3.2 路由规则的顺序

1. endpoint 的入站一律拒绝（2.5）。
2. 嗅探和 DNS 接管（hijack-dns）。
3. VPN 推送的网段和域名，用 `preferred_by` 匹配对应的 endpoint。它和场景规则谁在前，在 M3 定。
4. 场景规则，然后是 `final`。

### 3.3 DNS

- **不能配置**。
- **原则**：先按场景确定目标走哪条线路，再经这条线路解析。
  - `direct` 用系统 DNS。
  - 代理线路经它自己解析；线路自己服务器的域名，经系统 DNS 或它的 `detour` 链解析。
  - endpoint 线路用它对应的 DNS server 类型（`openconnect` / `tailscale`），解析 VPN 推送的域名和 Tailnet 名字。
- **编译 PR 定**：
  - 具体的 DNS 规则；
  - 目的地是域名（例如来自 `mixed` 入口）时，IP 类规则集要不要先解析、经哪个 DNS 解析；
  - 私有地址和局域网流量默认走哪里。
- **不悄悄加规则**：编译不悄悄加"私有地址直连"这类规则。公司网段多半也是私有地址。

### 3.4 资源下载

远程规则集和订阅都由 daemon 自己下载，不交给 sing-box。

- **为什么不交给 sing-box**：
  - sing-box 的下载器会跟随 https 到 http 的重定向，而且没有开关可以关；
  - 它在 endpoint 上线之前就要下载完；
  - 它的 `download_detour` 在 1.14 已经弃用。
- **只走 https**：每一跳都必须是 https。
- **经哪条线路**：经 `download_via` 指定的线路拨号。
  - 已经连接时，用运行中实例的这条出站；没连接时，用一个只含这条线路链、绑定物理接口的临时实例。
  - `download_via` 不能是 endpoint，也不能经组或 `detour` 到达 endpoint，因为临时实例会多起一个 tailscale 节点或 VPN 会话。
- **怎么交给 sing-box**：下载结果放进缓存，编译成 XDial 生成的 `local` 规则集，路径在 daemon 自己的目录里。
- **没缓存又下载失败**：连接失败，不悄悄换成直连。
- **编译 PR 定**：更新之后怎么生效。

## 4. 存放与修改

### 4.1 配置

- **谁持有**：配置由 daemon 持有，存为数据目录里的 `config.json`，root 所有，权限 0600。
- **怎么读写**：CLI 和 App 只通过本地 API 读写。
  - `xdial config export` 导出；`xdial config apply <文件> [--dry-run]` 提交。
  - 文件由 CLI 以调用者的身份读取，API 只接收内容，daemon 不打开调用方给的路径。
  - 提交的内容有大小上限，正则的数量和长度也有上限，数值在实现时定。
- **注释**：输入可以带注释和尾逗号。daemon 保存 XDial 规范化后的 JSON，不保留注释。
- **revision**：
  - 每份配置有一个 revision，即规范化内容的摘要。规范化由 XDial 自己定义，不依赖 sing-box 的序列化，升级 sing-box 不会让 revision 无故变化。
  - `export` 输出 revision；`apply --if-match <revision>` 在配置已被别人改过时拒绝。App 每次都带。
- **apply 是整份替换**：
  - 先完整校验：第 2 节的全部检查，加上 3.1 的编译检查，用的是 `box.New` 加 `Close`，凭据用占位值（4.4）。全部通过才原子写入；任何一项失败，现有配置都不动。
  - `--dry-run` 输出：和现有配置的差异、受影响的场景、缺少的凭据、凭据引用的变化（4.2）。
- **连接中 apply**：
  - 当前场景受影响时，先用新配置重载，成功才写入。重载失败就恢复旧配置继续运行，apply 报错，配置不变。
  - 不允许删掉当前场景，要先切到别的场景。
  - selector 手选的成员被删掉时，回到组的默认值。
- **缺凭据**：引用了还没设置的凭据，可以 apply，输出里列出缺哪些。真正连接、或者切到用到它的场景时，才因为缺凭据而拒绝。
- **版本和回退**：
  - `version` 只增不减。daemon 拒绝读比自己新的版本；比自己旧的版本在读入时迁移，每个迁移都有测试。
  - 升级 sing-box 时，上游弃用的字段也由版本迁移改写。
  - 分类表新增用户可写的字段时，`version` 必须加一，旧 daemon 才能认出这是新格式。
  - 迁移后写回之前，原文件保留为 `config.v<旧版本>.json`。退回旧版之后，daemon 遇到比自己新的版本，就改用和自己版本对应的副本，新版本的文件保留不删，并在状态里说明。这一点对应 [方案 §4.6](docs/plan.md#46-安装更新卸载) 的回退要求。
  - 回退之后的修改写到哪里、再次升级时怎么合并，在实现版本迁移时定。
- **变更档位**：格式和分类表的变更都属于高风险。

### 4.2 凭据的原则

- **凭据和配置分开**：配置里只有凭据引用。
- **只写不读**：本地 API 和 CLI 都没有读出凭据值的接口。
- **入口**：值只经本地 API 进入 daemon，来源有：
  - `secret set`，值来自 CLI 的 stdin、App 的安全输入框，或者导入旧库；
  - `xdial tailscale login` 的 auth key，用完不保存；
  - 订阅节点自带的凭据，见 1.5。
- **值不出现在别处**：
  - 带真值编译或连接时，sing-box 和依赖库给出的错误原文不透传给调用方，调用方只拿到字段路径和错误码。原文只写进 root 专属的诊断日志。
  - 原文里的凭据值尽量替换掉，包括转义、URL 编码、base64 等形式。但这只是兜底：有些错误只带出值的一部分，不一定都替换得到。
  - sing-box 的日志级别默认不开 debug 和 trace。
  - 运行时才拿到的敏感信息，例如 tailscale 的登录链接、AnyConnect 的会话 cookie，同样按凭据对待，只交给发起登录的调用方，不写进日志。
- **不写盘**：带凭据的编译结果不写盘。调试用的编译输出，把凭据换成占位符。
- **只写不读的边界**：
  - 它挡的是无意的泄露：日志、导出、AI 的对话记录、共享屏幕。
  - 它挡不住有权提交配置的人：把凭据引用填进一条指向自己服务器的线路，或者改掉 `detour` 链、关掉 TLS 校验，连接时凭据就发出去了。
  - 所以 M2 授权时，提交配置和设置凭据按同一级别管。
  - `--dry-run` 和 apply 的输出会列出凭据引用的变化（谁在引用、发往哪里），供人核对。
  - 更强的约束在 M2 和授权一起设计。可能的做法包括：
    - 确认必须带上 dry-run 给出的摘要；
    - 流向要覆盖整条 `detour` 链和 TLS 校验设置。

### 4.3 凭据的存放

- **位置**：daemon 数据目录下一个 root 专属的子目录（0700），凭据存在其中的 `secrets.json`（0600）。
  - 订阅和规则集缓存、tailscale 的 state 目录也放在这个子目录里。
  - 写入用临时文件加 rename，原子替换，权限保持不变。
- **备份**：整个子目录排除出 Time Machine；磁盘层面靠 FileVault。
- **换机后要重新设置**：
  - 从备份恢复之后，配置还在，凭据需要重新设置。`xdial secret list` 会列出缺哪些。
  - 【推断】用迁移助理直接从旧 Mac 迁过来时，也会跳过这个子目录。
  - 排除是否生效、迁移助理是否跳过，都在 M2 实测。
- **为什么不用钥匙串**：
  - 系统钥匙串：root 照样能读，还要用 cgo。它多出的保护在备份和磁盘层面，而这两层已经由"排除备份"和 FileVault 承担。
  - 用户钥匙串：daemon 重启后要等用户端补交凭据，和"daemon 持有一切"冲突。

### 4.4 凭据引用和校验

- **写法**：`{"secret": "<名字>"}`，名字的规则同 id。
- **能写在哪**：只能写在分类为"凭据"或"可为凭据"的字段，以及订阅和远程规则集的 `url` 里。
- **一个凭据可以被多处引用**。
- **格式校验**：每个凭据字段登记一个格式校验器。
  - `secret set` 时，按这个凭据现有的所有引用方校验格式；apply 时，对已设置的凭据按新的引用方再校验。报错不带值。
  - 不能依赖 sing-box 来校验：tuic 报错时会把原值带进错误信息。
  - vmess 和 vless 的 `uuid` 接受任意非空字符串：sing-box 会把非 UUID 的值映射成 UUIDv5，以兼容 Xray。
- **占位值**：
  - apply 的 sing-box 检查用格式合法的占位值，不用真值。
  - 占位值按关联字段成组生成：证书和私钥一起换，ss2022 的密码按 `method` 生成。
  - 只能用真值做的检查（证书和私钥是否配对等），由 XDial 在 `secret set` 和连接时自己做，报错不带值。

### 4.5 命令

本地 API 提供同样的三个操作，没有读取凭据值的接口。

| 命令 | 作用 |
|---|---|
| `xdial secret set <名字>` | 从 stdin 读值。stdin 是终端时关闭回显；只去掉末尾的一个 `\n` 或 `\r\n`。输出这个凭据当前被谁引用、发往哪里 |
| `xdial secret list [--json]` | 列出名字、是否已设置、更新时间、被哪些对象引用；也列出被引用了但还没设置的名字 |
| `xdial secret rm <名字>` | 删除凭据；仍被引用时拒绝，提示里列出引用方 |

### 4.6 各类凭据

| 凭据 | 处理 |
|---|---|
| 代理线路的密码、uuid 等 | 凭据引用 |
| AnyConnect 的密码、cookie、TOTP 种子 | 凭据引用。需要浏览器登录的方式，在 M3 定 |
| 订阅 URL | 凭据引用。拉下来的节点进订阅缓存，不进配置 |
| Tailscale auth key | 只在 `xdial tailscale login` 时从 stdin 读一次，用完不保存。登录要重载一次 sing-box，现有连接会断一次 |
| Tailscale 登录状态（节点密钥） | sing-box 写在 root 专属子目录里，不复制，也不导出 |

### 4.7 导入和种子配置

- **导入旧配置库**：
  - 由用户身份的 CLI 读旧库 `~/.xdial/configuration/profiles.enc`，密钥在用户的钥匙串里。读出后转成新格式，再通过本地 API 交给 daemon：配置走 apply，凭据走 `secret set`。
  - root daemon 不读用户的钥匙串。
  - 旧文件不写回，也不删除。
  - 旧版的部分绑定（`condition_ids`）和交错顺序（`match_order`）拆成多个规则集；取反用场景规则的 `invert`。
  - 表达不了的部分整体报错并列出，不悄悄丢掉，例如规则集里不支持的条件、HOTP。
  - 导入在 M6 实测。
- **种子配置**：只含配置，不含凭据。

## 5. 留给后面的

- **M1 编译 PR**：
  - DNS 规则的细节；
  - 域名目的地是否先解析；
  - 私有地址的默认去向；
  - 规则集更新后怎么生效；
  - 分类表和允许清单的包路径。
- **M2**：
  - 数据目录的具体路径，Debug 和正式版怎么分开；
  - sing-box 放在 daemon 进程里还是子进程里，以及连续崩溃时怎么办；
  - 本地 API 怎么核验调用方身份，提交配置和设置凭据同级，凭据流向的强约束也在这时设计；
  - launchd 的 stdout 和 stderr 放在 root 专属位置，因为 panic 会写到那里；
  - Time Machine 排除和迁移助理的实测。
- **M3**：
  - 订阅节点怎么被线路组和场景引用；
  - VPN 推送的规则和场景规则谁在前；
  - AnyConnect 需要浏览器登录时怎么办；
  - tailscale 那些 `ts_omit_*` tag 加上之后，运行行为是否正常；
  - `exit_node` 算配置还是运行状态；
  - 当前场景用不到的 tailscale 线路怎么登录。
