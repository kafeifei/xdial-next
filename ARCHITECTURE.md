# 架构

本文记录已经定下、据以实现的架构。还没写到这里的部分，以 [方案](docs/plan.md) 为准。

组件和所有权见 [AGENTS.md 的边界](AGENTS.md#边界)。这里先写配置和凭据，2026-10-27 与用户对齐；本地 API、数据面等在 M2 补上。

**核实依据**

- 对 sing-box 的说法，对照 v1.14.0-beta.2 和它依赖的 sagernet/tailscale fork 的源码核实过。
- 有几处实际编译、运行过：`ts_omit_*` 构建 tag、非 PEM 证书引发的 panic、负时长引发的 panic。
- sing-openconnect 和 sing-quic 的源码不在本地，要靠它们的结论都没有核实。
- 标【推断】的结论是从代码或文档推出来的，没有实际运行过。

## 1. 配置格式

### 1.1 原则

- **只描述三件事**：线路怎么连、匹配什么、场景怎么绑。
- **原生对象**：线路、线路组、规则集都直接写 sing-box 的原生对象。`tag` 换成 `id`，可以再加一个显示用的 `name`。XDial 自己只增加场景、凭据引用和少量全局项。
- **凭据不进配置**：凭据字段只能写成引用。配置可以 diff，也可以交给 AI 读。但它含有服务器地址、用户名和内部域名，"可为凭据"类字段（2.4）也允许写明文，分享之前要自己看一遍。
- **不含运行状态**：当前场景、selector 手选的成员由 daemon 另存，切场景不改配置。
- **配置是 root 权限的边界**：提交配置的人能做什么、不能做什么，见第 2 节。

### 1.2 示例

```jsonc
{
  "version": 1,
  "mixed": { "port": 7890, "username": "me", "password": { "secret": "mixed" } },
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
| `mixed` | 本机 SOCKS / HTTP 入口，即 sing-box 的 `mixed` 入站：`port`、`username`、`password`；不写就不开 | 只监听回环地址，端口不小于 1024；用户名和密码必填，密码是凭据引用；`set_system_proxy` 等其余字段由 XDial 生成 |
| `lines` | sing-box 的出站或 endpoint 对象，类型必须在线路允许清单里（2.3） | `detour` 只能指向线路或线路组 |
| `groups` | sing-box 的 `selector` 或 `urltest` | `outbounds` 只能指向线路或线路组；selector 的 `default` 必须是自己 `outbounds` 里的成员 |
| `rule_sets` | `inline`，或 `remote` | 不允许 `local`（读本机文件），本地规则写成 `inline`。`remote` 由 daemon 自己下载（3.4）：`url` 只能是 https，可以是凭据引用；`download_via` 指定经哪条线路下载，不写则走 `direct` |
| `scenarios` | `rules`：有序的规则列表，每条是 `{"rule_set", "line", "invert"?}`；`final`：其余流量走的线路 | 场景里不能写匹配条件，匹配只写在规则集里；`final` 必填 |
| `subscriptions` | 订阅来源：`url`，以及 `download_via` | `url` 必须是凭据引用，只能是 https；其余字段在 M3 定 |

- **`mixed` 为什么必须带认证**：
  - 它和 TUN 一样走当前场景，包括 VPN 和 tailnet 线路。连接时 TUN 本来就接管整机所有进程的流量，所以对本机进程来说，`mixed` 没有多给网络位置。
  - 它多出来的是一个按请求里的主机名转发的代理入口。【推断】网页经 DNS 重绑定，可以让浏览器把请求发到它这里，再由它解析出内网地址、经 VPN 转发，网页还能读到响应。
  - 必填的认证挡住这条路：网页的请求不能自己加 `Proxy-` 开头的头（Fetch 规范禁止），也说不了 SOCKS；本机其他用户不知道密码也连不上。
  - 用户名和密码由用户自己设置，所以"只写不读"不妨碍用户把它们配进要用代理的程序。
- **XDial 自己的键**：`id`、`name`、`download_via`、`invert`、凭据引用。
  - 它们在交给 sing-box 之前就被剥离，永远不进入原生选项。
  - 和这些键同名的原生字段（如 openconnect、wireguard 的系统接口名 `name`）因此无法设置，它们本来就属于禁止类。
  - 测试保证 XDial 的键不会遮住任何普通字段或凭据字段。
- **`invert`**：对规则集的匹配结果取反，编译成 sing-box 路由规则的 `invert`，用来表达旧版的"海外 IP = 国内 IP 取反"。
  - IP 类规则集遇到还没解析的域名目的地时，判为"没匹配上"，取反后反而成立。所以它的语义依赖 3.3 里"域名目的地是否先解析"的决定。

### 1.4 id 和引用

- **id 的格式**：由小写字母、数字和连字符组成，以字母或数字开头，最长 63 个字符。
- **命名空间**：线路和线路组共用一个，因为它们都会被当作出口引用。规则集、场景、订阅、凭据各自一个。
- **内置线路**：`direct` 和 `block` 是 XDial 内置的，名字保留。
  - `direct` 编译成直连出站。
  - `block` 编译成路由规则的 `action: reject`，只能当场景规则的目标或 `final`。
- **生成的 tag**：编译生成的 tag（入站、DNS server、订阅节点等）都带 `xdial:` 前缀。这个前缀在 id 的字符集之外，不会撞名。
- **XDial 自己检查引用**：引用都要存在；`detour` 和组成员合起来不许成环；所有 tag 不许重名。sing-box 在这几件事上都靠不住：
  - 环要到启动时才查出来，`sing-box check` 查不出；
  - 直接用结构体构造配置时，重复的 tag 会被静默替换；
  - selector 的 `default` 不合法时，如果缓存里有手选值，会被静默接受。

### 1.5 订阅节点

- **不进配置**：从订阅拉下来的节点是派生数据，放在 daemon 的订阅缓存里，不写进配置。
- **过同一套分类**：节点要过订阅节点的允许清单和同一份字段分类（2.3、2.4），另外再收紧三条：
  - 只允许代理协议，不允许 endpoint；
  - 不允许 `detour`；
  - 不允许凭据引用，否则恶意订阅就能把用户已设置的凭据引到自己的服务器。
- **节点自带的凭据**：凭据字段在缓存里可以是明文，按凭据对待，存放见 4.4，也不出现在任何输出里。
- **留到 M3**：线路组和场景怎么引用订阅节点。

### 1.6 第一版表达不了的

- **规则条件不全**：规则集里的规则没有 `protocol`、`ip_is_private` 这类条件，"BT 直连""拦截 QUIC"这类需求表达不了。
- **AnyConnect 的一次性密码**：只支持 TOTP，不支持 HOTP。sing-box 只把 HOTP 计数器放在内存里，重载后会回到配置里的值，导致重复使用已经用过的密码。

## 2. 安全边界

### 2.1 目标

不可信的输入有两类：

- **提交配置的人**：
  - 能提交配置，不等于能让 root daemon 读写本机文件或 socket、执行程序、开固定端口或提供未认证的入站服务（带认证、只监听回环的 `mixed` 入口是明确的例外，见 1.3）、创建或修改系统接口/路由/DNS/系统代理、改动网关（端口映射）、使用 root 专属的能力，或者把本机暴露给远端。
  - 凭据是例外：能提交配置的人能使用凭据，见 4.3。
- **远端输入**：
  - 包括规则集内容、订阅内容、tailscale 控制端，以及 VPN 服务端推送的配置。
  - 它们和配置一样不可信，要做同样的限额。
  - 它们不能让 daemon 崩溃，也不能留下系统残留。

### 2.2 进程结构

- **sing-box 跑在子进程里**：子进程由 daemon 监管，是同一个 `xdial` 二进制的子命令，daemon 进程里不跑 sing-box。理由如下：
  - **崩溃隔离**：sing-box 在构造和运行时都可能 panic，上游不 recover。例如证书内容不是合法 PEM，`box.New` 时就 panic：`common/tls/std_client.go:190` 把 `[]byte` 交给 sing 的 `F.ToString`，后者对不认识的类型直接 panic。urltest 的时长写成负值，第一次有流量时 panic。tailscale 控制端也能经 `Debug.Exit` 让进程直接退出。这些都只会带走子进程，daemon 照样回应 API，并报告原因。
  - **日志在进程边界过滤**：sing-box 自己会把敏感信息写进日志，例如 tailscale 登录链接用的是 Info 级别（`protocol/tailscale/endpoint.go:521`）。进程内没有不带副作用的截获入口，所以子进程的日志经管道交给 daemon，脱敏之后再分发，见 4.3。
- **子进程死了**：daemon 退避后重启它；连续崩溃就停下并报告，不反复重连。【推断】TUN 接口随子进程退出而消失，挂在它上面的路由一并消失；M2 实测有没有残留。
- **交给子进程的内容**：
  - XDial 组装、规范化之后的 sing-box 配置，经管道传，不写盘。
  - 由 XDial 自己序列化，字符串经 `encoding/json` 转义。
  - 子进程用同一个受限 registry 解析（2.3），解析的始终是 XDial 生成的内容，不是用户原文。sing-box 的类型化解析只在子进程里发生。
- **一次性子进程**：下载、二进制规则集转换和离线检查也在一次性的子进程里做，见 3.4 和 4.2。
- **M2 落实**：子进程的启动方式和管道协议。

### 2.3 XDial 组装 sing-box 配置

- **用户只提供三类对象**：用户配置只贡献线路、线路组、规则集。sing-box 配置的其余部分都由 XDial 生成，包括入站、DNS、路由、`experimental`、`ntp`、证书、`http_clients`、日志级别等。
- **受限 registry**：
  - 子进程用 `box.Context` 传入自己构造的 registry，只注册允许清单里的类型，以及 XDial 生成配置要用到的类型，不注册任何 service。
  - 上游的 `include` 无条件注册了 tor、bridge、snell 等类型，以及 api、ssmapi 等服务。不用它，这些东西就从根上进不来。
  - registry 里必须有 direct、selector、urltest 等类型，所以 registry 不能代替允许清单。
- **允许清单**：按用途分开。新增类型属于高风险改动。

  | 用途 | 第一版允许的类型 |
  |---|---|
  | 线路 | `shadowsocks`、`vmess`、`vless`、`trojan`、`anytls`、`openconnect`（`flavor` 只能是 `anyconnect`）、`tailscale` |
  | 线路组 | `selector`、`urltest` |
  | 订阅节点 | 线路清单里的代理协议，不含 endpoint |

  - hysteria2、tuic、http、socks、ssh、wireguard 等以后按需加。
  - **依赖没有源码的库的字段，先禁止**：有些可选字段的语义只在本地没有源码的库里才能确认，例如 openconnect 的 `csd`、`hip`、`tncc`、`fortinet_host_check`、`mobile`、`form_entries`，以及 `token` 除 `totp` 以外的模式。这些先禁止，核实之后再开放。
- **构建 tag**：
  - 不用 `include` 之后，`with_openconnect`、`with_tailscale` 只控制 `include/` 下的文件，管不到 XDial 自己的 registry。
  - `with_quic` 还控制 QUIC 传输层和 HTTP/3。第一版不加它，也就不支持 QUIC 类的传输。
  - 真正起作用的有：
    - `with_gvisor`：tailscale 和 gVisor 栈需要；
    - `with_utls`：reality 和 uTLS 需要；
    - `with_dhcp`：macOS 上 TUN 开着时，`local` DNS 要靠它查询 DHCP 下发的服务器（3.3）；
    - 2.6 列出的 `ts_omit_*`。

### 2.4 字段分类

允许的每种类型，它的每个字段都必须登记在分类表里。XDial 自己的对象也一样，例如 `mixed` 的 `port`、`username` 是普通字段，`password` 是凭据字段。

| 类 | 含义 | 例子 |
|---|---|---|
| 普通 | 用户直接写 | `server`、`server_port`、`tls.server_name`、tailscale 的 `control_url`、`exit_node` |
| 凭据 | 必须写成凭据引用，写明文直接拒绝 | `password`、`uuid`、openconnect 的 `cookie` 和 `token.secret`、`mixed.password` |
| 可为凭据 | 明文和凭据引用都接受 | 传输层 `headers` 的值 |
| XDial 生成 | 由 XDial 统一生成，配置里出现就拒绝 | `tag`；`tls.engine`（固定为 go）；tailscale 的 `state_directory`、`auth_key`；dialer 里选择接口、地址或 DNS 的字段，如 `bind_interface`、`inet4_bind_address`、`domain_resolver`、`network_strategy` |
| 禁止 | 2.1 列出的那些能力，配置里出现就拒绝 | 见下 |

**禁止类的例子**

- **读文件**：各种 `*_path`（证书、密钥、`token.secret_path`、`initial_path`）。
- **执行程序**：openconnect 的 `wrapper_path`。
- **交出 socket**：dialer 的 `protect_path`，它会把每个连接的 socket 交给这个 Unix socket 的监听者。
- **使用 root 专属能力**：`tls.spoof`，它要用原始套接字。
- **建接口、开端口、动网关**：
  - `system`、`listen_port`、`dtls_local_port`、`system_interface`、`relay_server_port`；
  - hysteria2 的整个 `realm`：里面的 `port_mapping` 会在网关上做端口映射，它还带着完整的 dialer 选项，而且会打洞。
- **对外开放本机**：tailscale 的 `ssh_server`、`advertise_routes`、`advertise_exit_node`、`advertise_tags`。
- **其他**：所有已弃用的字段。

**登记规则**

- **按字段登记，不猜名字**：分类按字段逐个登记，不按字段名去猜。比如规则里的 `process_path` 是匹配条件，属于普通字段；证书的 `certificate_path` 会读文件，属于禁止。
- **值域和约束**：每个字段同时登记值域，跨字段的约束单独登记。例如：
  - 时长写了就必须为正。这一条在原始 JSON 上检查，因为解析之后 0 和"没写"分不开。
  - 证书和密钥必须是能解析的 PEM。
  - ss2022 的密码长度要和 `method` 对得上。
  - 值域校验是防 panic 的第一道防线，子进程是第二道。
- **map 类字段**：如 `headers`，键是数据，不是字段名，按值域登记。
- **字符串里的第二层语法**：有些字段的值本身就是另一种配置语法，例如 shadowsocks 的 `plugin_opts`，`v2ray-plugin` 的 `cert` 会读文件。
  - 这类字段用上游自己的解析函数（如 `sip003.ParsePluginOptions`）拆开，再逐键登记，没登记的键一律拒绝。
  - 做不到逐键登记的，整个字段禁止。
- **证书和密钥写内联**：需要证书或密钥时，用内联内容写；属于凭据的，写成凭据引用。
- **包路径**：分类表和允许清单在 `internal/config/fields.go`，受限 registry 在 `internal/engine/registry.go`，构建 tag 在 `.github/build-tags.txt`。`cmd/`、`internal/` 和 `.github/` 都属于高风险档。

**覆盖测试**

- 字段从反射和 sing-box 自带的 schema 两边枚举。只看反射会漏掉用 `json:"-"` 声明、靠合并解析的变体字段；只看 schema 会漏掉标了 `schema:"omit"` 的弃用字段。
- 升级 sing-box 时出现了没登记的字段，测试就失败，必须先分类才能升级。
- 测试管不到字符串里的第二层语法，升级 sing-box 时要人工审查。

### 2.5 校验的顺序

都在 `box.New` 之前完成。`box.New` 构造协议时就会读文件，也可能 panic。

1. **XDial 自己严格解析原文**：允许注释和尾逗号；键名必须是登记过的，大小写完全一致；不许重复键；禁止类和 XDial 生成类的键只要出现就拒绝。
   - 解析的结果重新序列化成规范 JSON。之后的每一步只碰这份规范 JSON，不再碰原文，也就不存在"检查看到的键"和"实际生效的键"不一致的问题。
   - 这一步不能交给 sing：它的 JSON 解析器在键名精确匹配不上时，会按大小写折叠再匹配一次，`Certificate_Path`、甚至 `ſsh_server`（U+017F）都会生效。
2. **检查值域和跨字段约束**：在 XDial 自己的树上按分类表登记的值域检查，再检查跨字段约束。然后剥离 XDial 自己的键，生成规范 JSON；sing-box 的类型化解析在检查子进程里用受限 registry 做，主进程不碰。
3. **替换凭据**：在 XDial 的树上把凭据引用替换成值，不做文本替换，再按凭据字段登记的格式校验器检查真值。相关真值都齐全时，跨字段的真值检查在这一步做；缺凭据的，留到连接时再查。

### 2.6 运行时的暴露面

- **endpoint 的入站请求一律拒绝**：
  - tailscale、openconnect、wireguard 会把对端发往本端隧道地址的连接，改写成发往回环地址（127.0.0.1 或 ::1），再交给路由。wireguard 的判定范围是整个本端地址段。
  - 所以编译生成的路由规则和 DNS 规则，第一条都是 `{"inbound": [所有 endpoint], "action": "reject"}`。DNS 那条挡的是 tailscale peerapi 的 DoH，它会让同一用户的其他设备经本机解析域名。
  - 协议栈自己对本端地址的 ICMP echo 照常回应。目前没有证据表明这条路径能碰到本机的 TCP / UDP 服务。
- **tailscale 去掉自己终结的服务**：tailscale 自己终结的服务不经过 sing-box 的路由，上面的拒绝规则管不到，所以构建时一律去掉。

  | tag | 去掉什么 |
  |---|---|
  | `ts_omit_peerapiserver` | peerapi，其中 `/v0/env` 会返回进程的环境变量和参数 |
  | `ts_omit_c2n`、`ts_omit_debug` | 控制端到节点的调试和 pprof 通道 |
  | `ts_omit_portmapper` | 网关上的 UPnP、NAT-PMP、PCP 端口映射 |
  | `ts_omit_logtail`、`ts_omit_netlog` | 写进 state 目录的明文日志，里面有登录链接和注册错误 |
  | `ts_omit_ssh`、`ts_omit_webclient`、`ts_omit_drive`、`ts_omit_taildrop` | 其他由 tailscale 自己终结的服务 |

  - 上面这些和 `with_gvisor`、`with_utls` 一起加上之后，`protocol/tailscale` 能编译，已实测。运行是否正常，在 M3 验证。
  - serve 去不掉：加上 `ts_omit_serve` 后，tsnet 自己就编译不过（它直接调用 serve 的接口）。serve 要本地设置了 serve 配置才会生效，XDial 不提供设置它的途径，C2N 也已去掉。M3 要验证它确实没有开启。
  - 要用 `exit_node`，就不能去掉 peerapi 的客户端（`peerapiclient`、`useexitnode`）。
  - 日志不会上传：这个 fork 的 `envknob.NoLogsNoSupport()` 恒为 true。
- **tailscale 控制端去不掉的权力**：控制端能经 `Debug.Exit` 让进程直接退出，好在退出的只是子进程。所以 `control_url` 指向谁，就信任谁。`xdial tailscale login` 要显示控制端地址。

### 2.7 第二道防线

只是兜底，不替代前面几节：

- **拒绝一切的 `SecurityPolicy`**：sing-box 在 tor `executable_path`、tailscale `ssh_server`、NTP `write_to_system` 三处会查询它。
- **受限的 `filemanager`**：只放行 tailscale state 目录的创建，以及 XDial 生成的 cache file（如果用），不放行凭据文件。
  - TLS、ECH、SSH 和规则集的文件读取都经过它。
  - openconnect 的路径字段由协议库直接读，tsnet 也直接用 os 写文件，都不经过它。

## 3. 编译生成的部分

下面这些现在就定。编译器的实现变更同样属于高风险。

### 3.1 编译范围

- **只编译当前场景用得到的对象**：只编译当前场景能到达的线路、组和规则集。场景用不到的线路不会被实例化，例如 tailscale 线路，没被用到就不会上线。
- **检查时编译全部**：每个场景单独编译检查一次，所有对象再整体检查一次，保证用不到的线路也经过检查。
- **入站**：TUN（M2）和 `mixed`（只监听回环、带认证，见 1.3）。

### 3.2 路由规则的顺序

1. endpoint 的入站请求一律拒绝（2.6）。
2. 嗅探，然后接管 DNS（hijack-dns）。
3. 解析域名目的地（`resolve` 动作）。它只处理目的地是域名的连接，例如来自 `mixed` 入口的；TUN 进来的连接目的地已经是 IP，不受影响。解析按 3.3 的 DNS 规则走。这样 IP 类规则集对域名目的地也能命中，`invert` 的语义也不会被"没解析"带偏。解析失败（例如域名不存在）时连接直接失败。
4. 场景规则。`block` 编译成 `action: reject`。
5. VPN 推送的网段和域名，用 `preferred_by` 匹配对应的 endpoint。
   - 放在场景规则之后：VPN 服务端推送的内容是远端输入（2.1），不能盖过用户写下的规则，包括 `block`。它最多只能接管原本会落到 `final` 的流量。
   - 已知的信任假设：线路上线后，服务端推送 `0.0.0.0/0` 或很宽的域名后缀，就能接管全部 `final` 流量。sing-box 的 `preferred_by` 没有过滤推送内容的接口，不打补丁就做不了限额。M3 实测推送的实际形态后，再决定要不要由 XDial 自己读取推送、过滤后改写成普通规则。
   - 推送内容的变化写进事件日志；`xdial explain` 标明命中的是推送规则（M4）。
6. `final`。

### 3.3 DNS

- **不能配置**。
- **原则**：先按场景确定目标走哪条线路，再经这条线路解析。
  - 只对靠域名条件决定线路的流量成立。靠 IP 条件决定的流量，要先解析才知道走哪条线，解析只能发生在决定之前：用 `final` 线路对应的 DNS server；`final` 是 `block` 时用 `local`，否则 IP 放行规则永远轮不到。
  - `direct` 用系统 DNS。
  - 代理线路经它自己解析；线路自己服务器的域名在本机经系统 DNS 解析，有 `detour` 的也一样，见下面"线路自己服务器的域名"。
  - endpoint 线路用它对应的 DNS server 类型（`openconnect` / `tailscale`），解析 VPN 推送的域名和 Tailnet 名字。
- **DNS server**：都由 XDial 生成，tag 带 `xdial:` 前缀。

  | 给谁用 | 类型 |
  |---|---|
  | `direct`，以及线路自己服务器的域名 | `local`。在 macOS 上有 TUN 入站时，sing-box 改用 DHCP 下发的 DNS 服务器，从物理接口直接查询，不经过 TUN，这要构建 tag `with_dhcp`。没有这个 tag，或者还没从 DHCP 拿到可用的服务器（没有 DHCPv4、超时），都会退回 mDNSResponder，查询可能被 TUN 再截回来。另外，它会主动发 DHCP 请求，用户手动配置的 DNS 可能因此被忽略。这几种情况都在 M2 实测 |
  | 代理线路和线路组 | `https`，服务器 `1.1.1.1`，`detour` 指向这条线路或组 |
  | openconnect、tailscale 线路 | 对应的 `openconnect`、`tailscale` 类型，只用来解析 VPN 推送的域名和 Tailnet 名字（下面第 2 条）。它们不当通用解析器：没有下发默认解析器时，未匹配的域名一律返回 NXDOMAIN。被场景规则或 `final` 选中 endpoint 线路的其余域名，第一版用 `local` 解析。这样功能可用，代价是这些查询经本地网络发出；全隧道 VPN 和 exit node 下怎么让它们也走隧道，M3 实测后再定 |

- **系统 DNS**：连接期间由 daemon 把系统 DNS 指到 TUN 里，否则查询可能根本不进 TUN，见 6.4。
- **DNS 规则的顺序**：
  1. 从 endpoint 进来的查询一律拒绝（2.6）；`_dns.resolver.arpa` 一律返回 NXDOMAIN，挡住加密 DNS 的自动升级（6.4）。
  2. 场景规则：从每个规则集里只取纯域名条件的规则（`domain`、`domain_suffix`、`domain_keyword`、`domain_regex`，以及只由它们组成的逻辑规则），编成 DNS 专用的规则集，交给这条场景规则所选线路对应的 DNS server。
     - DNS 规则从不拒绝，选 `block` 的场景规则不生成 DNS 规则，拒绝只在路由阶段做。DNS 阶段看不到前面那些靠 IP、端口、进程或取反决定的规则，在这里提前拒绝，会抢在本该先命中的规则前面，让 `resolve` 失败。
     - 不能把规则集整个拿来用：sing-box 的 DNS 规则遇到 IP 条件会进入旧的匹配方式，预匹配时忽略目的 IP 条件，纯 IP 的那条分支就直接算命中，选 `block` 时会把无关域名一起拒掉。
     - 混有端口、进程等条件的规则，在 DNS 阶段判断不了，不进 DNS 规则。
     - 带 `invert` 的场景规则：规则集里全是纯域名条件时，DNS 专用规则集和原规则集等价，`invert` 原样保留；否则不生成 DNS 规则，因为对取出来的一部分条件取反，会命中本不该命中的域名。
     - 同样因为 DNS 阶段看不到那些前置规则，个别情况下解析用的线路会和实际走的线路不同，例如前面一条按进程把连接送去了代理，后面一条域名规则却决定了它经哪个 DNS 解析。
  3. VPN 推送的域名：`preferred_by` 匹配 endpoint 的 DNS server，交给它解析。和路由一样放在场景规则之后。
  4. 其余的，交给 `final` 线路对应的 DNS server；`final` 是 `block` 时交给 `local`（见上面的原则）。
- **域名关联**：DNS 开启 `reverse_mapping`，从 DNS 应答里记下 IP 和域名的对应关系。嗅探认不出域名的连接（例如 SSH）只带着 IP 进来，靠它恢复域名，域名规则和 `block` 才能命中。【推断】连接之前就被系统 DNS 缓存住的应答拿不到映射；连接时要不要清一次系统 DNS 缓存，M2 实测后定。
- **线路自己服务器的域名**：线路的 `domain_resolver` 由 XDial 生成，统一用 `local`。有 `detour` 的线路也一样：本机解析出地址，再经 `detour` 拨过去。
- **私有地址和局域网**：编译不加"私有地址直连"这类规则，公司网段多半也是私有地址。【推断】本机所在子网的路由比 TUN 的路由更具体，局域网流量本来就不进 TUN；其他私有地址按场景走。M2 实测。

### 3.4 资源下载

远程规则集和订阅都由 daemon 下载，不交给 sing-box。

- **为什么不交给 sing-box**：
  - sing-box 的下载器会跟随 https 到 http 的重定向，而且没有开关可以关；
  - 它在 endpoint 上线之前就要下载完；
  - 它的 `download_detour` 在 1.14 已经弃用。
- **只走 https**：每一跳都必须是 https。
- **不访问本机和内网**：`url` 由提交配置的人决定，订阅服务器也能发重定向，不加限制的话，daemon 会替他们访问本机和内网。
  - 经 `direct` 下载时，在拨号那一层检查解析出来的目标 IP，拒绝回环、链路本地、私有、CGNAT（含 tailnet 的 100.64.0.0/10）、组播和未指定地址。
  - 每一跳重定向都在拨号时重新检查，DNS 重绑定也挡得住。
  - 经代理线路下载时，连接由代理服务器发起，打到的是代理那一侧的网络，不是本机。
  - 第一版不为内网的规则集源开例外。
  - 下载失败只返回错误码，不回显远端的内容。
- **经哪条线路**：
  - 下载在一次性的子进程里做。子进程只含 `download_via` 指定的那条线路链，绑定物理接口，绕开 TUN。
  - `download_via` 不能是 endpoint，也不能经组或 `detour` 到达 endpoint，因为下载子进程会多起一个 tailscale 节点或 VPN 会话。
- **内容是远端输入**：
  - 下载大小、规则条数、正则数量和长度都有上限。
  - source 格式由 XDial 解析、限额。
  - binary 格式要先过 XDial 自己的有界预检，再在一次性的子进程里解码成 source，然后按 source 处理。
    - sing-box 解析 binary 时，按文件里声明的长度直接分配内存，几十字节的文件就能声明巨大的长度。子进程隔离得了 panic，限不住内存。所以预检要在解码之前做：解压后的大小有上限，每个声明的长度都不能超过剩下的字节数和各自的上限。
    - 域名部分是压缩过的前缀树，转换时会把每个叶子展开成完整的域名，展开后的总长度可能远大于文件本身。预检还要检查树的结构是否自洽、最长路径、叶子数，以及展开后字符串的总长度，按总预算拒绝。
    - 转换子进程限时运行，同一时间只跑一个。
    - 畸形的匹配结构能通过构造，到匹配流量时才 panic。转换在子进程里做，最多带走那个子进程。
    - 含 AdGuard 条件的 binary 一律拒绝，报确定的错误：这类条件在 source 格式里表达不了，转换会丢掉它。
  - 结果编成 inline 规则集交给 sing-box，不经过 sing-box 的 binary 解析，也不经过它对本地文件的监视重载。
- **没缓存又下载失败**：连接失败，不悄悄换成直连。
- **更新之后怎么生效**：规则集内容变了，在下一次连接或切场景时生效，不为了更新规则集专门重载、打断现有连接。

## 4. 存放与修改

### 4.1 配置

- **谁持有**：配置由 daemon 持有，存为数据目录里的 `config.json`，root 所有，权限 0600。
- **怎么读写**：CLI 和 App 只通过本地 API 读写。
  - `xdial config export` 导出；`xdial config apply <文件> [--dry-run]` 提交。
  - 文件由 CLI 以调用者的身份读取，API 只接收内容，daemon 不打开调用方给的路径。
  - 提交的内容最大 4 MiB，最多 50 万个值。正则按编译后的指令数计：单条不超过 4096 条，整份不超过 65536 条。
- **注释**：输入可以带注释和尾逗号。daemon 保存规范 JSON，不保留注释。
- **revision**：
  - 每份配置有一个 revision，即规范 JSON 的摘要。规范化由 XDial 定义，不依赖 sing-box 的序列化，升级 sing-box 不会让 revision 无故变化。
  - `export` 输出 revision；`apply --if-match <revision>` 在配置已被别人改过时拒绝。App 每次都带。
- **apply 是整份替换**：
  - 先完整校验：第 2 节的全部检查，加上 3.1 的编译检查（在一次性子进程里调 `box.New` 再 `Close`）。全部通过才原子写入；任何一项失败，现有配置都不动。
  - 编译检查用占位：凭据用占位值（4.5）；还没有缓存的远程规则集，用一条不可能命中的 inline 规则占位。
  - `--dry-run` 输出：和现有配置的差异、受影响的场景、缺少的凭据、还没下载的规则集、凭据引用的变化（4.3）。
- **连接中 apply**：
  - 当前场景受影响时，先用新配置重载，成功才写入。重载失败就恢复旧配置继续运行，apply 报错，配置不变。
  - 不允许删掉当前场景，要先切到别的场景。
  - selector 手选的成员被删掉时，回到组的默认值。
- **缺凭据或缺资源**：可以 apply，输出里列出缺什么。真正连接、或者切到用到它的场景时，才因为缺凭据或缺资源而拒绝。
- **版本**：
  - `version` 必填，只增不减。daemon 拒绝读比自己新的版本，旧版本在读入时迁移，每个迁移都有测试。
  - 分类表新增用户可写的字段时，`version` 必须加一。
  - 迁移写回前保留旧版本的副本，满足 [方案 §4.6](docs/plan.md#46-安装更新卸载) 的回退要求。
  - 细节在做版本迁移的 PR 里定。
- **变更档位**：格式和分类表的变更都属于高风险。

### 4.2 离线检查（M1）

`xdial config check <文件>` 在没有 daemon 的情况下，检查一份配置能不能用。它不联网、不依赖 daemon、不改任何状态，以调用者的身份运行。

- **检查什么**：第 2 节的全部检查，加上 3.1 的编译检查。编译检查在一次性子进程里做。
- **怎么占位**：凭据和远程规则集一律用占位（4.1）。
- **输出**：通过与否；没法离线验证的项单独列出，例如凭据的真值、远程规则集的内容。
- **和 apply 的关系**：daemon 在 apply 时用同一份代码，在资源齐全时再做完整检查。

### 4.3 凭据的原则

- **凭据和配置分开**：配置里只有凭据引用。
- **只写不读**：本地 API 和 CLI 都没有读出凭据值的接口。
- **入口**：值只经本地 API 进入 daemon，来源有：
  - `secret set`，值来自 CLI 的 stdin、App 的安全输入框，或者导入旧库；
  - `xdial tailscale login` 的 auth key，用完不保存；
  - 订阅节点自带的凭据，见 1.5。
- **值不出现在别处**：
  - 带真值编译或连接时，sing-box 和依赖库给出的错误原文不透传给调用方，调用方只拿到字段路径和错误码。原文只写进 root 专属的诊断日志。
  - 子进程的日志经管道交给 daemon。daemon 先替换掉其中的凭据值（包括转义、URL 编码、base64 等形式），并拦下已知的敏感消息，再分发给 `xdial logs` 等出口。
    - 已知的敏感消息例如 tailscale 的登录链接，它走结构化通道，只交给发起登录的调用方。
    - 已知的泄露点都做成回归用例。
    - 值的替换只是兜底：有些错误只带出值的一部分，不一定都替换得到。
  - 子进程的日志级别由 XDial 显式设定。
  - 带凭据的编译结果不写盘；调试用的编译输出把凭据换成占位符。
- **只写不读的边界**：
  - 它挡的是无意的泄露：日志、导出、AI 的对话记录、共享屏幕。
  - 它挡不住有权提交配置的人：把凭据引用填进一条指向自己服务器的线路，或者改掉 `detour` 链、关掉 TLS 校验，连接时凭据就发出去了。
  - 所以 M2 授权时，提交配置和设置凭据按同一级别管。
  - `--dry-run` 和 apply 的输出会列出凭据引用的变化（谁在引用、发往哪里），供人核对。
  - 更强的约束在 M2 和授权一起设计。例如确认时必须带上 dry-run 给出的摘要；流向要覆盖整条 `detour` 链和 TLS 校验设置。

### 4.4 凭据的存放

- **位置**：daemon 数据目录下一个 root 专属的子目录（0700），凭据存在其中的 `secrets.json`（0600）。
  - 订阅和规则集缓存、tailscale 的 state 目录也放在这个子目录里。
  - 写入用临时文件加 rename，原子替换，权限保持不变。
- **备份**：整个子目录排除出 Time Machine；磁盘层面靠 FileVault。
- **换机后要重新设置**：
  - 从备份恢复之后，配置还在，凭据需要重新设置。`xdial secret list` 会列出缺哪些。
  - 【推断】用迁移助理直接从旧 Mac 迁过来时，也会跳过这个子目录。
  - 排除是否生效、迁移助理是否跳过，都在 M2 实测。
- **为什么不用钥匙串**：
  - 系统钥匙串：root 照样能读，还要 cgo。它多出的保护在备份和磁盘层面，已经由排除备份和 FileVault 承担。
  - 用户钥匙串：daemon 重启后不能自己重连。

### 4.5 凭据引用和校验

- **写法**：`{"secret": "<名字>"}`，名字的规则同 id。
- **能写在哪**：只能写在分类为"凭据"或"可为凭据"的字段（包括 `mixed.password`），以及订阅和远程规则集的 `url` 里。`secret list` 和 `secret set` 显示引用方时，`mixed` 也算一个引用方。
- **一个凭据可以被多处引用**。
- **格式校验**：每个凭据字段登记一个格式校验器。
  - `secret set` 时，按这个凭据现有的所有引用方校验格式；apply 时，对已设置的凭据按新的引用方再校验。报错不带值。
  - 不能依赖 sing-box 来校验：tuic 报错时会把原值带进错误信息。
  - `mixed.password` 要求非空，不超过 255 字节，这是 SOCKS5 的上限。
  - vmess 和 vless 的 `uuid` 接受任意非空字符串：sing-box 会把非 UUID 的值映射成 UUIDv5，以兼容 Xray。
- **占位值**：
  - 编译检查用格式合法的占位值，不用真值。
  - 占位值按关联字段成组生成，例如 ss2022 的密码按 `method` 生成。
  - 第一版不开放客户端证书（TLS 和 openconnect 的 `client_certificate`、`client_key` 一律拒绝）。以后开放时，证书和私钥是一组：占位时成对替换，真值在 `secret set` 和连接时由 XDial 核对是否配对。
  - 只能用真值做的检查，见 2.5 第 3 步。

### 4.6 命令

本地 API 提供同样的三个操作，没有读取凭据值的接口。

| 命令 | 作用 |
|---|---|
| `xdial secret set <名字>` | 从 stdin 读值。stdin 是终端时关闭回显；只去掉末尾的一个 `\n` 或 `\r\n`。输出这个凭据当前被谁引用、发往哪里 |
| `xdial secret list [--json]` | 列出名字、是否已设置、更新时间、被哪些对象引用；也列出被引用了但还没设置的名字 |
| `xdial secret rm <名字>` | 删除凭据；仍被引用时拒绝，提示里列出引用方 |

### 4.7 各类凭据

| 凭据 | 处理 |
|---|---|
| 代理线路的密码、uuid 等 | 凭据引用 |
| AnyConnect 的密码、cookie、TOTP 种子 | 凭据引用。需要浏览器登录的方式，在 M3 定 |
| 订阅 URL | 凭据引用。拉下来的节点进订阅缓存，不进配置 |
| Tailscale auth key | 只在 `xdial tailscale login` 时从 stdin 读一次，用完不保存。登录要重载一次 sing-box，现有连接会断一次 |
| Tailscale 登录状态（节点密钥） | sing-box 写在 root 专属子目录里，不复制，也不导出 |

### 4.8 导入和种子配置

- **导入旧配置库**：
  - 由用户身份的 CLI 读旧库 `~/.xdial/configuration/profiles.enc`，密钥在用户的钥匙串里。读出后转成新格式，再通过本地 API 交给 daemon：配置走 apply，凭据走 `secret set`。
  - root daemon 不读用户的钥匙串。
  - 旧文件不写回，也不删除。
  - 表达不了的部分整体报错并列出，不悄悄丢掉。细节在 M6 定。
- **种子配置**：只含配置，不含凭据。

## 5. CLI 约定

CLI 是 XDial 的核心界面，菜单栏 App 和 AI 都按这里的约定调用。本节是架构样板，第一版由用户审；之后的命令都照着写，变更属于高风险。

### 5.1 命令语法

- **形式**：`xdial <名词> <动词> [参数] [--选项]`，例如 `xdial config check <文件>`、`xdial secret set <名字>`、`xdial scenario use <id>`。
- **常用操作提到顶层**：`status`、`connect`、`disconnect`、`explain`、`doctor`、`logs`、`schema`、`version`。
- **选项**：只用长选项（`--json`、`--if-match=<revision>`）。布尔选项不带值；带值的选项写成 `--name=value` 或 `--name value`。
- **不提问**：所有输入都由参数、文件或 stdin 给出，命令运行中不向终端提问。`secret set` 从 stdin 读值，stdin 是终端时关闭回显，这不算提问。
- **不读环境变量当输入**：凭据和配置都不从环境变量读，避免它们出现在进程信息里。

### 5.2 输出

- **默认**：给人看的文字。结果写 stdout，错误写 stderr，格式是 `xdial: <说明>`，有提示时另起一行 `提示：<下一步>`。
- **`--json`**：每个命令都支持。stdout 上只输出一个 JSON 文档，成功和失败都是；stderr 不输出任何东西。持续输出的命令（`logs --follow`）输出 JSON Lines，一行一个文档。
- **成功**：

  ```json
  { "schema": "xdial.config.check/v1", "ok": true, "result": { } }
  ```

- **失败**：

  ```json
  { "schema": "xdial.error/v1", "ok": false,
    "error": { "code": "config.invalid", "message": "配置有 2 处问题", "hint": "按 problems 逐条修改后重新检查",
               "problems": [
                 { "code": "config.secret_inline", "path": "lines[0].password", "object": "line hk",
                   "message": "password 是凭据字段，不能写明文", "hint": "改成 {\"secret\": \"hk\"}，再用 xdial secret set hk 设置值" } ] } }
  ```

- **字段**：
  - `schema`：输出的类型和版本，形如 `xdial.<命令>/v<N>`，错误统一是 `xdial.error/v1`。
  - `code`：稳定的错误码，见 5.4。
  - `message`、`hint`：中文，给人和 AI 读；程序判断只看 `code`。
  - `problems`：校验类命令一次列出所有问题，不在第一处停下；最多列 200 条，超出时最后一条是 `config.more`，给出没列出的数量。
  - `path`：出错的位置，用点和下标表示，例如 `lines[0].tls.server_name`、`scenarios[1].rules[0].line`。`object` 另外写出对象的类别和 id，方便对上号。
- **版本规则**：同一个 `schema` 版本里，字段只增不删、不改名、不改类型；做不到就升版本号。每个命令的输出都有契约测试，用 `xdial schema` 给出的 JSON Schema 校验。
- **外部文本**：订阅节点名、远端错误这类外部来的文本，文字输出时把控制字符转义成 `\uXXXX`，防止改写终端或误导读输出的 AI；`--json` 输出由 JSON 编码自然转义。

### 5.3 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 命令跑完了，结论是否定的，例如检查发现问题 |
| 2 | 用法错误：命令、参数或选项不对 |
| 3 | 依赖的东西不在：daemon 没在运行、文件不存在、资源还没下载 |
| 4 | 没有权限 |
| 5 | 冲突：`--if-match` 的 revision 已经过时，或者操作和当前状态冲突 |
| 70 | XDial 自己的错误（缺陷） |

### 5.4 错误码

- **格式**：小写，`<领域>.<原因>`，例如 `config.secret_inline`。错误码一旦发布就不改含义；不用了就留着不再产生。
- **完整的表由 `xdial schema` 输出**，代码里每个错误码都登记了退出码、说明和默认提示，测试保证没有登记的错误码发不出去。
- **第一批**：

  | 错误码 | 退出码 | 说明 |
  |---|---|---|
  | `usage` | 2 | 命令、参数或选项不对 |
  | `input.read` | 3 | 读不到输入文件或 stdin：不存在、读出错 |
| `input.permission` | 4 | 没有权限读输入文件 |
  | `config.invalid` | 1 | 配置有问题，详情在 `problems` |
  | `config.syntax` | — | JSON 语法错误 |
  | `config.unknown_key` | — | 没有登记的键，或者大小写不一致 |
  | `config.duplicate_key` | — | 同一个对象里键重复 |
  | `config.forbidden_key` | — | 禁止类或 XDial 生成类的键 |
  | `config.secret_inline` | — | 凭据字段写了明文 |
  | `config.value` | — | 值不在值域里 |
  | `config.type_not_allowed` | — | 类型不在允许清单里 |
  | `config.reference` | — | 引用的对象不存在，或者类别不对 |
  | `config.cycle` | — | `detour` 和组成员成环 |
  | `config.duplicate_id` | — | id 重复 |
  | `config.compile` | — | 编译出的 sing-box 配置没通过检查 |
  | `config.more` | — | 问题太多，只列出了前面的，这一条给出没列出的数量 |
  | `config.version` | 1 | 配置的 `version` 比这个 XDial 新 |
  | `internal` | 70 | XDial 自己的错误 |

  标"—"的只出现在 `problems` 里，整体的错误码是 `config.invalid`。daemon、凭据、连接相关的错误码随 M2 补上。

### 5.5 `xdial schema`

- 输出 XDial 的全部能力：命令、参数和选项；每个命令成功输出的 JSON Schema；错误信封 `xdial.error/v1` 的 JSON Schema（含 `problems` 的元素）；错误码表和退出码表；配置格式的 JSON Schema。
- 契约测试对成功和失败两条路径都用这些 JSON Schema 校验。
- 配置格式里线路部分的字段，从分类表和 sing-box 自带的 schema 生成器裁出来，只含允许的类型和字段。
- AI 不读文档，先跑 `xdial schema --json` 就能知道怎么用。

## 6. daemon 与本地 API（M2）

本节是 M2 的架构样板，第一版由用户审。标"实测"的结论，来自 2026-10-28 在 mbp64k 一次性测试虚拟机（macOS 26.6.2，NAT 网络，网关兼 DNS 服务器是 192.168.64.1）里的测量。

### 6.1 进程和身份

| 进程 | 身份 | 负责 |
|---|---|---|
| `xdial daemon` | root，launchd 的 LaunchDaemon | 配置、凭据、状态、事件日志、本地 API；监管引擎子进程；连接期间设置系统 DNS（6.4） |
| `xdial __engine` | root，daemon 的子进程 | 只跑 sing-box（2.2）。配置经 stdin 传入，日志写 stderr，交给 daemon 脱敏 |
| `xdial` CLI、菜单栏 App | 调用者自己 | 只通过本地 API 调用 daemon |

- **两个身份**：正式版的标识是 `com.kafeifei.xdial`，Debug 是 `com.kafeifei.xdial.debug`。下面路径里的 `<id>` 指其中之一，两套互不相干，可以同时安装，但同一时刻只能有一个连着（都会接管默认路由）。
- **路径**：

  | 路径 | 内容 | 权限 |
  |---|---|---|
  | `/Library/LaunchDaemons/<id>.plist` | launchd 配置 | root:wheel 0644 |
  | `/Library/Application Support/<id>/bin/xdial` | daemon 运行的二进制，安装时从调用者给的二进制拷贝过来 | root:wheel 0755，所在目录 0755 |
  | `/Library/Application Support/<id>/config.json`、`state.json` | 配置和运行状态（4.1） | root 0600 |
  | `/Library/Application Support/<id>/private/` | 凭据、订阅和规则集缓存、tailscale 状态、daemon 自己的日志（launchd 的 stdout 和 stderr）、事件日志 | root 0700，排除出 Time Machine |
  | `/var/run/<id>/api.sock` | 本地 API | 目录 root:admin 0750，socket 0660 |

- **二进制为什么要拷贝**：daemon 以 root 运行，它执行的文件必须只有 root 能改。直接跑用户目录里的 `xdial`，等于让用户进程改 root 执行的代码。
- **安装**：`sudo xdial daemon install` 拷贝二进制、写 plist、`launchctl bootstrap`。菜单栏 App 以后改用 `SMAppService` 注册同一个 daemon，两条路径怎么衔接在 M5 定。
- **卸载**：`sudo xdial daemon uninstall [--purge]` 先断开（清掉系统 DNS、停掉引擎），再 `launchctl bootout`，删掉 plist、二进制和 socket 目录；`--purge` 连数据目录一起删。

### 6.2 本地 API

- **传输**：Unix socket 上的 JSON Lines。一个请求一行，一个响应一行。
- **请求**：`{"v": 1, "id": 1, "method": "config.apply", "params": {...}}`。
- **响应**：和 CLI 的 `--json` 输出完全相同的信封（5.2），外加 `id`。CLI 收到什么就打印什么，不在 CLI 里重新组装。持续输出的方法（`logs`）对同一个 `id` 回多行，最后一行带 `"done": true`。
- **版本**：`v` 是协议的大版本，daemon 拒绝不认识的版本，报 `api.version`。方法和字段只增不改，变更属于高风险。
- **调用方身份**：
  - socket 只有 root 和 admin 组能连（目录 0750 root:admin，socket 0660）。
  - daemon 对每个连接再用 `LOCAL_PEERCRED` 核对一次对端的 uid 和组：只接受 root 或 admin 组成员，其他一律关闭连接。不靠 socket 文件权限这一层。
  - 第一版只有一个授权级别。提交配置等于能使用凭据（4.3），所以配置和凭据的写操作、连接与断开都是同一级。没有只读的低权限入口。
- **限额**：一个请求最大 8 MiB；同时最多 16 个连接；读请求和写响应各有超时。
- **凭据只走 API**：`secret.set` 的值在请求里传，不进命令行参数和环境变量（4.3）。
- **第一批方法**：`version`、`status`、`config.export`、`config.apply`（`dry_run`、`if_match`）、`secret.set`、`secret.list`、`secret.rm`、`connect`、`disconnect`、`scenario.use`、`logs`（`follow`）。
- **新增的错误码**：

  | 错误码 | 退出码 | 说明 |
  |---|---|---|
  | `daemon.unreachable` | 3 | daemon 没在运行，或者连不上 socket |
  | `api.permission` | 4 | 调用方不是 root 或 admin 组成员 |
  | `api.version` | 1 | 请求的协议版本 daemon 不认识 |
  | `config.conflict` | 5 | `--if-match` 的 revision 已经过时 |
  | `secret.missing` | 1 | 连接用到的凭据还没设置 |
  | `secret.in_use` | 5 | 删除仍被引用的凭据 |
  | `engine.failed` | 1 | 引擎没能启动，或者启动后很快退出 |

### 6.3 连接与断开

- **连接**：编译当前场景（凭据用真值、带 TUN），启动 `xdial __engine`，经 stdin 交配置，等它报告就绪，再设置系统 DNS（6.4）。
- **断开**：先撤掉系统 DNS，再给引擎 `SIGTERM`，5 秒没退出就 `SIGKILL`。
- **TUN**：stack 用上游默认的 `mixed`，不开 `strict_route`；地址 `172.19.0.1/30` 和 `fdfe:dcba:9876::1/126`，`auto_route`。实测 `gvisor`、`system`、`mixed` 三种 stack 和打开 `strict_route` 都能正常上网。
- **不留残留**：实测引擎正常退出和被 `kill -9` 两种情况下，utun 接口和它的路由都随之消失，默认路由回到物理网卡，DNS 和 HTTPS 恢复正常。
- **引擎崩溃**：daemon 立即撤掉系统 DNS，然后按 1、2、4、8、16 秒退避重启。5 分钟内连续失败 5 次就停下，状态里写明原因，不再重连。
- **daemon 自己被杀**：launchd 会重新拉起它。daemon 启动时先撤掉上一次可能留下的系统 DNS 设置，再看 `state.json`，上次是连着的就重连。
- **网络变化**：交给 sing-box（`auto_detect_interface`，`local` DNS 重新向 DHCP 取服务器），daemon 不因此重启引擎。

### 6.4 系统 DNS

**为什么要动系统 DNS**：实测只靠 TUN 加 hijack-dns 接管不了 DNS。

- 家用网络里，DNS 服务器常常就是网关，在本机所在的子网里。它的路由比 TUN 的路由更具体，DNS 查询根本不进 TUN。
  - 后果：查询以明文发给路由器；公司 VPN 的分割 DNS（例如 `corp.example` 只能由 VPN 的服务器解析）到不了 sing-box，域名解析失败。
- 把 DNS 服务器的 /32 路由进 TUN 也不行：服务器就是网关时，绑在物理接口上的直连出站找不到下一跳，实测整机断网。
- sing-box 的 `dns_mode` 在 Apple 平台上靠 NetworkExtension 设置接口 DNS，root 进程直接起 utun 时用不上，实测没有效果。

**做法**：连接期间，daemon 在 configd 的动态存储里写一个解析器 `State:/Network/Service/<id>/DNS`。

- 内容：服务器 `172.19.0.2`（TUN 网段里，查询会进 TUN，被 hijack-dns 接管），匹配所有域名（`SupplementalMatchDomains` 为空串），`SearchOrder` 最靠前。
- 实测它成为系统的第一解析器，查询全部进了 sing-box。删掉之后第一解析器恢复原样。
- 它在动态存储里，不写进持久的网络设置，重启自然消失；daemon 被杀时由下次启动清掉（6.3）。
- 只有 daemon 写这个键，配置里不能控制它，所以不违反 2.1。

**挡住加密 DNS 的自动升级**：

- 实测系统会查询 `_dns.resolver.arpa`，发现上游的加密 DNS（DDR）。一旦升级成 DoT 或 DoH，查询就会绕开 sing-box。
- 所以编译时在 DNS 规则最前面加一条：`_dns.resolver.arpa` 一律返回 NXDOMAIN。

### 6.5 事件日志

- **文件**：`private/events.jsonl`，一行一个事件，带时间、类型、相关的线路和场景，超过 10 MB 轮转，保留 3 份。
- **记录什么**：连接与断开、引擎启动、退出和崩溃、系统 DNS 的设置与撤销、配置 apply 与 revision、凭据的设置与删除（只记名字）、VPN 推送内容的变化（3.2）。
- **怎么读**：`xdial logs` 和 `xdial doctor` 经本地 API 读（M4），返回前一样要脱敏（4.3）。

## 7. 留给后面的

- **M2**：
  - 凭据流向的强约束（4.3），在本地 API 有了之后设计；
  - Time Machine 排除和迁移助理的实测；
  - DHCP 拿不到 DNS 服务器、只有 IPv6、手动配置 DNS 这几种网络下，`local` DNS 和系统 DNS 设置的行为。
- **M3**：
  - 订阅节点怎么被线路组和场景引用；
  - VPN 推送内容的形态，以及要不要由 XDial 过滤、限额后改写成普通规则；
  - AnyConnect 需要浏览器登录时怎么办；
  - `ts_omit_*` tag 加上之后运行是否正常；
  - `exit_node` 算配置还是运行状态；
  - 当前场景用不到的 tailscale 线路怎么登录；
  - 允许清单要不要加 hysteria2 等类型。
