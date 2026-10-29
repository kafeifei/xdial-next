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
| `groups` | sing-box 的 `selector` 或 `urltest` | `outbounds` 只能指向线路或线路组，或者写成订阅成员 `{"subscription", "filter"?, "exclude"?}`（1.5）；selector 的 `default` 必须是自己 `outbounds` 里的一个 id |
| `rule_sets` | `inline`，或 `remote` | 不允许 `local`（读本机文件），本地规则写成 `inline`。`remote` 由 daemon 自己下载（3.4）：`url` 只能是 https，可以是凭据引用；`download_via` 指定经哪条线路下载，不写则走 `direct` |
| `scenarios` | `rules`：有序的规则列表，每条是 `{"rule_set", "line", "invert"?}`，或者引用订阅的规则 `{"subscription", "policies", "other"?}`（1.5）；`final`：其余流量走的线路 | 场景里不能写匹配条件，匹配只写在规则集和订阅里；`final` 必填 |
| `subscriptions` | 订阅来源：`url`、`download_via`、`user_agent`、`update_interval`，见 1.5 | `url` 必须是凭据引用，只能是 https |

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

### 1.5 订阅

2026-10-29 用户决定：订阅带节点和机场的分流规则；Clash 格式要用的 `gopkg.in/yaml.v3` 批准进依赖白名单。

- **配置里只有来源**：

  ```jsonc
  { "id": "air", "name": "机场", "url": { "secret": "air-url" },
    "download_via": "direct",      // 可选，同远程规则集（3.4）
    "user_agent": "clash.meta",    // 可选，就是这个默认值
    "update_interval": "12h" }     // 可选，默认 24 小时，最短 10 分钟
  ```

  - 多数机场按 User-Agent 决定返回的格式。默认的 `clash.meta` 让它返回 Clash 格式，只有 Clash 格式带规则。
- **格式**：按内容判断。
  - Clash YAML：`proxies` 和 `rules`。`proxy-groups` 不收，组由用户自己在配置里建。
  - sing-box JSON：`outbounds` 里节点类型的出站，`tag` 当名字。
  - 分享链接：`ss://`、`vmess://`、`vless://`、`trojan://`、`anytls://`，每行一个，整段 base64 也行。
  - Surge 格式不支持（旧版支持），列在第 7 节。
- **下载和解析**：
  - 下载同远程规则集（3.4）：同一个下载子进程、同样的地址检查和上限，内容最多 16 MiB。
  - 解析在另一个以 `nobody` 运行的子进程里做（`xdial __subscription-parse`），它把内容转成 sing-box 原生对象交回 daemon。
  - daemon 再逐个检查交回来的东西，见下面"节点"和"规则"；通过的部分整体让 sing-box 构造一遍（同 3.4），sing-box 不接受就不替换旧缓存。
- **节点**：
  - 转成 sing-box 出站，过订阅节点的允许清单和同一份字段分类（2.3、2.4），另外再收紧三条：
    - 只允许代理协议：shadowsocks、vmess、vless、trojan、anytls；
    - 不允许 `detour`；
    - 凭据字段直接写值，写成凭据引用就拒绝，否则恶意订阅能把用户设置的凭据引到自己的服务器。
  - 没通过的节点不收，按 `node:invalid` 计数；不支持的类型（hysteria2、tuic 等）按 `node:<类型>` 计数。一个可用节点都没有就算下载失败。
  - 名字去掉控制字符，最长 256 字节，重名的按顺序加 ` (2)`、` (3)`。最多 2000 个节点。
  - 转换按这些格式的实际语义（以 mihomo 为准），sing-box 表达不了的组合不收：
    - WebSocket 节点没写 `servername` 时，用 `Host` 头当 SNI；
    - Clash 的 `network: h2` 要有 TLS，`network: http`（TLS 外面的 HTTP/1.1 伪装）不能有 TLS：sing-box 的 http 传输有 TLS 时走 HTTP/2；
    - shadowsocks 插件的默认 `host` 是 bing.com，v2ray-plugin 写了 `mux: false` 才关多路复用，`skip-cert-verify` 不收。
  - 节点自带的凭据只存在 daemon 的缓存里，不出现在任何输出：`xdial subscription show` 只列名字、类型、服务器和端口。
- **线路组引用节点**：`outbounds` 里写

  ```jsonc
  { "id": "hk", "type": "urltest",
    "outbounds": [{ "subscription": "air", "filter": "香港|HK", "exclude": "剩余|到期" }, "jp"] }
  ```

  - 编译时展开成名字被 `filter` 匹配、不被 `exclude` 匹配的节点，按订阅里的顺序。两个都不写就是全部节点。正则按 1.3 的预算计。
  - 同一个组里重复的成员只算一次；所有组里由订阅成员展开出来的成员合计最多 2 万个，超过就报 `resource.too_large`，现有连接不动。手写的成员已经受配置大小的限制，不算在内。
  - 节点编成 tag 为 `xdial:sub:<订阅 id>:<名字>` 的出站，只编被组用到的；和线路一样用物理网络的 DNS 解析自己服务器的域名（3.3）。
  - 一个组展开后一个成员都没有，连接时报 `resource.missing`，现有连接不动。
  - 节点不能直接当场景的目标或 `detour`，只能经组用。`download_via` 经过的组不能有订阅成员：下载子进程只装配置里的线路（3.4）。
- **场景引用规则**：

  ```jsonc
  { "subscription": "air",
    "policies": { "🚀 节点选择": "proxy", "🎯 全球直连": "direct", "🛑 广告拦截": "block" },
    "other": "proxy" }   // 可选
  ```

  - 订阅里的规则按原来的顺序放在这条场景规则的位置上，每条走它的策略名在 `policies` 里对应的线路；`policies` 里没有的走 `other`，不写 `other` 就不收。
  - 只有真被规则用到的线路才会编进去：写了映射却没有规则走它，那条线路（比如一条 VPN）不会因此上线。
  - 连续走同一条线路的规则合成一个编译生成的规则集，tag 为 `xdial:sub:<订阅 id>:rules-<序号>`。所以订阅里规则的先后关系不变。
  - 策略名是订阅里写的原样（Clash 规则的第三段），`xdial subscription list` / `show` 列出每个策略名和用到它的规则数。
  - 这些规则和普通规则集一样参与 DNS（3.3）：纯域名条件的部分交给所选线路的 DNS server。
- **规则**：
  - Clash 规则按类型转换：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`IP-CIDR`、`IP-CIDR6`、`DST-PORT`、`PROCESS-NAME`、`PROCESS-PATH`、`NETWORK`。
  - `no-resolve` 忽略：XDial 先解析域名目的地再路由（3.2）。带其他参数的规则（例如 `src`，按来源 IP 匹配）不收，按 `rule:<类型>,<参数>` 计数。`MATCH` 不收，由场景的 `final` 代替。
  - 其余类型（`GEOIP`、`GEOSITE`、`RULE-SET`、`AND`/`OR`/`NOT`、`SRC-*` 等）不收，按 `rule:<类型>` 计数。需要的话，用远程规则集补在场景里，例如订阅规则后面加一条国内 IP 直连。
  - 每条规则再过一遍和规则集相同的检查，没通过的按 `rule:invalid` 计数。最多 5 万条。所有规则共用一份正则预算（同一个规则集的预算），超了整份订阅不收。
- **不悄悄丢掉**：上面所有没收的条目按类型计数，存在缓存里，`xdial subscription list`、`update` 的结果和事件日志里都有。
- **缓存**：在 `private/resources/subscriptions/<id>.<指纹前 16 位>.json`，指纹是 url 和 User-Agent 的 SHA-256；写法、清理、`ETag` 同远程规则集（3.4）。
- **什么时候下载**：同远程规则集，在控制序列之外（3.4、6.3）。连接或切场景时，编译器报出场景用到而缓存里没有的订阅，先下载再编译，直到不再缺；失败则这次请求失败。后台按 `update_interval` 更新，新内容在下一次连接或切场景时生效。
- **命令**：`xdial subscription list`、`xdial subscription show <id>`、`xdial subscription update [<id>...]`，输出见 `xdial schema`。

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
- **子进程死了**：daemon 退避后重启它；连续崩溃就停下并报告，不反复重连。TUN 接口随子进程退出而消失，挂在它上面的路由一并消失（实测，见 6.3）。
- **交给子进程的内容**：
  - XDial 组装、规范化之后的 sing-box 配置，经管道传，不写盘。
  - 由 XDial 自己序列化，字符串经 `encoding/json` 转义。
  - 子进程用同一个受限 registry 解析（2.3），解析的始终是 XDial 生成的内容，不是用户原文。sing-box 的类型化解析只在子进程里发生。
- **一次性子进程**：下载、二进制规则集转换和离线检查也在一次性的子进程里做，见 3.4 和 4.2。
- **启动方式和管道协议**：见 6.3。

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
    - 2.6 列出的 `ts_omit_*`。
  - 不用 `with_dhcp`：物理网络的 DNS 由 daemon 读出来交给 sing-box（3.3），不靠 sing-box 自己发 DHCP 请求。

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
  - 只对靠域名条件决定线路的流量成立。靠 IP 条件决定的流量，要先解析才知道走哪条线，解析只能发生在决定之前：用 `final` 线路对应的 DNS server；`final` 是 `block` 时用物理网络的 DNS，否则 IP 放行规则永远轮不到。
  - `direct` 用物理网络的 DNS。
  - 代理线路经它自己解析；线路自己服务器的域名在本机经物理网络的 DNS 解析，有 `detour` 的也一样，见下面"线路自己服务器的域名"。
  - endpoint 线路用它对应的 DNS server 类型（`openconnect` / `tailscale`），解析 VPN 推送的域名和 Tailnet 名字。
- **物理网络的 DNS**：连接之前系统原来用的 DNS 服务器。连接期间系统解析器指向 sing-box 自己（6.4），所以 sing-box 和下载子进程都不能再用"系统 DNS"，否则查回自己。
  - 由 daemon 读出，做法接近 configd 选默认解析器的方式，但不保证完全一致：
    - 依次看 IPv4 和 IPv6 的主网络服务（`State:/Network/Global/IPv4`、`IPv6` 的 `PrimaryService`）；
    - 每个服务里，手动设置的服务器（`Setup:`）优先于 DHCP 或路由通告下发的（`State:`）；
    - 只留这个服务有地址的地址族，例如只有 IPv6 地址的服务，手动写的 IPv4 服务器不要；
    - 第一个还剩服务器的服务胜出。
  - 不读 `State:/Network/Global/DNS`：实测连接后它跟着第一解析器变成了 XDial 的（[实测记录](docs/verification/m2-system-dns.md) 第 4 节）。
  - 编成一个 `udp` server，地址取第一个全局地址，没有全局地址时才用链路本地地址。拨号跟随 `auto_detect_interface`，绑在物理接口上，不经过 TUN。
  - 只用第一个地址：sing-box 的 DNS server 没有多地址的故障切换。第一个地址不通时，经它的解析都失败，列在第 7 节。
  - 变了就重载引擎（6.4）。连接时读不到任何服务器（例如开机时网络还没就绪），连接失败，网络就绪后自动重试（6.3）。
  - 不用 sing-box 的 `local`：它在 macOS 上有 TUN 时向 DHCP 要服务器，拿不到就退回系统解析器，也就是查回自己；它还会忽略手动设置的 DNS。
- **DNS server**：都由 XDial 生成，tag 带 `xdial:` 前缀。

  | 给谁用 | 类型 |
  |---|---|
  | `direct`，以及线路自己服务器的域名 | `udp`，物理网络的 DNS |
  | 代理线路和线路组 | `https`，服务器 `1.1.1.1`，`detour` 指向这条线路或组 |
  | openconnect、tailscale 线路 | 对应的 `openconnect`、`tailscale` 类型，只用来解析 VPN 推送的域名和 Tailnet 名字（下面第 3 条）。它们不当通用解析器：没有下发默认解析器时，未匹配的域名一律返回 NXDOMAIN。被场景规则或 `final` 选中 endpoint 线路的其余域名，第一版用物理网络的 DNS 解析。这样功能可用，代价是这些查询经本地网络发出；全隧道 VPN 和 exit node 下怎么让它们也走隧道，M3 实测后再定 |

- **系统 DNS**：连接期间由 daemon 把系统解析器指到 TUN 里，否则查询可能根本不进 TUN，见 6.4。
- **DNS 规则的顺序**：
  1. 从 endpoint 进来的查询一律拒绝（2.6）；`_dns.resolver.arpa` 和 `use-application-dns.net` 一律由 sing-box 自己返回 NXDOMAIN，挡住系统发现加密 DNS 和 Firefox 自带的 DoH（6.4）。
  2. 场景规则：从每个规则集里只取纯域名条件的规则（`domain`、`domain_suffix`、`domain_keyword`、`domain_regex`，以及只由它们组成的逻辑规则），编成 DNS 专用的规则集，交给这条场景规则所选线路对应的 DNS server。
     - DNS 规则从不拒绝，选 `block` 的场景规则不生成 DNS 规则，拒绝只在路由阶段做。DNS 阶段看不到前面那些靠 IP、端口、进程或取反决定的规则，在这里提前拒绝，会抢在本该先命中的规则前面，让 `resolve` 失败。
     - 不能把规则集整个拿来用：sing-box 的 DNS 规则遇到 IP 条件会进入旧的匹配方式，预匹配时忽略目的 IP 条件，纯 IP 的那条分支就直接算命中，选 `block` 时会把无关域名一起拒掉。
     - 混有端口、进程等条件的规则，在 DNS 阶段判断不了，不进 DNS 规则。
     - 带 `invert` 的场景规则：规则集里全是纯域名条件时，DNS 专用规则集和原规则集等价，`invert` 原样保留；否则不生成 DNS 规则，因为对取出来的一部分条件取反，会命中本不该命中的域名。
     - 同样因为 DNS 阶段看不到那些前置规则，个别情况下解析用的线路会和实际走的线路不同，例如前面一条按进程把连接送去了代理，后面一条域名规则却决定了它经哪个 DNS 解析。
  3. VPN 推送的域名：`preferred_by` 匹配 endpoint 的 DNS server，交给它解析。和路由一样放在场景规则之后。
  4. 其余的，交给 `final` 线路对应的 DNS server；`final` 是 `block` 时交给物理网络的 DNS（见上面的原则）。
- **域名关联**：DNS 开启 `reverse_mapping`，从 DNS 应答里记下 IP 和域名的对应关系。嗅探认不出域名的连接（例如 SSH）只带着 IP 进来，靠它恢复域名，域名规则和 `block` 才能命中。连接之前就被系统缓存住的应答拿不到映射；sing-tun 设好路由后会清一次系统 DNS 缓存（`tun_darwin.go` 的 `flushDNSCache`），但那时系统解析器还没指到 TUN；daemon 在设好系统解析器之后再清一次（6.3），尽量不让这之前经物理网络 DNS 缓存的应答留下；这次清理失败只记事件，不影响连接。
- **线路自己服务器的域名**：线路的 `domain_resolver` 由 XDial 生成，统一用物理网络的 DNS。有 `detour` 的线路也一样：本机解析出地址，再经 `detour` 拨过去。
- **私有地址和局域网**：编译不加"私有地址直连"这类规则，公司网段多半也是私有地址。本机所在子网的路由比 TUN 的路由更具体，局域网流量本来就不进 TUN：实测 DNS 服务器在本机子网时，发给它的查询不进 TUN（6.4）。其他私有地址按场景走。

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
  - 下载在一次性的子进程里做。子进程只含 `download_via` 指定的那条线路链，绑定物理接口，绕开 TUN；解析用 daemon 交给它的物理网络的 DNS（3.3），不读 `/etc/resolv.conf`，连接期间那里写的是 TUN 里的地址。
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

M3 的实现（#10）：

- **两个子进程**：`xdial __fetch` 下载，`xdial __rule-set-decode` 把 binary 转成 source。
  - 都由 daemon 用自己的二进制起，以 `nobody` 身份运行，清掉附加组，什么都不继承，输入全在 stdin。找不到 `nobody` 就不起子进程；子进程发现自己是 root 也拒绝运行。
  - 下载子进程：
    - 经 `direct` 时，用 daemon 交给它的物理网络 DNS 解析，再用标准库拨号；
    - 经代理线路时，起一个只含 `download_via` 那条线路链的 sing-box（`engine.CompileDownload`），日志关掉。
  - 两种情况的 socket 都绑在物理接口上（macOS 的 `IP_BOUND_IF`），接口取主网络服务的 `PrimaryInterface`。TUN 不注册网络服务，所以连接期间它仍是物理接口。
- **拒绝的地址**（经 `direct` 时）：
  - 回环、链路本地、私有（含 `fc00::/7`）、CGNAT `100.64.0.0/10`、组播、未指定；
  - `0.0.0.0/8`、`240.0.0.0/4`、广播、`198.18.0.0/15`（常被假 IP 型 DNS 使用）、文档网段、Teredo、`fec0::/10`；
  - NAT64（`64:ff9b::/96`）和 6to4（`2002::/16`）按内嵌的 IPv4 再查一次。
  - 检查在拨号时做，每一跳重定向、每个新连接都重新检查；同一主机的连接复用不再检查。
  - 只有直接写 `download_via: direct`（或不写）时经过这道检查。经组成员走到 `direct` 会用 sing-box 自己的直连出站，什么都不查，所以配置检查拒绝经组成员能走到 `direct` 的 `download_via`。代理线路的 `detour` 不算：经它连的是代理服务器，下载目标仍由代理那一侧去连。
- **请求**：带 `If-None-Match` / `If-Modified-Since`，`304` 时只更新下载时间；缓存的内容过不了检查时不带这两个头，整份重下。重定向最多 5 次；整次下载 60 秒。
- **错误**：只回错误码和 XDial 自己写的固定说明（连不上、解析失败、证书不受信任、超时、HTTP 状态码等），不透传底层错误文本：它可能含 URL、重定向的地址或服务器名，订阅地址里常带令牌。不回显响应体。内容检查不通过时只给错误码和位置，位置里只留 XDial 认识的键和下标。
- **上限**：

  | 内容 | 上限 |
  |---|---|
  | source 下载 | 16 MiB；解析时最多 60 万个值 |
  | 单个列表 | 30 万项（手写配置是 2 万）；geosite-cn 一条规则就有约 11 万个后缀 |
  | 规则 | 每个规则集 2 万条，逻辑规则 4 层、每条最多 64 条子规则，正则按编译后的大小计；不能是空的 |
  | binary 下载 | 16 MiB；解压后 32 MiB；各层规则合计 5 万条，单个列表 30 万项，列表合计 200 万项 |
  | binary 的域名树 | 60 万个域名，展开后 16 MiB，单个域名 512 字节，必须是合法的 UTF-8 |
  | binary 的 IP 段 | 展开后 60 万个前缀 |
  | 转换 | 30 秒；输出按 source 的上限 |

- **binary 的预检**（`resource.Preflight`）：
  - 每个声明的长度都先和剩下的字节数比较，再和上限比较。只和剩下的字节数比不够：sing-box 先按声明的个数分配切片，一个元素在文件里几个字节，在内存里可能上千字节。
  - 域名树：按广度优先走一遍位图，核对节点数、边数和标签数一致，叶子位图覆盖所有节点且末尾没有多余的位，不通向任何域名的节点、空域名、不在末尾的后缀标记都拒绝，同时累计域名个数和展开后的长度。
  - IP 段：首尾地址族一致、首不大于尾，按 CIDR 展开数计数。
  - 子进程里在解码前再做一次预检，不依赖调用方。
- **缓存**：
  - 在 `private/resources/rule-sets/<id>.<指纹前 16 位>.json`，root 专属。指纹是 url 和 format 的 SHA-256。存检查过、压紧的 source 内容、下载时间、内容变化时间、`ETag`、`Last-Modified`。
  - 一个指纹一个文件：按旧配置跑到一半的下载，写不坏新配置的缓存。url 或 format 变了，旧文件就不再被读；后台检查时按当时的配置，删掉不用、超过一小时没被用过的文件（连接时读一次就算用过）。
  - 写入时不转义 `<`、`>`、`&`，存下的内容和检查过的一字不差。
  - 编译时发现缓存的内容过不了检查，就删掉它；这时正有下载占着下载锁的话，记下来，后台检查时不管它看起来多新都重下。
  - 进缓存之前，除了 XDial 自己的检查，还在以 `nobody` 运行的检查子进程里让 sing-box 构造一份只用这个规则集的配置，sing-box 不接受就不替换旧缓存。
  - 每次使用都重新过一遍 source 的检查。
- **什么时候下载**：
  - 连接、切场景、连接中 apply 时，场景用到而缓存里没有的，先下载再编译。下载在控制序列之外（6.3），失败则这次请求失败，错误码是下载的错误码，现有连接不动。
  - 对同一场景、同一配置再 `connect`：引擎要跑的内容（编译结果）变了才重载，所以更新过的规则集用 `connect` 也能生效。
  - 编译出的配置在替换现有连接之前再检查一次：大小不超过引擎读入的上限（64 MiB），并让 sing-box 构造一遍（凭据用占位值）。不通过就不动现有连接。
  - 后台：daemon 启动时、每次 apply 和 `secret set` 之后、以后每 5 分钟检查一次，下载没缓存或已过期的。
  - 过期按 `update_interval`，默认 24 小时，最短 10 分钟。失败后 10 分钟内后台不再试。
  - 下载一次只跑一个。
- **命令**：
  - `xdial rule-set list`：每个规则集是否已下载、规则条数、下载时间、下次更新时间、上次的错误。
  - `xdial rule-set update [<id>...]`：现在下载，不写 id 就下载全部远程规则集。有失败时整体报第一个失败的错误码，说明里列出每个失败的规则集和成功的个数。
- **事件**：`rule_set_updated`（是否变化、条数）、`rule_set_update_failed`（错误码和说明）。

### 3.5 AnyConnect 和 Tailscale 线路的状态（M3）

sing-box 在后台把 endpoint 连上：引擎就绪只说明配置跑起来了，VPN 本身可能还在连、要登录，或者连不上。所以引擎就绪之后接着报 endpoint 的状态（6.3），daemon 把最近一次的放在 `status` 的 `endpoints` 里，状态变了记 `endpoint_state` 事件。

- **字段**（`endpoints.<线路 id>`）：
  - `type`：`openconnect` 或 `tailscale`；`state`：`connecting`、`connected`、`auth_required`、`failed`。程序判断看这两个，说明文字给人看。
  - AnyConnect：`error`、`auth_message`（服务器要求再输入什么）、`browser_auth`、`addresses`（分到的地址）、`dns`（下发的 DNS）、`since`、`default_route`。
  - Tailscale：`auth_url`（要登录时的链接）、`tailnet`、`dns_name`、`self`（本机在 tailnet 里的地址）、`exit_node`、`peers`、`online`。
  - 登录链接只在 `status` 里，不进事件日志。服务器给的文字（`error`、`auth_message`）最多留 512 字节，并像引擎日志一样脱敏。截断点取在原文上、不落在任何凭据（及其各种编码形式）中间的位置，先截再脱敏，留下的部分里每个凭据都是完整的、整个被替换。不能先脱敏再截：替换会改变截断点之前的长度，半截凭据就可能挪进来。引擎那边另按 64 KiB 截，免得一条超长提示让每一行状态都超过上限；这一刀远在 512 字节之后，留下的部分碰不到它。
  - 引擎写的状态行超过 1 MiB 的跳过这一行，之后的照常读。
- **整个连接和 VPN 分开**：VPN 连不上不算连接失败。连接照常建立，场景里走这条线路的流量连不通，其余不受影响；`status` 和事件说明 VPN 的情况。
- **AnyConnect 的认证**：
  - 用户名、密码（凭据引用），可选 TOTP（`token.mode: totp`，种子是凭据引用）。旧版的公司线路就是用户名加密码。
  - 服务器要浏览器登录（SAML 等）时，状态是 `auth_required`、`browser_auth: true`。第一版不支持：要在本机开浏览器，取回 cookie 交给引擎，留到 M5 和 App 一起做。
  - 密码错时，服务器会再要一次表单，状态是 `auth_required`，`auth_message` 是服务器的提示。
  - 引擎不自己重试认证；线路断了之后由 sing-box 按 `reconnect_timeout` 重连，超时就是 `failed`。`failed` 之后要切一次场景（重载）才会再试，第一版不自动重载：重载会断掉所有连接。
- **VPN 推送的网段和域名**（3.2 的信任假设）：
  - sing-box 不把推送的内容交给外面（只有地址、DNS 和 MTU），XDial 读不到，也就无法过滤或限额，除非给 sing-box 打补丁，这和"只用上游"冲突。3.2 的做法不变：推送规则排在用户规则之后，只能接管原本走 `final` 的流量。
  - 能看到的是结果：引擎问 endpoint 两个文档用的地址（198.51.100.1、2001:db8::1）是不是由它接管。只有默认路由或者差不多一样宽的路由才会盖住它们，`default_route` 按地址族列出被接管的（`["ipv4"]`、`["ipv4", "ipv6"]`），`xdial status` 提示"原本走 final 的这些流量都会进这条 VPN"，并记进事件。不用公网地址探测：sing-box 给 VPN 下发的每个 DNS 服务器加一条主机路由，下发 1.1.1.1 就会误判。
  - 用户在公司网络上实测之后，再决定要不要做更多（第 7 节）。
- **Tailscale 的登录**（#13）：
  - 每条 tailscale 线路是 tailnet 里的一台设备，登录状态在 `private/tailscale/<线路 id>/`，由 sing-box 写，不复制、不导出。
  - 只能登录当前连接里用到的线路：登录和登出都作用在运行中的引擎上，当前场景用不到的线路没有上线，也就没有可登录的。要先切到用到它的场景。
  - `xdial tailscale login <线路>`：线路在等登录时，返回登录链接（`auth_url`），在浏览器里打开即可；`status` 里也有。
  - `xdial tailscale login <线路> --auth-key`：从 stdin 读 auth key，只编进这一次重载的配置（现有连接断一次），之后不保存；脱敏时和凭据同样对待。登录成功后，状态留在上面的目录里，以后的重载不再需要它。
  - `xdial tailscale logout <线路>`：经引擎的 stdin 发登出命令（6.3），线路随后等新的登录。引擎在单独的工作协程里一次执行一条命令，不挡住它对退出信号和 stdin 结束的处理。
  - 登录链接：sing-box 会把它写进日志；daemon 写引擎日志时把它换成"登录链接见 xdial status"。谁打开这个链接，就能把这台设备登进自己选的账户。
  - 等待登录或登出的结果只针对发起时的那个连接：期间连接断开或换掉，返回 `config.conflict`。带 auth key 的重载失败时，按用户要的状态走正常的重连，重连不再带 key。
  - `exit_node` 写在配置里（线路的字段），和旧版一样随场景生效；不另设运行时切换。
  - 构建去掉了 peerapi、C2N、SSH、Taildrop 等能力（2.6）。XDial 不提供设置 serve 的途径，serve 不会开启。

### 3.6 线路组在运行中（M4）

- **当前成员和延迟**：引擎的状态行里带每个组（selector、urltest）的当前成员和各成员最近一次测得的延迟，`status` 的 `groups` 里能看到。urltest 自己定时测，结果也进来；引擎每 15 秒至少报一次，组自己切了成员也看得到。
- **手选**（`xdial group select <组> <成员>`）：
  - 只有 selector 组能手选。成员是组里的 id，或者订阅成员展开出的节点（写它的 tag，`status` 里列着）。
  - 选择由 daemon 记在 `state.json` 的 `selections` 里，不写进配置（1.1）。连接中经引擎的 stdin 切换，现有连接不断；之后每次编译这个组，都把它编成组的 `default`。选的成员不在组里了（例如配置改了、订阅里没了），回到组自己的默认值。
- **测速**（`xdial line test [<id>...]`）：经运行中的引擎，每条线路取一次 `https://www.gstatic.com/generate_204`，10 秒超时；写组的 id 就测它的每个成员，不写就测所有组。结果也记进组的延迟里。没有连接时不能测：测速要走和实际流量一样的线路。

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
  - selector 手选的成员被删掉时，回到组的默认值（3.6）。
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
  - 所以提交配置和设置凭据按同一级别授权（6.2）。
  - `--dry-run` 和 apply 的输出会列出凭据引用的变化（谁在引用、发往哪里），供人核对。
  - 能调用本地 API 的是 root 和控制台用户（6.2），这个用户的任何进程都能改流向。挡这一层要在本机上另外确认，例如 App 弹窗确认凭据发往新的地方。协议为此预留了 `api.confirm_required`（6.2），具体做法在 M5 和 App 一起定；流向要覆盖整条 `detour` 链和 TLS 校验设置。

### 4.4 凭据的存放

- **位置**：daemon 数据目录下一个 root 专属的子目录（0700），凭据存在其中的 `secrets.json`（0600）。
  - 订阅和规则集缓存、tailscale 的 state 目录也放在这个子目录里。
  - 写入用临时文件加 rename，原子替换，权限保持不变。
- **备份**：整个子目录排除出 Time Machine；磁盘层面靠 FileVault。
- **换机后要重新设置**：
  - 从备份恢复之后，配置还在，凭据需要重新设置。`xdial secret list` 会列出缺哪些。
  - 【推断】用迁移助理直接从旧 Mac 迁过来时，也会跳过这个子目录。
  - 排除是否生效、迁移助理是否跳过，还没实测（第 7 节）。
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
| AnyConnect 的密码、cookie、TOTP 种子 | 凭据引用。浏览器登录第一版不支持（3.5） |
| 订阅 URL | 凭据引用。拉下来的节点进订阅缓存，不进配置 |
| Tailscale auth key | 只在 `xdial tailscale login --auth-key` 时从 stdin 读一次，编进那一次重载的配置，用完不保存（3.5）。现有连接会断一次 |
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

  标"—"的只出现在 `problems` 里，整体的错误码是 `config.invalid`。daemon、凭据、连接相关的错误码见 6.2。

### 5.5 `xdial schema`

- 输出 XDial 的全部能力：命令、参数和选项；每个命令成功输出的 JSON Schema；错误信封 `xdial.error/v1` 的 JSON Schema（含 `problems` 的元素）；错误码表和退出码表；配置格式的 JSON Schema。
- 契约测试对成功和失败两条路径都用这些 JSON Schema 校验。
- 配置格式里线路部分的字段，从分类表和 sing-box 自带的 schema 生成器裁出来，只含允许的类型和字段。
- AI 不读文档，先跑 `xdial schema --json` 就能知道怎么用。

## 6. daemon 与本地 API（M2）

本节是 M2 的架构样板，第一版由用户审。标"实测"的结论，来自 2026-10-28 在 mbp64k 一次性测试虚拟机（macOS 26.6.2，NAT 网络，网关兼 DNS 服务器是 192.168.64.1）里的测量，做法和结果见 [实测记录](docs/verification/m2-system-dns.md)。

### 6.1 进程和身份

| 进程 | 身份 | 负责 |
|---|---|---|
| `xdial daemon` | root，launchd 的 LaunchDaemon | 配置、凭据、状态、事件日志、本地 API；监管引擎子进程；连接期间持有系统解析器（6.4） |
| `xdial __engine` | root，daemon 的子进程 | 只跑 sing-box（2.2），管道协议见 6.3 |
| `scutil` 会话 | root，daemon 的子进程 | 连接期间持有系统解析器的临时键（6.4） |
| `xdial` CLI、菜单栏 App | 调用者自己 | 只通过本地 API 调用 daemon |

- **两个身份**：正式版的标识是 `com.kafeifei.xdial`，Debug 是 `com.kafeifei.xdial.debug`。下面路径里的 `<id>` 指其中之一。两套的配置、凭据、状态和 socket 互不相干，可以同时安装。
- **同一时刻只有一个连着**：
  - 两套都接管默认路由，TUN 地址和解析器地址也相同。sing-tun 加路由遇到"已存在"时，会先删掉已有的再加（`tun_darwin.go`），两套同时连着会互相拆路由。
  - 机制：两套共用一把连接锁（`flock`），见下面的路径表。daemon 启动引擎之前拿锁，拿不到就报 `engine.busy`；连接中重载时不放开锁，直接交给新连接。不靠"先查另一套的状态再启动"。
  - 锁放在只有 root 能进的目录里：macOS 的 `flock` 只要能打开文件就能加锁，别的用户能读到锁文件，就能一直占着它。目录和文件已经存在时，必须是 root 的、不是符号链接、别人没有任何权限，否则不连接。目录不放在 `/var/run`：那里 daemon 组也能写，理论上能把整个目录换掉，让两个身份锁到不同的文件上。
  - 引擎和 scutil 会话都继承这把锁的描述符。锁要等 daemon、引擎和临时键都没了才释放，不论各自怎么退出。
  - 引擎一启动就把这个描述符设成 exec 时关闭：sing-box 自己起的子进程（例如关 TUN 时的 `dscacheutil`）不会带着锁活得比引擎久。
- **路径**：

  | 路径 | 内容 | 权限 |
  |---|---|---|
  | `/Library/LaunchDaemons/<id>.plist` | launchd 配置 | root:wheel 0644 |
  | `/Library/Application Support/<id>/bin/xdial` | daemon 运行的二进制，安装时从调用者给的二进制拷贝过来 | root:wheel 0755，所在目录 0755 |
  | `/Library/Application Support/<id>/config.json`、`state.json` | 配置和用户要的连接状态（4.1、6.3） | root 0600 |
  | `/Library/Application Support/<id>/private/` | 凭据、订阅和规则集缓存、tailscale 状态、引擎日志、daemon 自己的日志（launchd 的 stdout 和 stderr）、事件日志 | root 0700，排除出 Time Machine |
  | `/var/run/<id>/api.sock` | 本地 API | 目录 root:wheel 0755，socket 0666；谁能用由 6.2 的核验决定 |
  | `/Library/Application Support/com.kafeifei.xdial.shared/connection.lock` | 两个身份共用的连接锁；卸载最后一个身份时删掉 | 目录 root:wheel 0700，文件 0600 |

- **二进制为什么要拷贝**：daemon 以 root 运行，它执行的文件必须只有 root 能改。直接跑用户目录里的 `xdial`，等于让用户进程改 root 执行的代码。
- **安装**：`sudo xdial daemon install`
  1. 准备目录：已存在的必须是目录、不是符号链接；属主改成 root，权限收紧到上表。
  2. 校验并暂存二进制，这一步失败时已装的 daemon 照常运行：
     - 先解析出真实路径；源文件所在目录的属主是 root 或运行 sudo 的用户，别人不能写（带粘滞位的目录除外，那里别人换不掉不属于自己的文件），也没有 ACL；
     - 按 `O_NOFOLLOW` 打开源文件，对打开的这个文件核对：普通文件，属主是 root 或运行 sudo 的用户，别人不能写，没有 ACL；
     - 内容写进 `bin/` 下新建的临时文件；签名的构建在这里核对临时副本的签名（M6）。
  3. `launchctl bootout` 已装的 daemon。它照常断开（6.3），但不改用户要的连接状态。再把临时文件 rename 成 `bin/xdial`：launchd 不会读到写了一半的文件，正在运行的二进制也不会被就地覆盖。
  4. 写 plist（同样是临时文件加 rename），`launchctl bootstrap`。
  5. 等 socket 出现，核对监听者是 root（6.2），并且 `version` 报告的构建和刚装的一致。
  - 重复执行就是升级。新 daemon 起来后按 `state.json` 恢复连接（实测）。
  - 可信的依据是源文件的属主：root 或运行 sudo 的用户。第 2 步挡的是别的用户换掉它，或者经符号链接把它引到别的文件。ACL 的检查按路径做，和打开文件之间有一个很短的空档。
  - 挡不住的：这个用户自己的进程在 sudo 之后、打开之前换掉文件。它在 sudo 之前同样能换，所以这一层不在这里挡；签名构建（M6）之后，可信的依据改成签名。
- **launchd 配置**：
  - `RunAtLoad`、`KeepAlive`，`ProcessType` 为 `Interactive`；
  - `AbandonProcessGroup` 为 false：daemon 退出时，launchd 杀掉它进程组里剩下的进程，引擎和 scutil 会话不会留下；
  - `ThrottleInterval` 5 秒；`ExitTimeOut` 20 秒，留够断开的时间。
- **卸载**：`sudo xdial daemon uninstall [--purge]` 先 `launchctl bootout`（daemon 断开），再删 plist、二进制和 socket 目录；另一个身份没装时，连共享目录一起删；`--purge` 连数据目录一起删。
- **和 App 的衔接**：
  - `SMAppService.daemon` 运行的是 App 包里的二进制。App 装在 `/Applications` 时 admin 用户就能改它，不满足上面"只有 root 能改"。两种注册方式也不能共用同一个 launchd label。
  - M2 只交付 CLI 安装。App 怎么安装和升级 daemon（例如调用同一个 install 流程），在 M5 定。

### 6.2 本地 API

- **传输**：Unix socket 上的 JSON Lines。一个请求一行，一个响应一行；一个连接上一次一个请求，响应按顺序回。
- **请求**：`{"v": 1, "id": 1, "method": "config.apply", "params": {...}}`。
- **响应**：
  - 和 CLI 的 `--json` 输出相同的信封（5.2），外加 `id`。
  - 持续输出的方法（`logs`）对同一个 `id` 回多行，最后一行带 `"done": true`；`follow` 时客户端关闭连接就结束。
  - CLI 打印时只去掉 `id` 和 `done`，其余原样输出，不在 CLI 里重新组装。
- **版本**：`v` 是协议的大版本，daemon 拒绝不认识的版本，报 `api.version`。方法和字段只增不改，变更属于高风险。客户端要能处理任何方法返回任何已登记的错误码。
- **谁能调用**（2026-10-28 用户定）：root，以及当前在屏幕前登录的用户（控制台用户，即 `/dev/console` 的属主）。
  - 每个请求都用内核记录的对端身份（`LOCAL_PEERCRED`）核对一次，不靠 socket 的文件权限。快速切换用户之后，前一个用户的请求就被拒绝。
  - 没有人登录（停在登录窗口）时，`/dev/console` 属于 root，只有 root 能用。
  - 公司 Mac 上的标准用户也能用；SSH 进来的其他账户不能用。
  - socket 对所有本地用户开放（0666）。不被允许的调用方收到 `api.permission`（实测），而不是看不出原因的 EACCES。
  - 只有一个授权级别。提交配置等于能使用凭据（4.3），所以配置和凭据的写操作、连接与断开都是同一级。控制台用户的任何进程都有这份权限，和他自己的 shell 一样。
  - **预留确认**：`api.confirm_required` 表示这次操作要先在本机上确认，例如由 App 弹窗。第一版不产生；以后加上它只是多一个错误码，不改方法和字段（4.3）。
- **客户端核验服务端**：
  - CLI 和 App 连上 socket 之后、发出任何请求之前，用 `LOCAL_PEERCRED` 核对监听者是 root。不是就报 `daemon.untrusted`，请求不发出去，凭据更不会。
  - 原因：`/var/run` 是 root:daemon 0775。socket 目录不存在时，理论上别的进程能抢先放一个假的 socket。
- **socket 目录**：daemon 启动时删掉 `/var/run/<id>` 再新建，不复用。新建失败（例如被别人抢先建了）就不启动。socket 建在这个新目录里。
- **限额**：
  - 一个请求最大 8 MiB，超过就回 `usage` 并关闭连接；读请求和写响应各有超时。
  - 连接一接上就核对对端身份，不被允许的连接不占名额：它们另走一个最多 8 个的小池子，5 秒内读第一个请求、回 `api.permission`；小池子满了就直接关掉。
  - 被允许的连接同时最多 32 个，满了之后新连接收到 `daemon.busy`。
  - `logs --follow` 可以一直开着、中间没有输出，客户端对它不设读超时。
- **凭据只走 API**：`secret.set` 的值在请求里传，不进命令行参数和环境变量（4.3）。
- **第一批方法**：`version`、`status`、`config.export`、`config.apply`（`dry_run`、`if_match`）、`secret.set`、`secret.list`、`secret.rm`、`connect`、`disconnect`、`scenario.use`、`logs`（`lines`、`follow`）。M3 加 `rule_set.list`、`rule_set.update`（`ids`），见 3.4；`subscription.list`、`subscription.show`（`id`）、`subscription.update`（`ids`），见 1.5。
  - `connect` 对已经连着的同一场景、同一配置不做任何事。
- **状态**：`status` 和改变连接的方法返回同一个结构。
  - `state`：`disconnected`、`connecting`（正在连接、重载或等待重连）、`connected`、`failed`。
  - `intent`：用户要的状态，`connected` 或 `disconnected`；daemon 一直朝它努力（6.3）。
  - `system_dns`：系统的第一解析器是不是 XDial 的（6.4）。
  - `physical_dns`：物理网络的 DNS（3.3）。
  - 另有 `scenario`、`revision`、`since`、`last_error`、`engine_pid`。
  - `endpoints`：AnyConnect 和 Tailscale 线路各自的状态，见 3.5（M3）。
- **M3 加的方法**：`tailscale.login`（`line`、`auth_key`）、`tailscale.logout`（`line`），见 3.5。
- **M4 加的方法**：`group.select`（`group`、`member`）、`line.test`（`ids`），见 3.6；`status` 加 `groups`。
- **新增的错误码**（退出码按 5.3）：

  | 错误码 | 退出码 | 说明 |
  |---|---|---|
  | `daemon.unreachable` | 3 | daemon 没在运行，或者连不上 socket |
  | `daemon.untrusted` | 3 | socket 上监听的不是 root 的进程，请求没有发出 |
  | `daemon.busy` | 5 | daemon 的连接数已满 |
  | `api.permission` | 4 | 调用方不是 root，也不是控制台用户 |
  | `api.version` | 3 | 请求的协议版本 daemon 不认识，要重装 daemon |
  | `api.confirm_required` | 4 | 要先在本机上确认；第一版不产生 |
  | `config.conflict` | 5 | `--if-match` 的 revision 已经过时，或者操作和当前状态冲突，例如删掉正在用的场景 |
  | `secret.missing` | 3 | 用到的凭据还没设置 |
  | `secret.in_use` | 5 | 删除仍被引用的凭据 |
  | `secret.format` | 1 | 凭据的格式不符合引用它的字段 |
  | `engine.failed` | 1 | 没能连上：引擎没能启动、启动后很快退出、查询进不了 sing-box，或者系统解析器没能设置 |
  | `engine.busy` | 5 | 另一个身份正连着（6.1） |
  | `resource.missing` | 3 | 编译时缓存里缺场景用到的远程规则集或订阅（3.4）；正常的请求会先下载，这只在下载之后缓存又不可用，或者重连、重载时出现 |
  | `resource.download` | 1 | 下载失败：连不上、超时，或者服务器返回了错误（3.4，M3） |
  | `resource.blocked` | 1 | 下载地址不被允许：不是 https、重定向到 http，或者解析到本机和内网 |
  | `resource.too_large` | 1 | 下载的大小超过上限，或者编译出的整份配置超过引擎读入的上限 |
  | `resource.invalid` | 1 | 下载的内容不合法，或者里面的条数、长度超过上限；详情在 `problems`，只给位置和错误码 |

  参数不对用 `usage`。

### 6.3 连接与断开

- **一个控制序列**：连接、断开、切场景、apply、凭据的写操作、重载、崩溃后的重试和定期检查（6.4），在 daemon 里排成一个序列，一次只做一件。凭据和配置是连接的原料，所以它们的写操作也进这个序列，不会插到 apply 的重载和回滚中间。`status` 不进这个序列，连接进行中也能马上回答。
  - 改变连接的用户请求让代次加一。退避中的重试带着安排它时的代次，到点时代次变了就作废：用户断开之后，旧的重试不会再把连接拉起来。
  - 用户请求先做不动现有连接的准备（找场景、编译、查凭据和资源），准备失败就原样返回，代次和重试安排都不变。
- **用户要的和实际的分开**：`state.json` 只存用户要的（场景、要不要连着），实际状态只在内存里。写进 `state.json` 是提交点：写失败，内存里的也不变。
  - `connect` 和连接中的 `scenario use`：新连接起来之后才记"要连着"。连不上，或者记不下来（记不下来时拆掉刚起来的连接），请求报错；用户原来要连着的，daemon 回到为原来的状态退避重连，原来不要连着的，状态是 `failed`。连不上的请求不会在重启后自己重试。
  - `disconnect` 先记"不要连着"，再拆连接：拆到一半 daemon 被杀，重启后也不会再连。记不下来就报错，连接不动。
  - `apply`：连着时，新配置先起来，再写盘，最后才成为当前配置；起不来或写不下，换回旧配置再连一次，配置不变（4.1）。
- **连接**：
  1. 准备：
     - 连接、切场景、连接中 apply 这类请求，先在控制序列之外把场景用到而缓存里没有的远程内容下载好（3.4），失败报下载的错误码。下载可能要几分钟，控制序列要随时能处理引擎崩溃这类不能等的事。
     - 然后在控制序列里，用凭据的真值和物理网络的 DNS（3.3）编译当前场景，带 TUN，远程内容只从缓存读。读不到物理网络的 DNS、缺凭据、缓存里还缺远程内容（占位规则只用于检查，报 `resource.missing`），都在这一步失败，现有连接不受影响。崩溃后的重连和网络变化后的重载也只读缓存，缺的由后台下载补上；补上之后，用户要连着、重连因为缺缓存而停下的，再连一次：只认带来新内容的下载（`304` 不算），并且先只读缓存准备一遍，场景用到的都齐了才连；因为别的原因停下的重连不受影响。
  2. 拆掉现有的连接（如果有）。从这里到新连接起来之前，流量直连。
  3. 拿连接锁（6.1）。
  4. 启动 `xdial __engine`，经 stdin 交配置，等它报告就绪。
  5. 经 TUN 向 `172.19.0.2` 分别用 UDP 和 TCP 问 `_dns.resolver.arpa`，要收到 sing-box 自己回的 NXDOMAIN（3.3），最多等 5 秒。这一步确认路由进了 TUN、hijack-dns 接住了查询、sing-box 在回答，不只凭引擎说自己就绪了。它不检查上游通不通（第 7 节）。
  6. 设置系统解析器（6.4），等 configd 收下并核对；再清一次系统 DNS 缓存（3.3）。
  7. 报告 `connected`；用户请求再按上面记下用户要的状态。第一解析器不是 `172.19.0.2` 时（例如另一个 VPN 的解析器也匹配所有域名），照样是 `connected`，但 `system_dns` 为 false，`last_error` 写明原因。
  - 第 2 步之后任何一步失败，倒着拆掉已经起来的部分，报 `engine.failed`，原因写进 `last_error`。
- **断开**：先撤掉系统解析器（关掉 scutil 会话），再给引擎 `SIGTERM`，5 秒没退出就 `SIGKILL`，最后放开连接锁。
- **切场景、连接中 apply**：按上面的步骤整个重来，连接断一次。apply 的新配置起不来时，换回旧配置再连一次，apply 报错，配置不变（4.1）。
- **引擎的管道协议**：
  - 启动：`xdial __engine <tailscale 目录>`。环境变量只有 PATH；继承连接锁的描述符。
  - stdin：daemon 先写一个 JSON 值，即编译好的配置，之后一直开着、不再写。引擎读到 EOF 就说明 daemon 没了，自己退出，不会留下占着 TUN 的孤儿进程。launchd 杀进程组是另一道保险（6.1）。
  - stdout：引擎先写一行 JSON，`{"ready": true, "pid": …, "version": …}` 或 `{"ready": false, "version": …, "error": …}`。
    - `version` 是构建标识（版本加 revision）。和 daemon 不一致就不用这个引擎，例如二进制被换掉了。
    - `error` 经脱敏（4.3）后才写进 `last_error`。
    - 就绪之后，每当 AnyConnect 或 Tailscale 线路的状态变了，再写一行 `{"endpoints": {"<线路 id>": {…}}}`，最多半秒一行，见 3.5。超过 1 MiB 的行丢掉。
  - stdin 上，配置之后可以再写命令，一行一个 JSON：`{"tailscale_logout": "<线路 id>"}`（3.5）、`{"select": {"group", "member"}}`、`{"url_test": {"id", "tags"}}`（3.6）。引擎的回应就是之后的状态行；测速的结果单独一行 `{"test": {"id", "results"}}`。
  - stderr：sing-box 的日志，脱敏后写进引擎日志。
  - 以后要加的运行中交互（selector 手选、urltest 状态），也加在 stdin 和 stdout 上，仍是一行一个 JSON。
- **TUN**：
  - stack 显式写 `mixed`，不依赖上游的默认值，它随构建 tag 变；不开 `strict_route`；地址 `172.19.0.1/30` 和 `fdfe:dcba:9876::1/126`，`auto_route`。
  - 实测 `gvisor`、`system`、`mixed` 三种 stack 和打开 `strict_route` 都能正常上网；`mixed` 下经 UDP 和 TCP 问 `172.19.0.2` 都能得到回答。
- **不留残留**：实测引擎正常退出和被 `kill -9` 两种情况下，utun 接口和它的路由都随之消失，默认路由回到物理网卡，DNS 和 HTTPS 恢复正常。
- **引擎意外退出**（2026-10-28 用户定：放行直连）：
  - daemon 立即撤掉系统解析器，流量和 DNS 按系统原来的网络走（实测）。不做断网保护（kill switch）。
  - 按 1、2、4、8 秒退避重连。5 分钟内失败到第 5 次就停下：状态是 `failed`，`last_error` 写明原因，这段时间一直直连。
  - 停下之后，物理网络的 DNS 变了（例如换了网络），或者用户再次 `connect`，计数清零、重新开始。
  - 引擎还活着但不回答：定期检查（6.4）连续 3 次问不通 `172.19.0.2`，就杀掉引擎，按崩溃处理。
- **daemon 自己被杀**：
  - 临时键随 scutil 会话一起消失（实测 `kill -9` 之后 0.5 秒内已经没有）；引擎读到 stdin EOF 自己退出；launchd 也会杀掉进程组。
  - launchd 重新拉起 daemon。`state.json` 记着要连着，就按上面的步骤重连（实测）。旧引擎还没退出时拿不到连接锁，走退避重试。
  - 新 daemon 不去删这个键：它随旧会话消失，这一点由 e2e 的 `kill -9` 用例单独证明。
  - 恢复连接在控制序列里后台进行，本地 API 先开始回答，`status` 不用等连接起来。用户请求抢先改了连接（代次变了，或者已经连上），这次恢复就不做。
- **网络变化**：sing-box 自己跟随默认接口（`auto_detect_interface`）。物理网络的 DNS 变了，daemon 重载引擎（6.4）。

### 6.4 系统 DNS

**为什么要动系统 DNS**：实测只靠 TUN 加 hijack-dns 接管不了 DNS。

- 家用网络里，DNS 服务器常常就是网关，在本机所在的子网里。它的路由比 TUN 的路由更具体，DNS 查询根本不进 TUN。
  - 后果：查询以明文发给路由器；公司 VPN 的分割 DNS（例如 `corp.example` 只能由 VPN 的服务器解析）到不了 sing-box，域名解析失败。
- 把 DNS 服务器的 /32 路由进 TUN 也不行：服务器就是网关时，绑在物理接口上的直连出站找不到下一跳，实测整机断网。
- sing-box 的 `dns_mode` 在 Apple 平台上靠 NetworkExtension 设置接口 DNS，root 进程直接起 utun 时用不上：sing-tun 的 `tun_darwin.go` 不读这个选项（源码确认，没有实测）。

**做法**：连接期间，daemon 在 configd 的动态存储里加一个解析器，键是 `State:/Network/Service/<id>/DNS`，内容是：

```
ServerAddresses          : ["172.19.0.2"]
SupplementalMatchDomains : [""]
```

- `172.19.0.2` 在 TUN 网段里，发给它的查询会进 TUN，被 hijack-dns 接管。
- `SupplementalMatchDomains` 是只含一个空字符串的数组，表示匹配所有域名。
- 不写 `SearchOrder`：它只在匹配同样域名的解析器之间排序，管不了谁排第一。
- 只有 daemon 写这个键，配置里不能控制它，所以不违反 2.1。

**它是临时键**：
- daemon 常驻一个 `/usr/sbin/scutil` 子进程，在这个会话里用 `add <key> temporary` 加上它。会话结束时 configd 自动删掉这个键，不论 daemon 是正常断开、崩溃还是被 `kill -9`（实测）。
- 不写进持久的网络设置，重启也会消失。全程用 scutil，不需要 cgo。
- scutil 或 configd 卡住时不拖住 daemon：一次性的 scutil 命令 5 秒超时；往会话里写命令 2 秒超时；关会话不等正在进行的写，3 秒没退出就杀掉。

**监视和补写**：同一个会话用 `n.watch` 监视主服务的变化和所有服务的 DNS 键（含自己的）。daemon 收到通知，以及每 15 秒，检查一次：

- 物理网络 DNS 的第一个地址变了（3.3）：重载引擎（实测手动改 DNS 之后自动重载）。读到空的，或者新配置准备不了（例如睡眠唤醒时主服务的键短暂消失），保持现有连接不动；
- 自己的键没了，例如 configd 重启：在会话里再加一次，还不生效就换一个新会话；
- 会话自己退出了：开一个新会话重新加；
- 第一解析器不是 `172.19.0.2`：记一条事件，`status` 的 `system_dns` 变成 false，`last_error` 写明原因；
- 问一次 `172.19.0.2`（6.3 第 5 步），连续 3 次不通就重启引擎。

**实测结果**：

- 它成为系统的第一解析器，系统发出的查询都进了 sing-box；删掉之后第一解析器恢复原样。
- `State:/Network/Global/DNS` 跟着变成了它，所以物理网络的 DNS 要从主服务自己的键读（3.3）。
- 上游失败时不回落到路由器：让 `final` 线路不可达，6 次系统查询各等约 60 秒后失败，这期间物理接口上没有出现这些查询。等 60 秒是因为 sing-box 在上游出错时不回应（第 7 节）。

**接管的范围**：

- 接管的是不指定接口、也没有更具体匹配域的查询，也就是绝大多数系统查询。
- 不在接管范围的：
  - 匹配域更具体的解析器（`/etc/resolver/<域名>`、其他 VPN 的分割 DNS），在它们的域名上优先，这些查询按它们的设置走；
  - 指定了接口的查询（scoped query），发给那个接口自己的 DNS；
  - 描述文件配置的加密 DNS、iCloud 私有中继和 XDial 谁优先，没有核实。
  - 这些在 `xdial doctor`（M4）里检测并列出。
- **挡住加密 DNS 的自动升级**：
  - 实测系统会查询 `_dns.resolver.arpa`，发现上游的加密 DNS（DDR）。一旦升级成 DoT 或 DoH，查询就会绕开 sing-box。所以这个名字由 sing-box 自己回 NXDOMAIN（3.3），UDP 和 TCP 都实测过。
  - Firefox 自带的 DoH 不走系统解析器。按 Mozilla 的约定，对 canary 域名 `use-application-dns.net` 回 NXDOMAIN，它就不默认开启 DoH；用户在 Firefox 里手动打开的不受影响，不在保证范围内。
  - 只挡住这两条路。DHCP 或路由通告直接下发的加密 DNS（DNR，RFC 9463）不经过这个名字，没有挡。

### 6.5 日志

- **事件日志**：`private/events.jsonl`，一行一个事件，带时间、类型、相关的线路和场景，超过 10 MB 轮转，当前文件之外再留 3 份。
- **记录什么**：
  - 连接与断开；引擎的启动、退出、崩溃和不回答；重连停止；
  - 系统解析器的设置、撤销、补写，会话重建，第一解析器的变化；物理网络 DNS 的变化；
  - 配置 apply 与 revision；凭据的设置与删除，只记名字。
  - VPN 推送内容的变化在 M3 加（3.2）。
- **怎么读**：`xdial logs [--follow]`（M2）经本地 API 读；`xdial doctor`（M4）汇总诊断。返回前一样要脱敏（4.3）。
- **其他日志**：引擎日志同样 10 MB 轮转，再留 3 份；引擎退出时，管道里剩下的日志也读到最后一行。launchd 接的 stdout 和 stderr 只有 panic 会写，daemon 每次启动时发现超过 1 MiB，就挪到 `.1` 重新开始。

## 7. 留给后面的

- **M2 之后实测**：
  - Time Machine 排除和迁移助理是否跳过凭据目录（4.4）；
  - 只有 IPv6、物理网络的 DNS 只有链路本地地址时的行为。
- **已知限制**：
  - sing-box 在上游出错时不回应 DNS 查询，系统要等约 60 秒才失败（6.4 实测）。线路断了时，应用会卡在解析上。M3 再看能不能让上游回 SERVFAIL，或者用 urltest 之类的方式缓解。
  - 物理网络的 DNS 只用第一个地址（3.3）。
  - 连接时和定期检查的探测只证明查询进了 sing-box，不检查上游：物理网络的 DNS 选错时，经它的解析会失败，`status` 仍是 `connected`。`xdial doctor`（M4）补上游检查。
  - "上游失败时不回落到路由器"只测了上游不回应的情况；如果以后让 sing-box 回 SERVFAIL，要重测。
  - 安装时的版本核对比的是构建标识，不是文件内容。签名构建（M6）后改用签名。
  - 和其他全局 VPN 同时连着、更具体的解析器、指定接口的查询：`xdial doctor`（M4）检测并提示。
- **M3**：
  - 远程规则集的下载（3.4）和订阅（1.5）已实现。
  - Surge 格式的订阅；Clash 的 `GEOIP`、`RULE-SET` 等规则类型。
  - VPN 推送的内容 XDial 读不到（3.5），只能看到是不是全隧道；用户在公司网络实测后再定要不要做更多；
  - AnyConnect 的浏览器登录（SAML 等），和 App 一起在 M5 做；
  - AnyConnect 线路 `failed` 之后不自动重载；
  - `ts_omit_*` tag 加上之后运行是否正常：e2e 用临时 auth key 登录后到 `connected`（3.5）；
  - `exit_node` 算配置，当前场景用不到的 tailscale 线路不能登录（3.5）；
  - 允许清单要不要加 hysteria2 等类型。
- **M5**：App 怎么安装和升级 daemon（6.1）；凭据发往新地方时的本机确认（4.3、6.2）。
