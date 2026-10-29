# M2：TUN 和系统 DNS 的实测记录

ARCHITECTURE.md 第 6 节里标"实测"的结论，出处都在这里。环境都是 mbp64k 上由 `xdial-base` 克隆的一次性虚拟机：macOS 26.6.2（25G83），NAT 网络，网关兼 DNS 服务器 192.168.64.1，sing-box v1.14.0-beta.2。

"系统查询"指经 mDNSResponder 的解析，用 `dscacheutil -q host` 发起；`dig` 自己读 `/etc/resolv.conf`、直接发包，只用来直接问某个服务器。

## 1. TUN 的 stack 和残留（2026-10-28）

方法：一次性程序直接起 sing-box 的 TUN（`auto_route`，direct 出站），分别用四种设置，各自检查运行中的路由、系统查询和 HTTPS，再分别用 SIGTERM 和 `kill -9` 结束，检查 utun 个数、默认路由、DNS 和 HTTPS 是否回到原样。脚本当时在本地的实验分支上，用的隐藏命令已经删掉，这里只留结果。

| 设置 | 运行中 | SIGTERM 之后 | `kill -9` 之后 |
|---|---|---|---|
| `gvisor` | 路由进 utun，查询、HTTPS 正常 | 恢复原样 | 恢复原样 |
| `system` | 同上 | 恢复原样 | 恢复原样 |
| `mixed` | 同上 | 恢复原样 | 恢复原样 |
| `gvisor` + `strict_route` | 同上 | 恢复原样 | 恢复原样 |

## 2. 只靠 TUN 接管不了 DNS（2026-10-28）

- DNS 服务器是网关 192.168.64.1，在本机子网里。运行中 `route -n get 192.168.64.1` 走 en0，不走 utun；sing-box 的日志里没有系统查询。
- 再把 192.168.64.1/32 也路由进 TUN：运行中系统查询拿不到结果，HTTPS 失败（`000`），整机断网；退出后恢复。
- `dns_mode` 没有实测。结论来自源码：sing-tun 的 `tun_darwin.go` 不读这个选项，它只在经 NetworkExtension 的平台接口上起作用。

## 3. 动态存储里的解析器（2026-10-28）

方法：TUN 起来后，用 scutil 在 `State:/Network/Service/<id>/DNS` 写 `ServerAddresses = [172.19.0.2]`、`SupplementalMatchDomains = [""]`。

- `scutil --dns` 的 resolver #1 变成 172.19.0.2，标记 Supplemental；系统查询和 HTTPS 正常。
- 系统查询确实进了 sing-box，由第 5 节 e2e 的断言证明：发一次 `example.org` 的系统查询，sing-box 日志里这个名字的行数随之增加（sing-box 在 info 级别只记有应答记录的查询，所以不能用随机生成、不存在的名字）；这一步的实验本身只记录了解析器的样子。
- 删掉键之后，resolver #1 回到 192.168.64.1。
- sing-box 的日志里能看到系统发出的 `_dns.resolver.arpa` 查询，即系统在找上游的加密 DNS（DDR）。

## 4. 临时键、通知、回落、TCP（2026-10-28）

脚本：[e2e/experiments/system-dns.sh](../../e2e/experiments/system-dns.sh)，用 `XDIAL_E2E_CASES=e2e/experiments/system-dns.sh make e2e` 重跑。

| 项 | 做法 | 结果 |
|---|---|---|
| 临时键 | 一个 scutil 会话 `add <key> temporary`，然后关掉它的 stdin | 会话活着时键在；stdin 关掉后 scutil 退出，键随之消失 |
| 被杀的会话 | 同上，然后 `kill -9` 这个 scutil | 键消失 |
| 通知 | 同一会话 `n.add` 两个键再 `n.watch`，另一个会话改其中一个键 | 输出 `changedKey [0] = <键>`；开着通知时同一会话还能继续执行命令（又加了一个临时键） |
| `State:/Network/Global/DNS` | 加上匹配所有域名的键前后各读一次 | 加之前是 192.168.64.1；加之后变成 172.19.0.2，来源标着 Supplemental。所以物理网络的 DNS 不能从它读 |
| 上游失败时的回落 | 先做阳性对照：连接前发一次随机域名的系统查询，在 en0 上抓 53 端口。再让 daemon 连一个 `final` 线路不可达的场景，同样抓包，发起 6 次随机域名的系统查询 | 对照：连接前的查询在 en0 上抓到 2 个包，抓包有效。连接后每次约 60 秒后失败，en0 上没有出现这些域名的查询，没有回落到 192.168.64.1（2026-10-28 第一次运行没有对照，10-29 加上对照重跑，结果相同） |
| UDP 和 TCP | daemon 用 `mixed` stack 连着，`dig` 和 `dig +tcp` 直接问 172.19.0.2 | 都得到回答；`_dns.resolver.arpa` 两种都回 NXDOMAIN；到 172.19.0.2 的路由是 utun |

## 5. daemon 的端到端用例（2026-10-28）

[e2e/run.sh](../../e2e/run.sh) 的 M2 部分，每次 `make e2e` 都跑。2026-10-29 的一次结果是 25/25 通过，其中：

- 不是控制台用户的 `nobody` 调用 `status`，收到 `api.permission`；
- 连接后路由进 utun，resolver #1 是 172.19.0.2，sing-box 日志里有 DNS 交换，`physical_dns` 是 192.168.64.1；
- `networksetup -setdnsservers` 把 DNS 改成 1.1.1.1 后，daemon 用新服务器重载了引擎，resolver #1 仍是 172.19.0.2，HTTPS 正常；
- 连接中切场景、连接中 apply（重载，结果带 `reloaded`）、再切回：都成功，`last_error` 为空，没有撞上连接锁；
- 只 `kill -9` 持有临时键的 scutil 会话：daemon 开了新会话把键补回，事件日志有 `dns_session_restarted`，引擎没动；
- 连接中 `kill -9` daemon：0.5 秒后键已经不在。新 daemon 启动时不删这个键，所以键是随旧会话消失的；launchd 拉起新的 daemon 后恢复连接，只有一个引擎；
- `kill -9` 引擎：0.3 秒后键已经不在（放行直连），随后自动重连；
- 连接中重新 `daemon install`：装完自动恢复连接；
- 断开和 `uninstall --purge` 之后，没有带 172.19.0.1 的接口，默认路由、resolver #1、DNS 和 HTTPS 都回到连接前，没有留下文件和进程。用例只数带 XDial 地址的接口，不比 utun 总数：系统服务自己的 utun 在开机后会陆续增加。
