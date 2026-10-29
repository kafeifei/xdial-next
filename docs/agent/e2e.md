# 测试虚拟机与 e2e

用户日常用的机器上跑着旧 XDial；新版会接管默认路由，两者同时连会冲突。所以新版接管之前，凡是会动系统网络的验证，都只在 mbp64k 的测试虚拟机里做。

动 mbp64k 之前，先读 `~/Codes/lume-mbp64k/CLAUDE.md`。

## 跑一次

```sh
make e2e
```

[scripts/e2e-vm.sh](../../scripts/e2e-vm.sh) 依次做这些事：

1. 构建 darwin/arm64 的 `xdial`，和 [e2e/](../../e2e/) 下的用例一起拷到 mbp64k；
2. 从基础镜像 `xdial-base` 克隆出一台一次性虚拟机 `xdial-e2e-<run>`；
3. 以只读共享目录把文件交给它，在里面执行 [e2e/run.sh](../../e2e/run.sh)；
4. 无论成败，都停掉并删除这台虚拟机，清掉拷过去的文件。清理由 mbp64k 上的脚本自己完成，发起端断线或被杀时也会执行；本机再兜一次底。

结果写在 `build/e2e/<run>/results.jsonl`，每个用例一行 JSON：`{"case", "ok", "detail"}`。`lume ssh` 会把虚拟机里的 stderr 并进 stdout，原始输出另存在 `output.log`。全部用例通过时退出码为 0；一个结果都没有也算失败。一次运行约 30 秒。

一台 Mac 同时最多运行两台 macOS 虚拟机，vm4 已经占了一台，所以 e2e 一次只跑一个：脚本会在 mbp64k 的 `~/xdial-e2e/.lock` 上排队。一次运行最长约 20 分钟，超过 25 分钟的锁视为上次运行异常退出留下的，接管前先删掉锁里记的那台虚拟机；接管在一把互斥锁里进行，两个等待者不会删掉对方的锁。

## 写用例

- 用例写在 [e2e/run.sh](../../e2e/run.sh) 里，用 `report <名字> <true|false> <细节>` 输出结果。
- 一次性的实验放在 [e2e/experiments/](../../e2e/experiments/)，不进 `make check`，用 `XDIAL_E2E_CASES=e2e/experiments/<文件> make e2e` 跑；结果和结论记在 `docs/verification/`。
- 用例以 `lume` 用户运行。这个账号有免密 sudo，需要 root 的步骤（装 daemon、建 TUN）直接用 `sudo`。
- 虚拟机自带 `jq`。
- 每次运行都是新克隆的虚拟机，用例不需要清理系统状态。但"断开或卸载后没有残留"这类检查，要在同一次运行里由用例自己完成。

## 基础镜像 xdial-base

| 项 | 值 |
|---|---|
| 位置 | mbp64k（192.168.1.3）的 `kafeifei_bot` 账号，Lume 0.6.1 |
| 系统 | macOS 26.6.2（25G83），也就是主机能直接装的最新版本。用户日常用的是 macOS 27，需要时在虚拟机里升级 |
| 规格 | 4 核、8 GB 内存、80 GB 稀疏磁盘、NAT 网络 |
| 账号 | `lume` / `lume`（Lume 无人值守安装的默认账号），管理员，免密 sudo |
| 调整 | 关闭自动更新（`com.apple.SoftwareUpdate` 和 `com.apple.commerce`）；关闭 Spotlight 索引 |
| 平时状态 | 关机，只用来克隆 |

**重建基础镜像**：安装包已经缓存在 `~/.lume/ipsw/UniversalMac_26.6.2_25G83_Restore.ipsw`。

```sh
lume create xdial-base --ipsw ~/.lume/ipsw/UniversalMac_26.6.2_25G83_Restore.ipsw --unattended tahoe --cpu 4 --memory 8 --disk-size 80
```

**已知问题**：在 Lume 0.6.1 上用 26.6.2 无人值守安装时，`lume ssh` 已经能登录，Lume 自己的 SSH 健康检查却一直失败；约 5 分钟后它会删掉这台虚拟机。2026-10-25 的绕法是在健康检查期间做完下面几步，虚拟机就能保住：

1. 用 `lume ssh xdial-base` 配好免密 sudo、关掉更新和索引；
2. 在虚拟机里执行 `sudo shutdown -h now`；
3. 结束 `lume create` 进程。
