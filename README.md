# onlymessh

把本机 UFW 的 IP 白名单绑定到一个域名的 DNS 记录上。

你给它一个域名（例如 `example.com`），它每 10 分钟解析一次；解析出来的每个地址都用
`allow from <地址>` 加进 UFW，同时删掉**其它**所有"允许某个 IP"的规则。带端口的规则
（例如 `22/tcp ALLOW Anywhere`）一条都不动，所以机器在你开放的端口上照常可访问，
变化的只是"谁有资格连进来"。

典型用途：家里或办公室的公网 IP 会变、用动态 DNS 名字跟踪它、或者一台跳板机的地址
在变而端口保持不变。

## 哪些规则归它管

`ufw status` 打出来的规则：

| 规则形态 | 是否被管理 |
|---|---|
| `Anywhere   ALLOW   1.2.3.4` | **是**，会加也会删 |
| `Anywhere (v6)  ALLOW  2001:db8::1` | **是** |
| `Anywhere   ALLOW   10.0.0.0/8` | **是** |
| `22/tcp   ALLOW   Anywhere` | 从不改动（端口规则） |
| `22/tcp   ALLOW   1.2.3.4` | 从不改动（带端口 + 源地址） |
| `Anywhere   DENY / LIMIT / REJECT ...` | 从不改动 |

也就是说，"清理其它允许 IP 的规则"= 所有 `Anywhere ALLOW <地址>` 里，不在本次解析
结果中的，全部消失。

注意：`allow from <地址>` 这条规则**不区分协议**。它是"该来源全放行"，所以名单里的地址
能 ping 通、也能连任何端口；名单外的地址在默认拒绝策略下什么都不通。

## 内置的安全约束

- **解析结果为空 = 什么都不改。** DNS 抖动绝不能把白名单清空、把人锁在门外。
- **ufw 未启用 = 什么都不改**，只记一条警告。
- **`--dry-run`** 只打印计划，不落盘。第一次跑先用它。
- **`keep = ["1.2.3.4"]`** 固定保留的地址（跳板机、备用入口、你当前 SSH 的来源）。
  落在一个被保留的 CIDR 里的地址同样会被保留。
- 单条规则加/删失败只记日志，主循环继续；systemd 单元是 `Restart=always`，
  不会静默死掉。
- 每轮都是幂等的：同样的输入再跑一遍不产生任何操作。

警告：按设计，域名一旦改指向别处，你就**会**从旧地址失去访问权。这就是功能本身。
第一次正式启用前，把你当前的访问地址放进 `keep`，给自己留条后路。

## 安装

```bash
git clone <仓库地址> && cd onlymessh
sudo ./deploy/install.sh
sudoedit /etc/onlymessh/config.toml     # 填你的域名
sudo systemctl restart onlymessh
journalctl -u onlymessh -f
```

手工方式：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
onlymessh --domain example.com --dry-run --once   # 先看计划
sudo onlymessh --domain example.com               # 常驻，600 秒一轮
```

## 命令行

```
onlymessh --domain 域名 [--interval 600] [--keep IP ...]
          [--ip-version {0,4,6}] [--dns-timeout 10] [--log-file 路径]
          [--config /etc/onlymessh/config.toml] [--ufw-cmd 路径]
          [--dry-run] [--once] [--version]
```

除 `--config` / `--dry-run` / `--once` / `--version` 外，其余都也可以写进 TOML 配置；
命令行参数优先。

配置文件示例见 `deploy/onlymessh.toml`：

```toml
domain = "example.com"   # 要跟踪的域名
interval = 600           # 检测间隔（秒）
ip_version = 0           # 0 = v4+v6，4 = 只 v4，6 = 只 v6
keep = ["1.2.3.4"]       # 永不删除的地址，可为空
dns_timeout = 10.0       # 单次解析超时
```

## 退出码

- `0` —— `--once` 正常结束，或收到 SIGTERM/SIGINT 正常退出
- `2` —— 找不到 ufw 或 ufw 不可用

## 目录结构

```
src/onlymessh/rules.py      解析 `ufw status`、给规则分类、算出变更计划
src/onlymessh/ufw.py        对 ufw 命令行的封装（allow / delete / status）
src/onlymessh/resolver.py   走系统解析器做 DNS 查询
src/onlymessh/sync.py       一次完整的同步流程
src/onlymessh/config.py     TOML + 命令行参数
src/onlymessh/cli.py        常驻循环、信号处理、日志
tests/fakeufw/ufw           测试用的有状态假 ufw
deploy/                     systemd 单元、配置示例、安装脚本
```

## 测试

```bash
pytest -q      # 18 个测试，不需要 root，不动本机防火墙
ruff check .
```

测试会启动真实子进程去调一个"假 ufw"（规则存在 JSON 文件里），所以子进程层、解析、
差异计算、幂等性都是端到端跑过的，但不会碰宿主机的防火墙。
