# onlymessh 设计

## 目标

把本机 UFW 的 IP 白名单绑定到一个域名的 DNS 记录上：域名解析出哪些地址，就只有那些
地址能连进来。端口规则保持不变。

## 非目标

- 不做端口管理（端口的增删仍由人手工 `ufw allow 22/tcp` 完成）。
- 不做 DoH / DNSSEC 校验，只用系统解析器（跟随 `/etc/hosts`、`resolv.conf`）。
- 不管 DENY / LIMIT / REJECT 规则，那些一律只读。

## 判定：哪些规则归我们管

`ufw status` 的一行 = `(To, Action, From)` 三元组。只有满足三个条件的行会被管理：

1. `To` 是 `Anywhere` 或 `Anywhere (v6)`；
2. `Action` 是 `ALLOW`；
3. `From` 能解析成地址或 CIDR。

带端口的行永远不动：

- `22/tcp ALLOW Anywhere` —— 端口规则，跟来源无关。
- `22/tcp ALLOW 1.2.3.4` —— 虽然是"IP 规则"，但它同时限定了端口，删掉等于改端口策略。

## 一次同步的流程

1. 解析域名，得到期望集合 `D`（按 `ip_version` 过滤 v4/v6）。
2. `D` 为空 → 记错误日志，**不动防火墙**，本轮结束。这是最重要的一条：DNS 抖动不能把
   白名单清空。
3. 执行 `ufw status`，得到当前纯 IP 的 ALLOW 规则集合 `C`。
4. ufw 未启用 → 记警告，不动。
5. 算计划：`add = D - C`，`remove = C - D - keep`。
6. 先删后加（先删能保证在短暂窗口里策略是最严的），逐条执行，单条失败只记日志。
7. 幂等：同样的输入跑第二遍不产生任何操作。

## 失效模式与对策

| 场景 | 行为 |
|---|---|
| DNS 超时 / NXDOMAIN | 本轮跳过，保留现状 |
| ufw 未安装或非 root | 启动即报错，退出码 2 |
| 域名换 IP，而人正从旧 IP 通过 SSH 登录 | **会断**。用 `keep = ["旧地址"]` 留后路 |
| 规则被人工改动 | 下一轮（10 分钟内）自动纠正回来 |
| 想要 ICMP 彻底关闭 | 注意 `allow from` 是全协议放行，名单内的地址照样能 ping；需要另加 `-p icmp -j DROP` |

## 为什么不用 iptables/nftables 直接写

`ufw` 是用户已有的抽象层：规则带注释、`status` 可读、回滚方便；直接写 nft 会和 ufw
的落盘状态打架，下一次 `ufw reload` 就被覆盖。

## 测试策略

`tests/fakeufw/ufw` 是一个有状态的假 ufw（规则存 JSON），测试用真实子进程去调它，覆盖：
解析、分类、差异计算、幂等、DNS 失败保护、`--dry-run`、`keep` 列表、ufw 未启用。
真实 ufw 的 `allow from` / `delete allow from` 往返由维护者在真实机器上人工验证：
加一条示例地址 → 确认被解析成 IP 规则 → 删除 → 状态恢复原样。
