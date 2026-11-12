# proxy-health

对 [proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list) 的代理列表做全量健康探测：
记录每个节点的**入口真实归属**、**实际出口**、协议握手结果、延迟，并识别异常节点
（Tor 出口、出口与入口不一致、多入口共用同一出口等）。

## 为什么需要

- 列表宣称"每 5 分钟更新"，实测提交间隔中位数约 6.3 小时；jsDelivr 的 `Cache-Control`
  是 7 天，直接引用 `@main` 会拿到过期副本。本脚本用 GitHub API 取 commit SHA 后
  按 SHA 下载，确保数据版本可追溯。
- 列表里的国家/城市字段有约 1/4 不准，必须用实际出口核验。
- 存在伪造响应的节点（返回固定的假 JSON），只靠"HTTP 200"判断会把它们算成可用。
  本脚本用**自建回显服务**取出口 IP，避免被伪造结果欺骗。

## 用法

```bash
# 全量（默认），经前置代理，回显用自建服务
python3 probe.py --upstream 192.168.1.231:7890 \
    --echo whatsmyip.125478.xyz --output-dir data

# 抽样 1000 条，直连
python3 probe.py --sample 1000 --seed 20260101 --output-dir data

# 锁定某个列表版本
python3 probe.py --sha 65eb2c77eb3be5540be57a2eec0663e0e0e67ce2

# 用本地 data.json（跳过下载）
python3 probe.py --list-file /path/to/data.json --sample 100
```

主要参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--sample` | `0` | 抽样条数，0 = 全量 |
| `--seed` | `20260101` | 抽样种子，保证可复现 |
| `--sha` | 最新 | 锁定列表 commit |
| `--upstream` | 空 | 前置代理 `host:port`（HTTP CONNECT），空则直连 |
| `--upstream-auth` | 空 | 前置认证 `user:pass` |
| `--echo` | `whatsmyip.125478.xyz` | 回显域名，需返回含 `ip` 字段的 JSON |
| `--concurrency` | `120` | 并发数 |
| `--output-dir` | `data` | 输出目录 |
| `--no-entry-geo` | 关 | 跳过入口 IP 归属查询 |

## 输出

```
data/
├── latest.json                       # 最新一次汇总 + 可用节点清单 + 分片索引
├── latest-ok.txt                     # 可用节点，ip:port#CC，可直接喂给 proxyip.py
├── index.json                        # 所有历史运行的索引，便于趋势分析
└── history/
    ├── <run_id>.json                 # 单次运行的汇总快照（体积小）
    └── <run_id>-details-NN.json      # 逐条明细，每 3000 条一个分片
```

`latest.json` 的 `summary` 包含：

- `meta` — 列表 SHA、提交时间、下载时间、文件 SHA256、前置、回显、起止时间
- `list` — 原始条目数、去重后条目数、唯一 IP 数、按协议/国家分布
- `totals` — 探测总数、可用数、可用率
- `by_protocol` — 各协议的可用率
- `by_entry_country` — 按入口真实归属国家的可用率
- `exit_country` — 可用节点的出口国家分布
- `latency_ms` — min/p50/p90/p99/max 与延迟分档
- `anomalies` — Tor 出口、IPv6 出口、出口≠入口、出口国家≠入口国家、
  出口国家≠列表声明、多入口共用同一出口
- `entry_network` — 机房 vs 住宅 IP 统计
- `failures` — 失败原因归类

每条明细记录包含：`ip`、`port`、`protocol`、`declared_cc`、`declared_city`、
`anonymity`、`t_start`、`t_end`、`dur_ms`、`ok`、`stage`、`error`、
`http_status`、`latency_ms`、`exit_ip`、`exit_cc`、`exit_region`、`exit_city`、
`exit_isp`、`exit_colo`。

## 定时任务

`.github/workflows/probe.yml` 每天 **06:00 UTC+8**（cron `0 22 * * *` UTC）执行，
跑完后把 `data/` 提交回仓库。也可在 Actions 页面手动触发，并覆盖抽样条数、
前置代理、回显域名。

> 定时任务里默认**直连**（不配置 `--upstream`）。GitHub Actions 的 runner 在境外，
> 直连可达性通常好于国内环境。如需前置，在 `workflow_dispatch` 里填 `upstream`。

## 依赖

仅使用 Python 3.11 标准库，无第三方依赖。

## 判定标准

节点被计为「可用」需同时满足：

1. 经前置（或直连）能建立到该节点的 TCP 连接
2. 按 `protocol` 完成正确的代理握手（SOCKS4 / SOCKS5 / HTTP CONNECT）
3. 通过该代理成功请求回显服务并返回 HTTP 200
4. 回显内容是可解析的 JSON 且含 `ip` 字段

只满足 TCP 连通、或只返回 200 但内容不对的节点，一律记为不可用。
