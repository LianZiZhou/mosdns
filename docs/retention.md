# DNS 域名证据保留策略

本次调整针对客户端继续使用 DNS TTL 已过期地址时，新 TCP / UDP 会话失去域名分流证据的问题。MosDNS lazy cache 最终返回的 TTL 为 5 秒，旧桥接按该 TTL 删除；客户端若未重新查询 DNS，新连接就只能回退到原嗅探路径。

## 开源实现核对

以下结论来自固定版本官方源码及底层缓存实现；不能用 DNS 应答缓存的配置推断 IP → 域名反查表的行为。

| 实现 | 反查证据的实际保留行为 |
| --- | --- |
| Mihomo v1.19.32 | 内置真实 IP 映射容量 4096。构造 LRU 时没有 `WithAge`，底层过期检查要求 `maxAge > 0`，所以虽写入 RR TTL，到期时间实际不触发删除；命中提升 LRU，容量满才淘汰。 |
| sing-box v1.11.0 | `cache.New()` 不配置 age 或 size，写入的 TTL 不触发检查，也没有容量上限。 |
| sing-box v1.13.21 | 独立 1024 条反查缓存。正 TTL 严格过期，命中 `Get` 只提升 LRU、不续期；零 TTL 是底层永久哨兵。 |
| dae（下列固定 commit） | DNS 默认容量 65536，默认 stale 窗口 60 秒；可设置 `optimistic_cache_ttl=0` 由容量淘汰。DNS 派生的是 IP → 路由位图，多个域名 owner 合并；连接命中不续 DNS TTL。 |

源码依据：

- Mihomo：[映射构造](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/dns/enhancer.go)、[写入 TTL](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/dns/middleware.go)、[LRU 过期条件](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/common/lru/lrucache.go)。
- sing-box v1.11.0：[reverse mapping](https://github.com/SagerNet/sing-box/blob/d09d2fb665f1a4aa0cefb1ce0298539867ba487b/route/route_dns.go#L23-L40)、[缓存检查](https://github.com/SagerNet/sing/blob/d9f6eb136d177971b9cfc2ae528eb1fa95486e49/common/cache/lrucache.go#L226-L249)。
- sing-box v1.13.21：[构造与 DNS 写入](https://github.com/SagerNet/sing-box/blob/628cb31ffa79cffffd34c2f9cde6cae044e4fc12/dns/router.go)、[底层 Get 与 GetAndRefresh](https://github.com/SagerNet/sing/blob/87773cc9c5b2a4e4fc05cbd2db304ba23ca13515/contrab/freelru/lru.go#L303-L548)。reverse mapping 使用前者。
- dae：[默认配置](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/config/config.go#L142-L148)、[缓存淘汰](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/control/dns_controller_cache.go#L708-L753)、[多个 owner 合并](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/control/domain_routing_tracker.go#L76-L105)。

由此得出的设计取舍：只使用 `now + 10 × TTL` 的滑动过期，仍比 Mihomo 更容易丢掉长时间闲置的映射。LRU 模式应在窗口结束后继续保留记录，直到容量淘汰。它匹配内置映射的时间宽容程度，同时用客户端维度减少全局 IP 映射混淆；不承诺消除共享 IP 歧义。

## 配置与语义

推荐 `size: 262144`、`retention: {mode: lru, ttl_multiplier: 10, min_window: 300, max_window: 86400}`，完整部署说明见 [mihomo-bridge.md](mihomo-bridge.md#dns-到期路由续期与容量淘汰)。旧配置默认 `ttl`，行为不变。

三种时间分别是：

- `dns_expires_at`：最近最终应答的 DNS 到期时间，连接查询不能修改。
- `expires_at`：提供给 v1 调用方的路由有效期。客户端路由命中按窗口续期；LRU 的全局与诊断响应也计算充足的临时有效期，但不改写原客户端的存储状态。
- 索引寿命：LRU 模式无时间硬截止，由观察记录容量限制；sliding 模式在路由窗口结束时删除；ttl 模式按原 DNS TTL 删除。

观察顺序只由最终 DNS 应答更新，决定域名归属；访问 LRU 由真实路由查询更新，决定容量淘汰。默认完整查询和 stats 是只读诊断，不提升热度、不续期。Mihomo 只在新连接 / 新 UDP NAT 会话查询，已有 HTTP/2 连接中的每个请求不触发续期。

本实现保持“客户端优先、最近真实 DNS 观察胜出”的既有规则。保留多个域名时 `conflict=true`，不会因为连续命中选中记录而把它改成新的 DNS 观察。长期保留会延长共享 CDN IP 歧义的存在时间；容量淘汰、重启丢失状态、客户端地址变化及绕过 MosDNS 仍可影响结果。

## 容量实测与复现

容量按 `(client, IP, domain, source)` 观察记录计数，不等同于独立 IP 数，也不是内存的字节硬上限。按实际记录逐步分配，空索引不预分配全部容量。

2026-10-18，Go 1.27.1、Windows/amd64、Ryzen 9950X3D，262144 条实际 LRU 索引（包括记录域名字符串），主动 GC 后净活跃堆：

| 记录分布 | 填满后 | 满容量继续换入 294912 条后 |
| --- | --- | --- |
| 每条独立 client / IP / domain | 380.103 MiB（约 1520 B/条） | 380.113 MiB |
| 同 client / IP，不同 domain | 182.673 MiB（约 731 B/条） | 182.682 MiB |

两个场景均检查 records、访问 LRU、双索引 bucket 和域名引用计数一致；LRU expiry heap 的长度、容量均为 0；时钟前进十年不按 TTL 删除，热点保留、冷记录被容量淘汰。上述数值不包括进程基础内存、DNS 缓存、HTTP、GC 峰值或其他插件，较长域名也会增加内存。2 GiB 路由器应为索引预留数百 MiB，同时检查其余服务占用；小内存设备须降低 `size`。

资源测试默认跳过，显式启用后在开发机器运行：

```sh
MOSDNS_RETENTION_RESOURCE=1 go test ./plugin/executable/domain_mapping -run '^TestRetentionResource' -count=1 -v
MOSDNS_RETENTION_RESOURCE=1 go test ./plugin/executable/domain_mapping -run '^$' -bench '^BenchmarkRetention' -benchmem
```

纯索引基准不包含 JSON、HTTP、锁竞争及生产 GC，不能将其耗时当作实际连接增加的延迟。协议仍复用 HTTP 连接，每次查询只有原来的一次往返，没有新增握手、能力探测或重试。

## 保留策略验证

本轮两仓库全量 `go test ./...` 及修改包 `go vet` 通过。Fake clock 覆盖 TTL 5 秒后闲置 48 小时、300 秒 TTL 每次命中延至 3000 秒后、TTL=0、诊断不续期、全局不续其他客户端、窗口临界值、取消请求和溢出。固定 seed 的 5000 步独立参考模型验证 DNS 归属、冲突、访问 LRU 及所有索引计数。32 位配置测试也通过。

独立 Windows 真实进程测试关闭 Mihomo DNS 和报文嗅探，以纯数字 SOCKS 目标验证：TTL 5 秒经过 6 秒后 TCP/UDP 仍按 DOMAIN 规则通过，TTL 300 秒获得约 3000 秒有效期，冷记录超过单次路由窗口仍命中，最新 DNS 能改变同客户端分流、其他客户端不受影响；连接 API 展示新诊断。旧版 bridge Mihomo 也成功使用新 MosDNS API。严格 TTL 兼容脚本另通过 1000 条 TCP、100 个 UDP 会话、可信 ECS、重载、过期及嗅探回退。

```sh
python3 scripts/domain_bridge_retention_smoke.py \
  --mosdns /absolute/path/mosdns \
  --mihomo /absolute/path/mihomo \
  --work-dir /absolute/path/retention-results
```

可选 `--legacy-mihomo /absolute/path/older-bridge-core` 验证旧消费者兼容；需要已经包含 v1 桥接功能的旧内核。测试不访问公网 DNS，不改变生产配置。当前开发环境没有 C 编译器，尚未执行 race detector。
