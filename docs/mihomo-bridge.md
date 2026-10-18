# MosDNS 与 Mihomo 域名映射桥接

此分支让 MosDNS 记录发送前最终 DNS 应答中的地址，让 Mihomo 查询域名用于真实 IP 连接的分流。DNS 链路保持 `LAN → dnsmasq → MosDNS → 原有上游`；业务连接仍拨号到原始目标 IP。

开发基线：MosDNS `9cfb7ce985599c087cb7ccfb1531d0c0f4021242`；Mihomo `v1.19.32`（`88dcbf7f1614a67c3b36b848ee3592dfa92ada36`，官方 `Meta` 内核分支）。长期维护分支为 [MosDNS fork 的 main](https://github.com/LianZiZhou/mosdns/tree/main) 和 [Mihomo fork 的 Meta](https://github.com/LianZiZhou/mihomo/tree/Meta)，后者也是 Mihomo fork 的默认分支。

## 部署顺序

1. 分别构建 MosDNS fork 的 `main` 和 Mihomo fork 的 `Meta`，保留旧二进制及配置用于回滚。
2. 按 [MosDNS 示例](../examples/mihomo-bridge.yaml) 合并配置，替换示例上游地址和客户端网段。保留已有 `client_ip` 策略：新入口在执行插件前恢复客户端地址。
3. 将 [dnsmasq 片段](../examples/dnsmasq-bridge.conf) 合并到当前 OpenWRT 管理的配置入口，检查生成的实际配置及 `dnsmasq --version`。`strip-subnet` 与 `add-subnet=32,128` 必须同时生效。
4. 先启动 MosDNS，确认 API 返回 JSON，再切换 dnsmasq 上游。核对两个不同策略客户端针对同一域名的应答和查询日志。
5. 在 Mihomo 加入下方配置并重载；保留现有代理、分流及透明代理配置。

```yaml
domain-mapping:
  enable: true
  timeout: 50 # 毫秒；所有 provider 共享一次总预算
  max-connections: 16 # 每个 provider 的 HTTP 连接上限
  max-inflight: 128 # 当前运行时全部未完成的共享查询上限
  providers:
    - name: mosdns
      type: mosdns-http-v1
      endpoint: http://127.0.0.1:9091/plugins/domain_index/v1/lookup
```

桥接不要求 Mihomo `dns.enable` 或 `sniffer.enable`。未命中、容量饱和、超时或错误时继续原处理流程；已有嗅探配置可作为回退。映射命中时跳过报文嗅探，防止 ECH 外层名称覆盖 DNS 证据。

此 API 没有新增鉴权。示例绑定 loopback，仅供同机可信程序使用；不要将包含客户端查询关联的 API 暴露到 LAN/WAN。也不要把 dnsmasq 上游设回链路中的 Mihomo DNS，形成解析环。

## 可信 ECS 与客户端规则

`udp_server`、`tcp_server`（含 DoT）、`quic_server` 和 `http_server` 均支持服务器级参数：

```yaml
trusted_ecs: ["127.0.0.1/32", "::1/128"]
```

默认空列表，不从 ECS 恢复身份。ECS 信任判断只使用真实传输对端 `PeerAddr`。仅当真实对端命中 CIDR，且请求具有唯一、合法的 IPv4 `/32` 或 IPv6 `/128` ECS、scope 为零时，入口才覆盖 `ServerMeta.ClientAddr`。错误 CIDR 在启动时报错。

CIDR 匹配忽略 IPv6 地址的接口 zone，原始 `PeerAddr` 仍保留 `%eth0` 等信息。例如 `fe80::/64` 同时信任该地址范围内经 `eth0`、`eth1` 等接口连接的对端；CIDR 本身不约束接口。需要限制入口接口时，应通过监听配置和防火墙实现。默认 loopback 配置不受此影响。

HTTP 的 `src_ip_header` 无法改变 ECS 信任判断，但该选项原有的行为会直接将头部地址作为 `ClientAddr`。若开启此选项并允许终端直达 HTTP 入口，终端仍能伪造头部身份，影响 `client_ip` 策略及映射归属；配置 `trusted_ecs` 不会阻止这条独立路径。此类入口应仅允许可信反向代理访问，并由代理覆盖客户端地址头。普通 HTTP 代理也不会自动清理用户提供的 ECS，只有能可靠生成或覆盖 ECS 的转发器才适合加入 `trusted_ecs`。

恢复发生于所有插件之前，因此 `client_ip`、限速、查询日志、fallback 和 lazy cache 的上下文副本使用同一个客户端地址。`PeerAddr` 保留传输来源，`ClientAddrFromECS` 标记身份来源；日志可检查 `client`、`peer`、`client_source`。

缺失、不可信、部分前缀、重复、无效地址等 ECS 不覆盖客户端身份。畸形 wire 长度在入站解码时拒绝，即使没有开启恢复；这是为防止 DNS 库把截短地址补零后误认成完整地址。合法的其他 EDNS 选项不受影响。

ECS 代表本次 DNS 查询的源地址，不能自动合并设备的 IPv4 与临时 IPv6 地址。通过 IPv4 查 DNS、通过 IPv6 建连时，客户端索引可能无法匹配，会回退到全局索引。

MosDNS 默认把原 OPT 留在 `ClientOpt`，上游查询从干净 OPT 开始，内部完整 ECS 不自动外发。但 `ecs_handler.forward: true`、`ecs_handler.send: true` 和 `forward_edns0opt 8` 会重新携带地址，迁移时必须检查。内部身份 ECS 不应复用为公网 ECS；需要公网 ECS 时使用独立 `preset` 策略，并关闭原 ECS 转发。

## 缓存与观察位置

```text
入口恢复 ClientAddr
  → domain_mapping 外层
    → client_ip 选择解析策略
      → 该策略独立 cache
        → 原有 forward / fallback
    ← 策略最终选择的应答
  ← 可选地址筛选及临时预留
入口处理 UDP 大小限制（TCP 无此截断），再编码最终应答
  → 成功应答完成编码且非 TC：登记映射，将预留转为 TTL 租约
  → 编码失败、错误应答或 TC：释放预留，不登记该应答
传输层发送已编码应答
```

不同解析策略使用独立 cache 实例及独立 dump 文件；同一策略的客户端可共用 cache。隔离边界是整个解析策略，包括可能改变应答的公网 ECS。不要在客户端分支之前放共享解析缓存，也不要让不同策略引用同一 cache tag。

从共享缓存迁移时，采用新的独立 dump 路径并冷启动，不把旧共享 dump 复制给各策略。策略变更后清理受影响实例的缓存与旧 dump。现有 `/plugins/<cache-tag>/flush`、`/dump`、`/load_dump` 仍按实例工作。

`domain_mapping` 必须包在所有缓存、fallback 和应答变换外层。它在链路返回后准备观察，并等待入口完成 UDP 截断及最终编码后再登记。普通命中与 lazy 命中均按最终应答记录，lazy 应答采用返回的短 TTL；后台刷新和竞争失败的备用应答不会提前写入索引。

最终 `TC=true` 的截断应答整包不作为证据，后续 TCP 重试成功后才登记完整应答。编码失败或最终错误应答也不登记，并释放本次临时预留。登记发生在传输层写入之前，避免客户端收到 DNS 应答后立即建立业务连接时映射尚未就绪；这不能证明终端已经收到。后续 socket 写入失败时不会回滚已登记的映射与 TTL 租约。

dnsmasq 的动态 ECS 缓存行为依赖版本。目标是每个客户端的上游 DNS 请求都抵达 MosDNS，不能被共享缓存提前回答。已用 dnsmasq 2.92（Ubuntu 包 `2.92-1ubuntu0.5`）实测动态 `/32,/128` 模式和非零缓存。更旧版本应按实际包复测；不要直接套用“关闭缓存”到使用 `--dnssec` 的实例。dnsmasq 自己生成的 hosts/DHCP/local 应答不会经过 MosDNS，当前不纳入桥接索引。

## 插件配置与 HTTP v1

```yaml
- tag: domain_index
  type: domain_mapping
  args:
    size: 65536
    api:
      max_concurrent: 128
      timeout: 1000 # 毫秒
    allocation:
      enable: false
      size: 65536
```

`size` 是观察记录上限，默认 65536；每个客户端、域名、IP、来源组合占一个记录。容量满时淘汰最久未观察的记录；全局索引复用这些记录。索引仅保存在内存中，重启后由新 DNS 应答重建。

```text
GET /plugins/domain_index/v1/lookup?ip=203.0.113.8&client=192.168.10.20
GET /plugins/domain_index/v1/lookup?ip=203.0.113.8&client=192.168.10.20&view=route
GET /plugins/domain_index/v1/stats
```

`ip` 必填，`client` 可选，均为 IP 字面量。`view` 可选，只接受 `full` 或 `route`；省略时为 `full`。这些字段的非法或重复参数返回 HTTP 400；有效查询返回 HTTP 200 与 `status: hit|miss`。客户端索引优先，未命中查全局；多个域名共享地址时选择最近观察的域名，并返回冲突信息。时间使用 RFC3339Nano。

`view=route` 在 hit 和 miss 时均省略整个 `candidates` 字段，其他顶层字段与同一时刻的完整查询一致。新 Mihomo 始终请求此精简视图；旧 MosDNS 忽略该参数并返回完整 v1 响应时，新 Mihomo 仍能使用，因此不需要能力探测或额外往返。默认视图及 `view=full` 保留原有诊断响应。

每个客户端/IP 及全局/IP 索引分别维护观察顺序和不同域名的有效记录计数，精简查询直接读取最新有效记录及冲突状态，不扫描全部候选。更新、刷新、过期和容量淘汰同步维护这些索引。观察记录的过期清理仍有实际工作量：API 每批最多清理 128 条观察记录并释放锁、检查取消，避免整批过期始终占住 DNS 登记所用的锁；普通 DNS 登记也只进行有界的观察记录清理。没有过期积压时，路由记录选择为常数时间。

`candidates` 是按最近观察顺序排列、按域名去重的诊断列表，最多返回 **32 个域名**，不表示索引中的全部记录。顶层 `domain` 等字段仍对应最近的候选；所用客户端或全局索引范围内存在两个或以上有效域名时，`conflict` 保持为 `true`。此上限不会淘汰观察记录或改变 TTL、客户端优先级及选中域名，避免大量共享 IP 候选使 HTTP 响应超过 Mihomo 的读取上限。

```json
{
  "version": 1,
  "status": "hit",
  "ip": "203.0.113.8",
  "domain": "example.com",
  "scope": "client",
  "source": "a",
  "observed_at": "2026-10-18T00:00:00Z",
  "expires_at": "2026-10-18T00:05:00Z",
  "conflict": false,
  "candidates": [{
    "domain": "example.com",
    "source": "a",
    "observed_at": "2026-10-18T00:00:00Z",
    "expires_at": "2026-10-18T00:05:00Z"
  }]
}
```

`source` 为 `a`、`aaaa`、`https_hint` 或 `svcb_hint`。普通 A/AAAA 查询只沿 Answer 中从原问题可达的 CNAME 链记录地址。HTTPS/SVCB 查询还会检查相关 Additional：沿 CNAME 和同类型 AliasMode 查找服务记录，再按 ServiceMode 的目标名称查找 A/AAAA；目标为 `.` 时使用服务记录自身名称，地址查找可继续沿 CNAME。HTTPS 与 SVCB 类型不互相串接，无关 Additional 不作为证据。

AliasMode 最终目标的 A/AAAA 也可作为客户端回退端点证据；中间别名的地址不采用。同一 RRset 存在 AliasMode 时忽略其中的 ServiceMode 目标和 hints。

地址与 hints 均采用自身和关联链的最短 TTL；HTTPS/SVCB hints 单独标识来源，原 ECH 参数保持原样。重复观察不能提前撤销同一客户端先前仍有效的应答。

miss 缺省命中字段，返回 `conflict: false`；完整视图还返回 `candidates: []`，精简视图不返回此字段。Mihomo 要求命中带有尚未过期的 `expires_at`；不缓存已完成的查询，仅合并同时在途的相同客户端＋目标查询。

`/v1/stats` 提供观察记录数、淘汰次数、分配开关、活动租约数、分配成功/不安全/耗尽/容量降级计数与降级截止时间，并提供 `api_active`、`api_rejected` 和 `api_timeouts`，分别表示正在执行的 API handler 数、因容量饱和被拒绝的累计请求数与查询或 handler 应答写入报告超时的累计次数。stats 本身也占用 API 容量；`api_active` 不包括 handler 返回后 HTTP 服务仍在完成的最终缓冲写入。Mihomo 连接元数据的 `domainMappingHost` 和 `domainResolution` 可核对来源、范围、冲突、状态与有效期。

### API 与连接资源限制

`api.max_concurrent` 默认 128，`lookup` 和 `stats` 共用，达到上限的新请求立即尝试返回 HTTP 503，不再排队等待索引锁。`api.timeout` 默认 1000 毫秒；省略或填写 `0` 使用默认值，负数无效。索引锁等待、查询和分批过期清理响应请求取消及截止时间，应答写入与 HTTP 服务自动读取未消费请求体使用同一绝对截止时间，包括 GET 的 Content-Length、chunked 数据及 trailer；拒绝响应也受到同一读写截止时间约束。截止时间保留至 handler 返回后的最终写入和请求体关闭，正常完成后由 HTTP 服务重置，保持后续 keepalive 请求可用。查询超时也尝试返回 HTTP 503；但截止时间已到或应答已开始写入时，服务端可能只能终止写入，客户端收到连接关闭或不完整应答，不能保证 503 送达，也不能改写已经发出的状态。这里限制的是插件 handler 中的请求，不是 MosDNS 整个 HTTP 服务器的 socket 总数，也不覆盖进入 handler 之前读取请求头的时间，更不是调度延迟的硬实时保证。

Mihomo 的默认预算仍为 50 毫秒，连接等待、建立 TCP/TLS、HTTP 读写、解析及多个 provider 共用原始截止时间。`max-connections` 默认 16，限制每个 provider 的连接；`max-inflight` 默认 128，限制当前运行时尚未结束的共享查询，包括等待连接和已经超时但尚未退出的工作。相同客户端/IP 的有效在途查询仍可共享；容量满时不同的新查询立即回退，不增加无限等待队列。两项填写 `0` 使用默认值，负数无效。

这些上限不会延长查询预算或缓存已完成的域名结果。较低的上限能够减少资源占用，但也可能让突发业务更早回退；应结合 `api_rejected`、`api_timeouts` 和 Mihomo 的连接诊断调节。50 毫秒是等待预算，不是调度、GC 和原有后续分流的硬实时上限。配置重载会创建新的 Mihomo 运行时；旧运行时只完成既有工作，因此短时间内新旧运行时的资源可能并存。

## 可选真实 IP 分配

`allocation.enable` 默认关闭。开启后，仅从普通且可安全筛选的 A/AAAA 应答中，按地址族选取一个**该域名本次上游实际返回的地址**；不虚构地址，不借用其他域名的地址。优先延用仍在候选池且仅由本域名持有的地址，否则选择全局未占用地址。复制应答后筛选，缓存保留完整候选。

筛选阶段临时预留所有计划发送的关联地址，包括耗尽回退、未筛选应答和 hints，防止并发查询重复分配。最终应答成功编码且非 TC 时，按编码后仍存在的证据建立 TTL 租约并释放预留；失败或 TC 则只释放预留。

活动 TTL 租约不因容量压力提前淘汰；容量不足时保守暂停筛选，直至无法记录的成功应答全部过期。临时预留表达到容量上限时，也会在相关请求完成前暂停筛选；请求完成后，根据实际编码结果决定是否需要继续按 TTL 降级。`allocation.size` 默认继承 `size`。

带 CNAME、DNSSEC DO/AD/CD/RRSIG、HTTPS/SVCB 或已知仍有效的 HTTPS/SVCB 关联时跳过筛选。候选耗尽、容量不足或不安全时保留原应答并增加诊断计数。重复地址取最短 TTL。分配只能降低冲突概率；重启丢失租约、客户端超 TTL 使用旧地址、后续 HTTPS 应答及新候选重叠，均不能保证绝对唯一。

## 验证与限制

两仓库分别运行 `go test ./...`。新增测试覆盖可信 ECS 的 UDP/TCP/DoT/DoQ 实际入口、HTTP 头部边界、非法 ECS、旧 `client_ip` 策略、独立缓存及 dump/lazy 刷新、映射 TTL/冲突/缓存命中、分配并发/容量/安全跳过，以及 Mihomo 契约、超时、并发、热重载、TCP/UDP 入口与拨号地址保持。

审计回归额外覆盖最终 UDP 截断、编码失败及预留释放，HTTPS/SVCB 相关 Additional 的目标、类型和 TTL 边界，4000 个长域名候选及 65536 条观察记录，带 zone 的 IPv6 可信对端，以及 provider 迟到、旧请求退出与新请求共享的超时边界。

跨进程脚本只依赖 Python 标准库与编译后的二进制，不使用公网 DNS，不需要透明代理或 root：

```sh
python3 scripts/domain_bridge_smoke.py \
  --mosdns /absolute/path/mosdns \
  --mihomo /absolute/path/mihomo \
  --dnsmasq /absolute/path/dnsmasq \
  --connections 1000 \
  --work-dir /absolute/path/test-results
```

省略 `--dnsmasq` 时直接注入可信 ECS，可用于 Windows。脚本启动独立上游与回显服务，关闭 Mihomo DNS/嗅探，以数字目的地址经 SOCKS 检验规则命中；同时检查客户端上游隔离、缓存命中观察、内部 ECS 不外发、跨地址族回退、热重载与 provider 停机后的 HTTP 嗅探回退。额外直接查询 MosDNS，确认截断应答不会覆盖旧映射、HTTPS 仅登记相关 Additional。精简查询的检查覆盖与完整视图的一致性、客户端与全局冲突、到期后的全局回退及 miss；本地旧版 API 模拟器忽略 `view` 并返回完整 JSON，验证新 Mihomo 的兼容行为。每个 UDP 会话使用新源端口并核对后续包。结果和进程日志保留在指定目录。

真实 dnsmasq 2.92 Linux 联调中，1000/1000 条 TCP 连接与 100/100 个 UDP 会话通过。这证明可重复的本地链路，不代表已复现原现场约 4% 的失败，也不等同于 OpenWRT Netfilter/TProxy 实机验收。当前缺少 CGO 编译器，未运行 Go race detector。

此前应答边界与 ECS 修复的检查记录（2026-10-18，Go `1.27.1`，`CGO_ENABLED=0`）：

| 检查 | 结果 |
| --- | --- |
| 两仓库 `go test ./...` | 通过 |
| 新增/修改包的 `go vet` | 通过 |
| Windows 直接可信 ECS 跨进程测试 | TCP 1000/1000，UDP 100/100，重载与回退通过 |
| WSL Linux amd64 + 真实 dnsmasq 2.92 | TCP 1000/1000，UDP 100/100，ECS 覆盖、缓存隔离与回退通过 |
| Linux arm64 与 mipsle softfloat | 两个内核均交叉编译成功，尚未设备运行 |
| 三份示例配置 | MosDNS 实际启动/API、Mihomo `-t`、dnsmasq `--test` 通过 |
| Go race detector / OpenWRT 透明代理现场 | 未验证 |

精简查询及资源限制的验收还包括：route/full 选择与冲突语义一致、刷新/过期/淘汰后的索引一致、连接及共享查询容量约束、取消等待与超时后台资源回收，以及服务端拒绝和超时诊断。性能应同时测量映射查询及 DNS 应答延迟，包含大桶、批量过期和突发负载；桌面测试不代表目标 ARM/MIPS 设备的 p99 延迟。

本轮精简查询及资源限制验证（2026-10-18，Go `1.27.1`，`CGO_ENABLED=0`）：

| 检查 | 结果 |
| --- | --- |
| 两仓库 `go test ./...` 与相关包 `go vet` | 通过 |
| Windows 可信 ECS 跨进程测试 | TCP 1000/1000、UDP 100/100；route/full 一致、过期回退及旧 API 兼容通过 |
| WSL Linux amd64 + 真实 dnsmasq 2.92 | TCP 1000/1000、UDP 100/100；ECS 策略、缓存隔离、TCP DNS、截断与 HTTPS Additional、route/full、到期、重载、旧 API 兼容及原嗅探回退全部通过 |
| Linux arm64 与 mipsle softfloat | 两个内核均交叉编译成功，尚未设备运行 |
| 实际 `net.Pipe` 阻塞写入 | 完整响应 handler 写入和精简响应最终 flush 均受截止时间约束，keepalive 后续响应不受旧截止时间影响 |
| 真实 TCP 未完成 GET 请求体 | full/route/stats 的 Content-Length、chunked 数据及 trailer 均受读取截止时间约束；过载拒绝可结束，API 名额可回收，完整请求体仍支持 keepalive 复用 |
| Go race detector / OpenWRT 透明代理现场 | 未验证 |

DNS 反向映射仍有歧义：共享 CDN IP、同客户端同 IP 多域名、应用自带 DoH、未经过 MosDNS 的缓存、IPv4/IPv6 身份差异，以及 HTTP/2 或 HTTP/3 连接复用都可能影响判定。UDP 沿用 Mihomo 按源 IP＋端口复用 NAT 会话的机制，同一 socket 发往多个目标不会逐目标重新选路。桥接不解密 ECH，也不按已建立连接中的每个请求重新分流。

回滚时先将 Mihomo `domain-mapping.enable` 设为 `false` 并重载，即恢复原路径；若同时撤销 dnsmasq ECS 转发，需恢复原 DNS 拓扑或客户端识别方式，否则 MosDNS 的 `client_ip` 会再次只看到 dnsmasq。分配功能可独立关闭。

## 在主分支跟进上游

`origin` 指向自己的 fork，`upstream` 指向 `https://github.com/IrineSistiana/mosdns.git`。在工作区干净时，将上游合并到长期维护的 `main`，保留桥接提交历史；解决冲突后运行测试再推送：

```sh
git switch main
git fetch upstream
git merge upstream/main
go test ./...
git push origin main
```

Mihomo 对应合并 `MetaCubeX/mihomo` 的 `Meta`，步骤见其 `docs/domain-mapping.md`。两端协议变化应配套验证，并重跑本文的跨进程脚本。
