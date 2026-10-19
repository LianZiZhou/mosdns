# Native-style routing hints and client-scoped address allocation

The v3 route API uses a small single-value LRU, separate from address ownership
history: each `(client, IP)` retains the latest finalized DNS domain. The default
is **4096 total keys across all clients**, matching the capacity of Mihomo's
native redir-host map rather than accumulating every historic domain as a route
candidate. An actual DNS reply replaces the hint. A connection lookup only moves
that one hint in its LRU; it does not renew DNS timestamps or keep all historic
names hot. A hint survives its DNS TTL until overwritten or evicted and remains
a best-effort inference, not a unique identity for an encrypted connection.

The client-scoped allocator chooses only addresses present in the final upstream
answer. It keeps an independent, finalized singleton preference while that IP
still appears in a safely filterable upstream family, even if another domain
later shares the IP. Otherwise it tries an existing compatible assignment, a
shared address, then an unused address. IPv4 and IPv6 are independent. If no
compatible address remains, it returns the original alternatives for that family
and records every exposed address. Reordering an upstream answer does not rotate
an existing assignment. TTL zero is retained as exposure history in LRU mode.

```yaml
size: 262144
routing:
  size: 4096
retention:
  mode: lru
  ttl_multiplier: 10
  min_window: 300
  max_window: 86400
allocation:
  enable: true
  client_scope: true
  size: 262144
  state_file: /etc/mosdns/domain-index.state.gz
  startup_guard: 86400
  policy:
    endpoint: http://127.0.0.1:9090/dns-policy/classify
    secret_file: /etc/mosdns/bridge-policy.secret
    timeout: 200
    cache_size: 65536
    batch_size: 64
    queue_size: 4096
```

`client_scope` requires allocation, LRU retention and a writable state file.
The client identity comes from the query's effective server metadata; use the
existing trusted-ECS mechanism to preserve clients behind dnsmasq. An absent
identity never participates in per-client allocation. Keep the bridge API on a
trusted local listener. Legacy allocation and the v1 lookup contract are retained.

`size` bounds conservative allocation history; `routing.size` independently
bounds routing hints. Stable preferences have their own LRU bounded by
`allocation.size`. An exhausted third domain may receive A+B without revoking
Gemini's established A and gstatic's B. Preferences are committed only after a
safe singleton family is successfully encoded, persisted separately, and never
inferred from an old multi-domain ownership bucket. DNSSEC and complex service
answers bypass this optimization.

Sharing requires current positive classification for **every** different owner
of the address, for the same client and classifier epoch. `unmatched` may share;
`direct` may join only when Mihomo explicitly sets `share_eligible` (the final
fallback is proven literal DIRECT). Proxy rules, unknown policies, expired tokens,
and unavailable classification remain isolated. Classification is asynchronous:
DNS never waits for an RPC. The bounded worker batches up to 64 names over a
5 ms window, deduplicates requests and reuses one HTTP connection. Tokens are
locally capped at 5 seconds. Failed classification is negatively cached for one
second. The bearer credential file is reread for each batch, so atomic credential
rotation does not require a MosDNS restart.

DNSSEC/CD/DO and complex answers are preserved. HTTPS/SVCB records and ECH values
are never rewritten. Same-name ServiceMode (`target=.` or the query's own name)
disables subsequent address trimming but can retain a complete candidate set.
Reachable cross-name aliases and service targets are conservatively uncertain;
their exposed addresses cannot be promoted to a unique detected name. This is a
bounded conservative association mechanism, not a complete DNS dependency graph.

## v3 routing hints (recommended)

`GET /v3/lookup?ip=203.0.113.1&client=192.168.6.180` returns JSON:

```json
{"version":3,"status":"hit","ip":"203.0.113.1","scope":"client","domain":"ordinary.test","source":"a","observed_at":"2026-10-19T06:00:00Z","dns_expires_at":"2026-10-19T06:05:00Z","retention_mode":"lru","domains":["ordinary.test"],"candidates_complete":true,"generation":42,"allocation_recovering":true}
```

`hit` supplies the latest DNS hint even during allocation recovery or after a
CNAME association. `miss` has no hint. A supplied client never falls back to
another client's/global history. An omitted client matches only replies that
actually lacked a client identity; it is not an aggregation across clients.

`domains` contains at most 32 distinct recent actual DNS observations, sorted
and deduplicated. Freshness is `clamp(10 * actual TTL, 5 minutes, 24 hours)` from
the last actual response, never from connection accesses. `domains` may be empty
while an older LRU hint remains. `candidates_complete` means the bounded recent
set was not truncated; it **does not certify all possible IP owners**. Truncation
sets `reason:candidate_limit` and remains explicit until dropped facts expire.
Consumers must evaluate recent conflicts using the connection's actual metadata
and current rules. On a cross-policy conflict or truncation they should continue
ordinary IP/source/port/MATCH rules, not choose a historic preferred proxy.

`allocation_recovering` is diagnostic and never controls routing eligibility.
There is no v2 `complete` or renewable `expires_at` lease in v3. Reliable payload
sniffing may correct the hint; the hinted domain must not suppress sniffing.
No reverse-DNS heuristic can establish exact domain identity for a shared real
IP with unavailable encrypted hostname information.

Stats expose `routing_hints`, `routing_capacity`, `routing_evictions`,
`routing_touches`, and `allocation_preferences` independently of history counts.

## Legacy v2 route candidates

The v2 contract is retained for compatibility. New routing deployments should
use v3; v2's complete-history flags must never become a fixed special outbound.

`GET /v2/lookup?ip=203.0.113.1&client=192.168.6.180` returns JSON:

```json
{"version":2,"status":"ambiguous","ip":"203.0.113.1","scope":"client","domains":["gemini.google.com","other.test"],"complete":true,"total":2,"generation":42,"reason":"shared_address"}
```

`hit` has exactly one complete owner and includes `domain`. `ambiguous` has no
`domain`; consumers must evaluate each candidate as a complete routing input and
apply their explicit conflict policy. This is policy selection among possible
owners, not proof of the connection's hostname. `miss` has no owner. Unknown
exposure, a new pending owner or truncation produces `ambiguous, complete=false`.
A repeat pending DNS response for an already known owner does not reduce
completeness. The maximum returned set is 1024 names; `total` counts retained
distinct owners and is a lower bound when history was lost. The 32-name v1
diagnostic limit does not restrict v2. Metadata `expires_at` is a route cache
lease; it does not erase LRU exposure history or prove the client's DNS expired.

A lookup with a valid client uses only that client's bucket and never guesses
from another client's global result. Without a client the response is global
diagnostic information; it cannot prove per-client allocation. A global lookup
promotes LRU entries without renewing another client's TTL lease. Complete-history
and eviction protections require `client_scope`; old mode has no exposure guard
and v2 returns `ambiguous, complete=false, reason=history_untracked` (v1 unchanged).

## Persistence and migration

State consists of the configured checkpoint, `.wal` and `.dirty`. Files are
private (0600); the checkpoint contains a version/checksum envelope and gzip JSON
(it is not a raw gzip stream). A durable dirty marker is written before accepting
answers. WAL writes are asynchronous and sync every 200 ms, with 128 queued
events, a 1 MiB event limit, a 16 MiB file limit and compaction at 4 MiB. Checkpoints
are atomically replaced and capped at 64 MiB compressed / 256 MiB decoded on read.
Normal shutdown closes DNS request admission and gives admitted requests and
their final response callbacks up to 10 seconds to drain before closing plugins
and checkpointing. The dirty marker is removed only after a successful durable
checkpoint. A drain timeout refuses to close stateful plugins, and shutdown or
storage errors keep recovery enabled instead of reporting a clean checkpoint.
Production process supervision should allow 45 seconds for this shutdown path.
Startup refuses to serve if it cannot create the marker and initial
checkpoint. Runtime write failures leave DNS available, mark state unhealthy,
and retain the dirty marker so an unclean restart activates recovery.

LRU eviction never turns an exposed address into a known free address. An 8 MiB
non-decaying Bloom guard remembers client/address taints and service associations;
false positives restrict allocation, never falsely certify exclusivity. The
guard and its recovery window do not participate in v3 route decisions.
Long-running saturation can reduce allocation opportunities. Do not clear this
guard while clients may still use previously returned addresses.

For the first upgrade, import real client-scoped history, not global DNS records
assigned to arbitrary clients. `import_file` is read only when the state file is
absent. It is ordinary JSON:

```json
{"version":1,"history_complete":false,"incomplete_buckets":[{"client":"192.168.6.180","ip":"203.0.113.1"}],"records":[{"client":"192.168.6.180","ip":"203.0.113.1","domain":"gemini.google.com","source":"a","observed_at":"2026-10-18T03:00:00Z","dns_expires_at":"2026-10-18T03:05:00Z","expires_at":"2026-10-18T03:50:00Z"}]}
```

Preserve timestamps and mark every truncated client/IP bucket incomplete. An
incomplete bucket stays uncertain even if some owners are later evicted. Missing
or corrupt state, an unclean restart, or `history_complete:false` activates the
configured startup guard (default 86400 seconds, maximum 30 days). During this
window unseen addresses are not treated as free; known compatible owners can be
reused. Normal known candidate sets still route, and unknown IPs are not all
forced into one proxy. A missing temporary import after reboot is tolerated and
also activates the guard. A malformed existing import is rejected.

An unclean restart or damaged state/WAL additionally makes populated buckets
`complete:false` during this horizon: a lost asynchronous write may contain an
unseen owner of an already known address. This `incomplete_until` deadline is
persisted and survives subsequent clean shutdowns. Partial legacy imports alone
do not impose this global known-bucket restriction. Completely unrecorded IPs
remain misses; the bridge cannot recover their lost names. Cached targets of
later CNAME/HTTPS aliases are checked immediately on lookup and allocation, even
when the client does not query the target again.

On the first v3 migration, old records restore at most `routing.size` hints in actual
`observed_at` order. Historical retention extensions are ignored. Old snapshots
have no stable preferences; those are learned from subsequent finalized DNS
replies. New snapshots persist the actual small routing LRU, its recent facts,
and truncation horizon, including an explicitly empty cache. Subsequent restarts
never rebuild evicted hints from the larger historical index. A snapshot/WAL
sequence fence prevents already checkpointed DNS events from resurrecting those
evictions. Connection touches are not journaled; after a dirty/uncertain restart
or replay of newer DNS events, routing starts empty rather than guessing the lost
LRU order. Allocation exposure history and preferences are still recovered. New
finalized DNS answers immediately repopulate the routing cache during recovery.
Live DNS wins by response order even after wall-clock rollback; future-dated
hint facts are discarded instead of being kept hot indefinitely. Existing
guard/recovery data stays available for allocator safety.

The finite startup guard is an explicit best-effort migration compromise. After
it expires the allocator may use unseen addresses again; it cannot promise
correctness for clients retaining unobservable answers indefinitely. A clean
restart preserves recorded history and per-bucket taints. `state_healthy`,
`history_complete`, `startup_guard_until`, `observation_evictions` and
`allocation_exhausted` expose relevant operational state. The history flag
describes the finite recovery window, not proof that every historic client
answer has been observed.

Allow space for the old checkpoint, replacement checkpoint and WAL together.
The implementation bounds individual files, not total filesystem availability.
The initial 26,442-record migration fixture compressed to about 1.45 MiB; a
262,144-record synthetic profile compressed to 4.69 MiB. These are measurements,
not a worst-case size guarantee. High-entropy names and a saturated guard cost
more. Check free space before installing binaries alongside existing state.

Resource tests are opt-in with `MOSDNS_RETENTION_RESOURCE=1`; migration testing
uses `MOSDNS_ALLOCATION_IMPORT=/path/to/import.json`. The package also tests
concurrent allocation, exhaustion, policy failure/rotation, service hints, v1/v2
compatibility, LRU eviction, partial imports and clean/unclean restart recovery.
