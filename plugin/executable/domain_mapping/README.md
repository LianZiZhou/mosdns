# Client-scoped real-address allocation and candidate lookup

The client-scoped allocator chooses only addresses present in the final upstream
answer. It keeps an existing compatible assignment, then tries a compatible
shared address, then an unused address. IPv4 and IPv6 are independent. If no
compatible address remains, it returns the original alternatives for that family
and records every exposed address. Reordering an upstream answer does not rotate
an existing assignment. TTL zero is retained as exposure history in LRU mode.

```yaml
size: 262144
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
  import_file: /tmp/mosxmihomo-allocation-20261018/history/legacy-import.json
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

## v2 route candidates

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
Normal shutdown drains admitted replies and checkpoints before removing the
marker. Startup refuses to serve if it cannot create the marker and initial
checkpoint. Runtime write failures leave DNS available, mark state unhealthy,
and retain the dirty marker so an unclean restart activates recovery.

LRU eviction never turns an exposed address into a known free address. An 8 MiB
non-decaying Bloom guard remembers client/address taints and service associations;
false positives make allocation/routing conservative, never falsely exclusive.
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
