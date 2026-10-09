# Local mux/carrier benchmark

Gate 7 harness, independent review passed as bc11abc. The only measured backend is the pinned `smux` implementation behind Kavern's `mux.Backend` and bounded carrier pool. All connections are real TCP on `127.0.0.1:0`; the harness has no remote address flag. It measures the native mux/carrier boundary without TLS, control authentication, NPC, or target dialing. These are local regression measurements, not production/WAN throughput claims.

## Reproduce

```sh
go run ./experiments/muxbench -suite smoke -iterations 2 > smoke.json
go run ./experiments/muxbench -suite matrix -iterations 3 > matrix.json
go run ./experiments/muxbench -suite matrix -iterations 1 -cpu-profile cpu.pprof -heap-profile heap.pprof > profiled.json
go tool pprof -top cpu.pprof
go tool pprof -top -alloc_space heap.pprof
go test -race ./experiments/muxbench ./internal/dataplane/carrier -count=10
```

With dependencies cached, `GOPROXY=off GOSUMDB=off` keeps these commands offline. Neither NPC_BIN nor NPS_BIN is required. `-iterations` is bounded to 1..20, `-timeout` to 1s..1m (default 15s). Use the ordinary non-race matrix for performance observations; race runs establish correctness, not comparable performance. Profiling changes overhead and is recorded explicitly.

The pool-scaling cases also increase offered concurrency/stream count; they do not isolate carrier count as a causal variable. Every comparison must retain the complete reported parameter row.

The fixed matrix varies one/two/four carriers, stream limits, 1 KiB/64 KiB/1 MiB payloads, total stream count and concurrency, a 20 ms controlled open duration, 16/64 KiB inflight limits, 256/512 KiB buffer limits, 2 ms receive delays, and 1 ms write delays. Capacity probes hold all allowed leases and require one rejected extra acquire. Abort probes intentionally close streams early. Echo worker admission and all local queues are bounded. Each iteration creates and closes its own pool, joins accept/handler/write/sampling/timeout workers, and verifies exact echo bytes for data cases.

## Result schema and metric definitions

JSON contains the fixed parameters for each row, iteration, Go/OS/architecture/CPU/kernel details, GOMAXPROCS, dependency version, Git commit/dirty state when available, transport, timeout and sampling interval. A separate unmeasured warmup initializes Go's persistent network poller.

- Throughput counts verified request + echo bytes (`2 * verified_payload_bytes / duration`). Timing starts after setup and ends after traffic/lease-close work; correctness copying/checking and resource sampling are included. Setup/authentication/TLS are excluded.
- Latency spans pool acquisition through verified echo EOF and lease release. Open latency includes pool/backend open attempts plus bounded capacity-retry waiting. p95/p99 use the nearest-rank definition and include the reported finite sample count; they are descriptive small-workload statistics, not tail-SLA estimates. Capacity probes have zero latency samples and no payload throughput.
- CPU is Linux `getrusage(RUSAGE_SELF)` user+system time over the traffic interval. Process CPU, heap allocation and sampled RSS describe both loopback endpoints and harness overhead in one process. Total allocation/CPU snapshot counters are cumulative; `traffic_cpu_ns` and `allocated_bytes_during_traffic` are interval deltas. RSS peaks are sampled, not exact OS high-water marks.
- Resource samples are taken every 1 ms; heap/RSS, goroutines and `/proc/self/fd` counts are reported before, sampled peak, and after owned worker cleanup. Persistent runtime/poller descriptors are included. Heap/RSS is not promised to return immediately to its baseline.
- Stream open failures count every failed acquire attempt. Ordinary workload clients retry only `ErrNoCarrierAvailable` before any stream/application bytes exist, using a fixed 1 ms delay and the scenario deadline; every data request must eventually complete exact verification. Retry delay is included in request/open latency and separately measured, and all rejections remain in `capacity_rejections`. There is no application replay. `expected_capacity_rejections` separates the deliberate overload probe. `stream_reset_failures` means failures of the workload client's Kavern abort/full-Close operation, because the common stream interface exposes Close, not a backend wire-RST primitive. Unexpected integrity/I/O/close failures cause a nonzero command exit and partial JSON evidence, rather than being ignored.
- `local_budget_wait_total_ns` measures time in `Carrier.acquireBytes` waiting for its shared pending-write budget. `local_budget_wait_wakeups` counts blocked waits, including repeated wakeups/cancellation. It excludes backend socket waits. `write_operation_total_ns` measures complete synchronous write+directional-EOF operations, which includes budget/socket/EOF waits. Both are aggregate concurrent durations and may exceed wall time.
- `peak_owned_inflight_per_carrier_bytes` is the maximum observed by exact carrier accounting, across either endpoint. Backend receive occupancy is unavailable through the common interface and is JSON null; configured receive capacity remains in each row. Payload budgets exclude TLS/runtime/socket/kernel object overhead.

## Future comparison and manual WAN

`yamux`, `kavernmux`, and optional QUIC are explicitly unimplemented and unmeasured. Future implementations must use the same mux/carrier abstractions, stream/EOF contract, workloads, limits and metric definitions, with independent dependency/license review before adding code. No new dependency is introduced here.

WAN runs require human deployment and a separate approved plan recording server/agent regions, instance types, network conditions, kernel/TLS settings, carrier/tunnel counts, workloads, safety and cleanup. This harness cannot perform a WAN run. Do not extrapolate its loopback results to production capacity.
