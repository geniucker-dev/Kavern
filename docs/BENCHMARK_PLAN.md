# Benchmark Plan

This benchmark plan is part of Gate 0 specification review and does not approve implementation.

## Goals

- Compare replaceable mux backends under a common Kavern carrier-pool interface.
- Measure behavior under bounded carrier limits.
- Identify correctness, fairness, and backpressure problems early.
- Keep local loopback results separate from production or WAN claims.

## Non-Goals

- Do not claim production performance from local-only benchmarks.
- Do not treat full WAN/server benchmarking as an autonomous acceptance gate.
- Do not benchmark HTTP/2 as the core raw TCP data plane.
- Do not design or validate one unlimited mux connection.

## Location

Local benchmark harnesses may live under:

```text
experiments/muxbench
```

## Backends

Future benchmark suites should compare:

- `smux`
- `yamux`
- `kavernmux`
- Optional QUIC carrier

All backends must be exercised through the same `MuxBackend` and carrier-pool abstractions.

Third-party mux packages must be hidden behind Kavern's `MuxBackend` interface. Business logic must not depend directly on `smux`, `yamux`, or other backend-specific types. Gate 3 must include dependency and license review for every mux backend. No GPL, AGPL, or other copyleft dependency may be added without explicit review.

## Carrier-Pool Scenarios

Each scenario must vary:

- `max_streams`
- `max_streams_per_carrier`
- `max_inflight`
- `max_buffer`
- Number of carriers.
- Stream payload size.
- Stream count.
- Stream duration.
- Read/write asymmetry.
- Slow receiver behavior.

Infinite queues are forbidden. Backpressure must be measured.

## Metrics

Required metrics:

- Throughput.
- Latency.
- p95 latency.
- p99 latency.
- CPU.
- Memory.
- Goroutine count.
- File descriptor count.
- Stream open failures.
- Stream reset failures.
- Backpressure wait duration.
- Buffer occupancy where observable.

## Local Loopback Methodology

Local benchmarks should:

- Run on loopback.
- Use deterministic parameters.
- Record host details.
- Record Go version.
- Record backend version.
- Record Kavern git commit when available.
- Run multiple iterations.
- Output machine-readable results when practical.

Local benchmarks are useful for regression detection and backend comparison under controlled conditions. They must not be presented as WAN or production performance.

## Manual WAN Benchmark Phase

Full WAN/server benchmarking requires human deployment and is not an autonomous acceptance gate.

Manual WAN benchmark documentation should later define:

- Server region.
- Agent region.
- Network conditions.
- Instance types.
- Kernel settings.
- TLS settings.
- Carrier counts.
- Tunnel counts.
- Client workload.
- Safety and cleanup procedure.

## Review Gate

Gate 7, Benchmark Harness Review, must verify:

- `experiments/muxbench` exists only when implementation is approved.
- Benchmarks are local-only unless manually deployed.
- `smux`, `yamux`, `kavernmux`, and optional QUIC are represented in the comparison plan.
- Results do not claim production performance from local loopback measurements.
- WAN benchmark remains explicitly manual.

## Gate 7 implementation (review pending, 2026-10-09)

`experiments/muxbench` implements real bounded TCP loopback smux/carrier workloads, exact payload verification, machine-readable repeated results and local CPU/heap/RSS/goroutine/FD/backpressure measurements. See its README for exact fixed scenarios, parameter bounds, metric definitions, profiling commands and unavailable receive occupancy. The only measured backend is smux v1.5.57; yamux, kavernmux and optional QUIC remain future unimplemented/unmeasured comparisons. WAN remains an explicitly manual deployment phase.
