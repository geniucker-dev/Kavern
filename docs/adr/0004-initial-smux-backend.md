# ADR 0004: Initial smux Backend

## Status

Accepted for Gate 3 implementation.

## Context

Kavern needs a replaceable mux data-plane boundary before real agent data paths are implemented. Gate 3 requires one initial mux backend, carrier-level `max_streams_per_carrier` enforcement, no infinite stream queue, and a dependency/license review.

## Decision

Gate 3 uses `github.com/xtaci/smux` as the first mux backend.

The dependency is contained inside:

```text
internal/dataplane/mux
```

Business logic and session/router/domain packages use Kavern interfaces only. Third-party `smux` types must not appear in `internal/domain`, `internal/session`, `internal/router`, `internal/gateway/agent_v1`, or `internal/dataplane/carrier`.

Gate 3 only enforces `max_streams_per_carrier`. `max_inflight` and `max_buffer` remain required future data-plane limits, but this gate does not implement byte queueing, inflight byte accounting, or buffer backpressure.

## License Review

`github.com/xtaci/smux` is MIT licensed according to its upstream repository and Go package metadata:

- https://github.com/xtaci/smux
- https://pkg.go.dev/github.com/xtaci/smux

MIT is a permissive license and is acceptable for this project gate. No GPL, AGPL, or other copyleft mux dependency is introduced.

## Consequences

- The initial mux backend can be replaced by adding another implementation of Kavern's mux interface.
- Carrier-pool correctness can be tested before real `kavernd` or `kavern-agent` data paths exist.
- Future gates must still implement broader carrier limits such as inflight and buffer accounting before claiming full data-plane backpressure coverage.
