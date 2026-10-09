package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestSmokeMeasuresRealWorkloadsAndCleanup(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-suite", "smoke", "-iterations", "2"}, &output); err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(output.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 6 || r.Transport != "tcp_loopback_without_tls" || r.Backend != "smux" || len(r.FutureBackends) != 3 {
		t.Fatal("missing measured/future scope metadata")
	}
	for _, v := range r.Results {
		if v.DurationNS <= 0 || v.IOFailures != 0 || v.ResetFailures != 0 {
			t.Fatalf("invalid measured result for %s", v.Scenario.Name)
		}
		if v.Before.FDs != nil && v.After.FDs != nil && *v.After.FDs != *v.Before.FDs {
			t.Fatalf("FDs retained by %s: %d -> %d", v.Scenario.Name, *v.Before.FDs, *v.After.FDs)
		}
		if v.Scenario.LimitProbe {
			if v.ExpectedCapacityRejections != 1 || v.OpenFailures != 1 || v.VerifiedBytes != 0 {
				t.Fatal("capacity limit was not exercised")
			}
		} else if v.Scenario.Abort {
			if v.VerifiedBytes != 0 {
				t.Fatal("abort reported throughput payload")
			}
		} else {
			if v.VerifiedBytes != int64(v.Scenario.Streams*v.Scenario.PayloadBytes) || v.Samples != v.Scenario.Streams || v.P99NS < v.P95NS || v.Throughput <= 0 {
				t.Fatal("payload/latency measurement invalid")
			}
		}
		if v.ReceiveOccupancy != nil {
			t.Fatal("unobservable backend receive occupancy invented")
		}
	}
}
func TestBenchmarkRejectsUnboundedParameters(t *testing.T) {
	for _, args := range [][]string{{"-iterations", "0"}, {"-iterations", "21"}, {"-timeout", "2m"}, {"-suite", "wan"}, {"-server", "example.com:443"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted parameters %v", args)
		}
	}
}

func TestCapacityRetriesAreMeasuredAndDeadlineBounded(t *testing.T) {
	s := scenarios("smoke")[0]
	s.MaxStreams = 1
	s.Concurrency = 1
	s.Streams = 1
	w, err := setup(s)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	hold, err := w.pool.Acquire(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Release()
	// Finish this held stream's wire exchange while deliberately keeping its
	// local lease reserved. The retrying request must not acquire/send any bytes.
	if err = hold.Stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, hold.Stream); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(w.ctx, 25*time.Millisecond)
	defer cancel()
	v := transfer(ctx, w, s, 0)
	if !v.openErr || v.capacityRejections < 1 || v.retryWait <= 0 || v.bytes != 0 || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("bounded retry outcome=%+v", v)
	}
	if w.ctx.Err() != nil || w.local[0].ActiveStreams() != 1 {
		t.Fatal("failed retry changed existing lease or workload context")
	}
}
