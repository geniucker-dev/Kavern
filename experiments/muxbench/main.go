// muxbench measures the native mux/carrier boundary on TCP loopback only.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
)

type scenario struct {
	HoldOpenNS   int64  `json:"hold_open_ns"`
	Name         string `json:"name"`
	Carriers     int    `json:"carriers"`
	MaxStreams   int    `json:"max_streams_per_carrier"`
	MaxInflight  int    `json:"max_inflight"`
	MaxBuffer    int    `json:"max_buffer"`
	Streams      int    `json:"streams"`
	Concurrency  int    `json:"concurrency"`
	PayloadBytes int    `json:"payload_bytes"`
	ReadDelayNS  int64  `json:"read_delay_ns"`
	WriteDelayNS int64  `json:"write_delay_ns"`
	Abort        bool   `json:"abort"`
	LimitProbe   bool   `json:"limit_probe"`
}
type resource struct {
	Goroutines int     `json:"goroutines"`
	FDs        *int    `json:"fds"`
	RSSBytes   *uint64 `json:"rss_bytes"`
	HeapAlloc  uint64  `json:"heap_alloc_bytes"`
	TotalAlloc uint64  `json:"total_alloc_bytes"`
	CPU        *int64  `json:"cpu_ns"`
}

func snapshot() resource {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fd, rss, cpu := platformResources()
	return resource{runtime.NumGoroutine(), fd, rss, m.HeapAlloc, m.TotalAlloc, cpu}
}

type result struct {
	CapacityRejections         int      `json:"capacity_rejections"`
	OpenRetryWaitNS            int64    `json:"pool_retry_wait_total_ns"`
	Scenario                   scenario `json:"scenario"`
	Iteration                  int      `json:"iteration"`
	DurationNS                 int64    `json:"duration_ns"`
	VerifiedBytes              int64    `json:"verified_payload_bytes"`
	Throughput                 float64  `json:"bidirectional_bytes_per_second"`
	Samples                    int      `json:"latency_samples"`
	MeanNS                     int64    `json:"mean_latency_ns"`
	P95NS                      int64    `json:"p95_latency_ns"`
	P99NS                      int64    `json:"p99_latency_ns"`
	OpenMeanNS                 int64    `json:"mean_open_latency_ns"`
	OpenFailures               int      `json:"stream_open_failures"`
	ExpectedCapacityRejections int      `json:"expected_capacity_rejections"`
	ResetFailures              int      `json:"stream_reset_failures"`
	IOFailures                 int      `json:"unexpected_io_failures"`
	WriteBlockedNS             int64    `json:"write_operation_total_ns"`
	BudgetWaitNS               int64    `json:"local_budget_wait_total_ns"`
	BudgetWaits                uint64   `json:"local_budget_wait_wakeups"`
	PeakInflight               int      `json:"peak_owned_inflight_per_carrier_bytes"`
	ReceiveOccupancy           *int     `json:"backend_receive_occupancy_bytes"`
	Before                     resource `json:"resources_before"`
	After                      resource `json:"resources_after_cleanup"`
	Peak                       resource `json:"resources_peak_sampled"`
	CPUTime                    *int64   `json:"traffic_cpu_ns"`
	Allocated                  uint64   `json:"allocated_bytes_during_traffic"`
	ResourceSamples            int      `json:"resource_samples"`
}
type report struct {
	PoolRetryNS      int64             `json:"pool_acquire_retry_delay_ns"`
	Schema           int               `json:"schema_version"`
	Transport        string            `json:"transport"`
	GoVersion        string            `json:"go_version"`
	GOOS             string            `json:"goos"`
	GOARCH           string            `json:"goarch"`
	CPUs             int               `json:"cpus"`
	GOMAXPROCS       int               `json:"gomaxprocs"`
	Host             map[string]string `json:"host"`
	Commit           string            `json:"git_commit"`
	Dirty            *bool             `json:"git_dirty"`
	Backend          string            `json:"backend"`
	BackendVersion   string            `json:"backend_version"`
	FutureBackends   []string          `json:"unmeasured_future_backends"`
	Iterations       int               `json:"iterations"`
	TimeoutNS        int64             `json:"scenario_timeout_ns"`
	SampleIntervalNS int64             `json:"resource_sample_interval_ns"`
	ProfileEnabled   bool              `json:"cpu_profile_enabled"`
	Results          []result          `json:"results"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("muxbench", flag.ContinueOnError)
	iterations := fs.Int("iterations", 3, "iterations per fixed scenario (1..20)")
	suite := fs.String("suite", "matrix", "matrix or smoke")
	cpuPath := fs.String("cpu-profile", "", "optional CPU profile file")
	heapPath := fs.String("heap-profile", "", "optional heap profile file after cleanup")
	timeout := fs.Duration("timeout", 15*time.Second, "per-scenario timeout (1s..1m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *iterations < 1 || *iterations > 20 || *timeout < time.Second || *timeout > time.Minute {
		return errors.New("invalid benchmark parameters")
	}
	cases := scenarios(*suite)
	if cases == nil {
		return errors.New("unknown suite")
	}
	var profile *os.File
	if *cpuPath != "" {
		var err error
		profile, err = os.Create(*cpuPath)
		if err != nil {
			return err
		}
		defer profile.Close()
		if err = pprof.StartCPUProfile(profile); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	// Prime the Go network poller so its persistent descriptors are not counted
	// as leaked scenario sockets. This warmup is separate from measured results.
	warm := scenarios("smoke")[0]
	if _, err := measure(warm, 0, *timeout); err != nil {
		return err
	}
	commit, dirty := gitState()
	r := report{PoolRetryNS: int64(time.Millisecond), Schema: 1, Transport: "tcp_loopback_without_tls", GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Host: platformHost(), Commit: commit, Dirty: dirty, Backend: "smux", BackendVersion: backendVersion(), FutureBackends: []string{"yamux: planned, unimplemented, unmeasured", "kavernmux: planned, unimplemented, unmeasured", "QUIC: optional future carrier, unimplemented, unmeasured"}, Iterations: *iterations, TimeoutNS: int64(*timeout), SampleIntervalNS: int64(time.Millisecond), ProfileEnabled: profile != nil}
	for _, s := range cases {
		for i := 1; i <= *iterations; i++ {
			v, err := measure(s, i, *timeout)
			r.Results = append(r.Results, v)
			if err != nil {
				_ = json.NewEncoder(out).Encode(r)
				return fmt.Errorf("scenario %s iteration %d: %w", s.Name, i, err)
			}
		}
	}
	if *heapPath != "" {
		runtime.GC()
		f, err := os.Create(*heapPath)
		if err != nil {
			return err
		}
		err = pprof.WriteHeapProfile(f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
func scenarios(suite string) []scenario {
	base := scenario{Name: "baseline", Carriers: 1, MaxStreams: 8, MaxInflight: 65536, MaxBuffer: 524288, Streams: 32, Concurrency: 8, PayloadBytes: 65536}
	if suite == "smoke" {
		base.Streams = 4
		base.Concurrency = 2
		base.PayloadBytes = 1024
		limit := base
		limit.Name = "capacity-rejection"
		limit.MaxStreams = 2
		limit.LimitProbe = true
		abort := base
		abort.Name = "abort-close"
		abort.Abort = true
		return []scenario{base, limit, abort}
	}
	if suite != "matrix" {
		return nil
	}
	cases := []scenario{base}
	add := func(name string, change func(*scenario)) {
		s := base
		s.Name = name
		change(&s)
		cases = append(cases, s)
	}
	add("two-carriers", func(s *scenario) { s.Carriers = 2; s.Concurrency = 16 })
	add("four-carriers", func(s *scenario) { s.Carriers = 4; s.Concurrency = 32; s.Streams = 64 })
	add("small-payload", func(s *scenario) { s.PayloadBytes = 1024; s.Streams = 64 })
	add("large-payload", func(s *scenario) { s.PayloadBytes = 1 << 20; s.Streams = 16 })
	add("held-streams", func(s *scenario) { s.HoldOpenNS = int64(20 * time.Millisecond) })
	add("tight-inflight", func(s *scenario) { s.MaxInflight = 16384 })
	add("tight-buffer", func(s *scenario) { s.MaxBuffer = 262144 })
	add("slow-reader", func(s *scenario) {
		s.ReadDelayNS = int64(2 * time.Millisecond)
		s.PayloadBytes = 262144
		s.Streams = 16
	})
	add("asymmetric-writer", func(s *scenario) { s.WriteDelayNS = int64(time.Millisecond); s.PayloadBytes = 262144; s.Streams = 16 })
	add("capacity-rejection", func(s *scenario) { s.MaxStreams = 2; s.Carriers = 2; s.LimitProbe = true })
	add("abort-close", func(s *scenario) { s.Abort = true })
	return cases
}
func backendVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/xtaci/smux" {
				return dep.Version
			}
		}
	}
	return "unavailable"
}
func gitState() (string, *bool) {
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unavailable", nil
	}
	status, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return string(bytesTrim(revision)), nil
	}
	dirty := len(status) > 0
	return string(bytesTrim(revision)), &dirty
}
func bytesTrim(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	return p
}

type workload struct {
	closeOnce     sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
	pool          *carrier.Pool
	local         []*carrier.Carrier
	remote        []*carrier.Carrier
	accepts       sync.WaitGroup
	handlers      sync.WaitGroup
	handlerErrors chan error
}

func setup(s scenario) (*workload, error) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &workload{ctx: ctx, cancel: cancel, handlerErrors: make(chan error, s.Streams+s.Carriers*s.MaxStreams+8)}
	fail := func(err error) (*workload, error) { w.close(); return nil, err }
	backend := mux.NewSmuxBackend()
	for range s.Carriers {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fail(err)
		}
		client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			listener.Close()
			return fail(err)
		}
		server, err := listener.Accept()
		listener.Close()
		if err != nil {
			client.Close()
			return fail(err)
		}
		cfg := mux.Config{MaxReceiveBuffer: s.MaxBuffer - s.MaxInflight, MaxStreamBuffer: 65536, MaxFrameSize: 16384}
		local, err := backend.Client(client, cfg)
		if err != nil {
			client.Close()
			server.Close()
			return fail(err)
		}
		remote, err := backend.Server(server, cfg)
		if err != nil {
			local.Close()
			server.Close()
			return fail(err)
		}
		limits := carrier.Config{MaxStreamsPerCarrier: s.MaxStreams, MaxInflight: s.MaxInflight, MaxBuffer: s.MaxBuffer}
		lc, err := carrier.New(local, limits)
		if err != nil {
			local.Close()
			remote.Close()
			return fail(err)
		}
		rc, err := carrier.New(remote, limits)
		if err != nil {
			lc.Close()
			remote.Close()
			return fail(err)
		}
		w.local = append(w.local, lc)
		w.remote = append(w.remote, rc)
		slots := make(chan struct{}, s.MaxStreams)
		w.accepts.Add(1)
		go func() {
			defer w.accepts.Done()
			for {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				stream, err := remote.AcceptStream(ctx)
				if err != nil {
					<-slots
					return
				}
				lease, err := rc.AdoptStream(ctx, stream)
				if err != nil {
					stream.Close()
					<-slots
					w.handlerErrors <- err
					continue
				}
				w.handlers.Add(1)
				go func() {
					defer w.handlers.Done()
					defer func() { <-slots }()
					defer lease.Release()
					if s.Abort || s.LimitProbe {
						_, _ = io.Copy(io.Discard, lease.Stream)
						return
					}
					reader := delayedReader{ctx: ctx, r: lease.Stream, delay: time.Duration(s.ReadDelayNS)}
					writer := delayedWriter{ctx: ctx, w: lease.Stream, delay: time.Duration(s.WriteDelayNS)}
					_, err := io.CopyBuffer(writer, reader, make([]byte, 32768))
					if err == nil {
						err = lease.Stream.(interface{ CloseWrite() error }).CloseWrite()
					}
					if err != nil && ctx.Err() == nil {
						w.handlerErrors <- err
					}
				}()
			}
		}()
	}
	var err error
	w.pool, err = carrier.NewPool(w.local...)
	if err != nil {
		return fail(err)
	}
	return w, nil
}
func (w *workload) close() {
	w.closeOnce.Do(func() {
		w.cancel()
		if w.pool != nil {
			w.pool.Close()
		}
		for _, c := range w.local {
			c.Close()
		}
		for _, c := range w.remote {
			c.Close()
		}
		w.accepts.Wait()
		w.handlers.Wait()

	})
}

type delayedReader struct {
	ctx   context.Context
	r     io.Reader
	delay time.Duration
}

func (d delayedReader) Read(p []byte) (int, error) {
	if err := delay(d.ctx, d.delay); err != nil {
		return 0, err
	}
	return d.r.Read(p)
}

type delayedWriter struct {
	ctx   context.Context
	w     io.Writer
	delay time.Duration
}

func (d delayedWriter) Write(p []byte) (int, error) {
	if err := delay(d.ctx, d.delay); err != nil {
		return 0, err
	}
	return d.w.Write(p)
}
func delay(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type sample struct {
	capacityRejections       int
	retryWait                time.Duration
	latency, open, write     time.Duration
	bytes                    int64
	openErr, ioErr, resetErr bool
}

func transfer(ctx context.Context, w *workload, s scenario, index int) sample {
	start := time.Now()
	var lease *carrier.Lease
	var err error
	v := sample{}
	for {
		lease, err = w.pool.Acquire(ctx)
		if !errors.Is(err, carrier.ErrNoCarrierAvailable) {
			break
		}
		v.capacityRejections++
		wait := time.Now()
		err = delay(ctx, time.Millisecond)
		v.retryWait += time.Since(wait)
		if err != nil {
			break
		}
	}
	v.open = time.Since(start)
	if err != nil {
		v.openErr = true
		return v
	}
	defer lease.Release()
	if s.Abort {
		v.resetErr = lease.Release() != nil
		v.latency = time.Since(start)
		return v
	}
	if err := delay(ctx, time.Duration(s.HoldOpenNS)); err != nil {
		v.ioErr = true
		return v
	}
	payload := make([]byte, s.PayloadBytes)
	for i := range payload {
		payload[i] = byte((i + index) % 251)
	}
	writeDone := make(chan sample, 1)
	go func() {
		started := time.Now()
		_, err := lease.Stream.Write(payload)
		if err == nil {
			err = lease.Stream.(interface{ CloseWrite() error }).CloseWrite()
		}
		writeDone <- sample{write: time.Since(started), ioErr: err != nil}
	}()
	got, err := io.ReadAll(io.LimitReader(lease.Stream, int64(s.PayloadBytes)+1))
	wr := <-writeDone
	v.write = wr.write
	v.ioErr = err != nil || wr.ioErr || len(got) != len(payload)
	if !v.ioErr {
		for i := range got {
			if got[i] != payload[i] {
				v.ioErr = true
				break
			}
		}
	}
	if !v.ioErr {
		v.bytes = int64(len(got))
	}
	v.resetErr = lease.Release() != nil
	v.latency = time.Since(start)
	return v
}
func measure(s scenario, iteration int, timeout time.Duration) (result, error) {
	r := result{Scenario: s, Iteration: iteration, Before: snapshot()}
	w, err := setup(s)
	if err != nil {
		return r, err
	}
	closed := false
	defer func() {
		if !closed {
			w.close()
		}
	}()
	ctx, cancel := context.WithTimeout(w.ctx, timeout)
	defer cancel()
	timeoutDone := make(chan struct{})
	stopTimeout := context.AfterFunc(ctx, func() { defer close(timeoutDone); w.close() })
	defer stopTimeout()
	beforeTraffic := snapshot()
	r.Peak = beforeTraffic
	stopSamples := make(chan struct{})
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSamples:
				return
			case <-ticker.C:
				mergePeak(&r.Peak, snapshot())
				r.ResourceSamples++
			}
		}
	}()
	start := time.Now()
	var samples []sample
	if s.LimitProbe {
		var held []*carrier.Lease
		for range s.Carriers * s.MaxStreams {
			lease, err := w.pool.Acquire(ctx)
			if err != nil {
				r.OpenFailures++
				break
			}
			held = append(held, lease)
		}
		extra, err := w.pool.Acquire(ctx)
		if errors.Is(err, carrier.ErrNoCarrierAvailable) {
			r.OpenFailures++
			r.ExpectedCapacityRejections++
			r.CapacityRejections++
		} else if err != nil {
			r.OpenFailures++
		} else {
			extra.Release()
		}
		for _, lease := range held {
			if lease.Release() != nil {
				r.ResetFailures++
			}
		}
	} else {
		jobs := make(chan int, s.Streams)
		results := make(chan sample, s.Streams)
		for i := range s.Streams {
			jobs <- i
		}
		close(jobs)
		var workers sync.WaitGroup
		for range s.Concurrency {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for index := range jobs {
					results <- transfer(ctx, w, s, index)
				}
			}()
		}
		workers.Wait()
		close(results)
		for v := range results {
			samples = append(samples, v)
		}
	}
	r.DurationNS = int64(time.Since(start))
	afterTraffic := snapshot()
	close(stopSamples)
	<-sampleDone
	mergePeak(&r.Peak, afterTraffic)
	for _, v := range samples {
		r.OpenFailures += v.capacityRejections
		r.CapacityRejections += v.capacityRejections
		r.OpenRetryWaitNS += int64(v.retryWait)
		if v.openErr {
			r.OpenFailures++
			continue
		}
		if v.ioErr {
			r.IOFailures++
		}
		if v.resetErr {
			r.ResetFailures++
		}
		r.VerifiedBytes += v.bytes
		r.WriteBlockedNS += int64(v.write)
		r.MeanNS += int64(v.latency)
		r.OpenMeanNS += int64(v.open)
	}
	r.Samples = 0
	for _, v := range samples {
		if !v.openErr {
			r.Samples++
		}
	}
	if r.Samples > 0 {
		r.MeanNS /= int64(r.Samples)
		r.OpenMeanNS /= int64(r.Samples)
	}
	latencies := make([]int64, 0, r.Samples)
	for _, v := range samples {
		if !v.openErr {
			latencies = append(latencies, int64(v.latency))
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	r.P95NS = quantile(latencies, .95)
	r.P99NS = quantile(latencies, .99)
	if r.DurationNS > 0 {
		r.Throughput = float64(r.VerifiedBytes*2) / (float64(r.DurationNS) / 1e9)
	}
	r.Allocated = afterTraffic.TotalAlloc - beforeTraffic.TotalAlloc
	if beforeTraffic.CPU != nil && afterTraffic.CPU != nil {
		value := *afterTraffic.CPU - *beforeTraffic.CPU
		r.CPUTime = &value
	}
	for _, c := range append(append([]*carrier.Carrier(nil), w.local...), w.remote...) {
		v := c.Stats()
		r.BudgetWaitNS += int64(v.BudgetWaitDuration)
		r.BudgetWaits += v.BudgetWaits
		r.PeakInflight = max(r.PeakInflight, v.PeakInflightBytes)
	}
	trafficErr := ctx.Err()
	if !stopTimeout() {
		<-timeoutDone
	}
	w.close()
	closed = true
	for len(w.handlerErrors) > 0 {
		<-w.handlerErrors
		r.IOFailures++
	}
	// Backend Close signals internal workers; wait briefly for their observable
	// retirement before recording the cleanup sample, without asserting RSS return.
	until := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > r.Before.Goroutines+1 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	r.After = snapshot()
	if trafficErr != nil {
		return r, trafficErr
	}
	if r.OpenFailures != r.CapacityRejections || r.IOFailures != 0 || r.ResetFailures != 0 || (!s.LimitProbe && r.Samples != s.Streams) || (s.LimitProbe && r.ExpectedCapacityRejections != 1) {
		return r, errors.New("workload correctness or cleanup failed")
	}
	return r, nil
}
func quantile(values []int64, q float64) int64 {
	if len(values) == 0 {
		return 0
	}
	return values[int(math.Ceil(q*float64(len(values))))-1]
}
func mergePeak(dst *resource, v resource) {
	dst.Goroutines = max(dst.Goroutines, v.Goroutines)
	dst.HeapAlloc = max(dst.HeapAlloc, v.HeapAlloc)
	dst.TotalAlloc = max(dst.TotalAlloc, v.TotalAlloc)
	if v.CPU != nil && (dst.CPU == nil || *v.CPU > *dst.CPU) {
		dst.CPU = v.CPU
	}
	if v.FDs != nil && (dst.FDs == nil || *v.FDs > *dst.FDs) {
		dst.FDs = v.FDs
	}
	if v.RSSBytes != nil && (dst.RSSBytes == nil || *v.RSSBytes > *dst.RSSBytes) {
		dst.RSSBytes = v.RSSBytes
	}
}
