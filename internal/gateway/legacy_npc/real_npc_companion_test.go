//go:build legacy_npc_integration

package legacy_npc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

// All inspection is test-private. The tap wraps only the post-authentication
// chan byte stream; only bounded partial frames and aggregate counters are kept.
// Consumed frame storage is cleared; bearer material never enters this tap.
type realNPCWireStats struct {
	frames    [9]int
	dataBytes uint64
	credits   uint64
	lastMax   uint32
}
type realNPCWireTap struct {
	net.Conn
	mu                 sync.Mutex
	changed            chan struct{}
	incoming, outgoing []byte
	read, write        realNPCWireStats
	parseErr           error
}

func newRealNPCWireTap(c net.Conn) *realNPCWireTap {
	return &realNPCWireTap{Conn: c, changed: make(chan struct{})}
}
func (c *realNPCWireTap) signal() { close(c.changed); c.changed = make(chan struct{}) }
func (c *realNPCWireTap) observe(p []byte, in bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := &c.outgoing
	stats := &c.write
	if in {
		buf = &c.incoming
		stats = &c.read
	}
	*buf = append(*buf, p...)
	for len(*buf) >= 5 {
		flag := FrameFlag((*buf)[0])
		size := 5
		switch flag {
		case FrameFlagWindow:
			size = 13
		case FrameFlagPing, FrameFlagPingResponse, FrameFlagDataFinal, FrameFlagDataContinue:
			if len(*buf) < 7 {
				c.signal()
				return
			}
			size = 7 + int(binary.LittleEndian.Uint16((*buf)[5:7]))
		case FrameFlagStreamOpen, FrameFlagStreamAccepted, FrameFlagStreamRejected, FrameFlagStreamClose:
		default:
			c.parseErr = ErrInvalidFrame
			c.signal()
			return
		}
		if size > 7+legacyProtocolMaxContentBytes {
			c.parseErr = ErrFrameTooLarge
			c.signal()
			return
		}
		if len(*buf) < size {
			break
		}
		f, err := ReadFrame(bytes.NewReader((*buf)[:size]))
		if err != nil {
			c.parseErr = err
			c.signal()
			return
		}
		stats.frames[int(f.Flag)]++
		if f.Flag == FrameFlagDataFinal || f.Flag == FrameFlagDataContinue {
			stats.dataBytes += uint64(len(f.Content))
		}
		if f.Flag == FrameFlagWindow {
			stats.credits += f.WindowState & legacyWindowDeltaMask
			stats.lastMax = uint32((f.WindowState >> 32) & legacyWindowDeltaMask)
		}
		copy(*buf, (*buf)[size:])
		clear((*buf)[len(*buf)-size:])
		*buf = (*buf)[:len(*buf)-size]
	}
	c.signal()
}
func (c *realNPCWireTap) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observe(p[:n], true)
	}
	return n, err
}
func (c *realNPCWireTap) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.observe(p[:n], false)
	}
	return n, err
}

type realNPCCompanion struct {
	ctx           context.Context
	cancel        context.CancelFunc
	gw            *Gateway
	manager       *session.Manager
	store         *store.MemoryStore
	listener      net.Listener
	acceptDone    chan struct{}
	workers       sync.WaitGroup
	mu            sync.Mutex
	changed       chan struct{}
	taps          []*realNPCWireTap
	stop          context.CancelFunc
	npcDone       chan struct{}
	current       *LegacyNpcSession
	mux           *LegacyMux
	generation    uint64
	target        net.Listener
	targetDone    chan struct{}
	targetWorkers sync.WaitGroup
	targetMu      sync.Mutex
	targetConns   map[net.Conn]struct{}
	keys          map[domain.DeviceID]string
	extraStops    []context.CancelFunc
	extraDone     []<-chan struct{}
	extraMuxes    []*LegacyMux
}

func (c *realNPCCompanion) signal() {
	c.mu.Lock()
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

type realNPCCompanionManager struct {
	*session.Manager
	c *realNPCCompanion
}

func (m realNPCCompanionManager) Attach(ctx context.Context, s session.AgentSession) error {
	err := m.Manager.Attach(ctx, s)
	m.c.signal()
	return err
}
func (m realNPCCompanionManager) Detach(ctx context.Context, id domain.SessionID) error {
	err := m.Manager.Detach(ctx, id)
	m.c.signal()
	return err
}

func newRealNPCCompanion(t *testing.T) *realNPCCompanion {
	t.Helper()
	bin := os.Getenv("NPC_BIN")
	if bin == "" {
		t.Fatal("NPC_BIN is required with legacy_npc_integration; use pinned v0.26.34 release")
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal("cannot read NPC_BIN")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != "13c12ffd3ebbab07b62cfb7e396d2290276a679f00ecb018b44f0db8e5fab2c7" {
		t.Fatal("companion requires reviewed pinned Linux amd64 v0.26.34 NPC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	c := &realNPCCompanion{ctx: ctx, cancel: cancel, manager: session.NewManager(), store: store.NewMemoryStore(), changed: make(chan struct{}), acceptDone: make(chan struct{}), npcDone: make(chan struct{}), targetDone: make(chan struct{}), targetConns: make(map[net.Conn]struct{}), keys: make(map[domain.DeviceID]string)}
	t.Cleanup(func() { c.close(t) })
	if err := c.store.CreateUser(ctx, domain.User{ID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.CreateDevice(ctx, domain.Device{ID: "device", ProjectID: "project", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	credential, err := c.store.IssueLegacyCredential(ctx, "device", []byte("private 4B test secret"))
	if err != nil {
		t.Fatal(err)
	}
	c.keys["device"] = credential.VKey
	c.gw, err = New(Config{ServerSecret: []byte("private 4B test secret"), Store: c.store, Sessions: realNPCCompanionManager{c.manager, c}, MuxConfig: LegacyMuxConfig{PingInterval: 100 * time.Millisecond, PingTimeout: 3 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	c.target, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(c.targetDone)
		for {
			conn, err := c.target.Accept()
			if err != nil {
				return
			}
			c.targetMu.Lock()
			c.targetConns[conn] = struct{}{}
			c.targetMu.Unlock()
			c.targetWorkers.Add(1)
			go func() {
				defer c.targetWorkers.Done()
				defer conn.Close()
				defer func() { c.targetMu.Lock(); delete(c.targetConns, conn); c.targetMu.Unlock() }()
				var length [4]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(length[:])
				if n > 262144 {
					return
				}
				payload := make([]byte, n)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				_ = writeAll(conn, payload)
			}()
		}
	}()
	if err := c.store.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel", DeviceID: "device", Protocol: domain.TunnelProtocolTCP, TargetAddr: c.target.Addr().String(), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	c.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(c.acceptDone)
		for {
			conn, err := c.listener.Accept()
			if err != nil {
				return
			}
			c.workers.Add(1)
			go func() {
				defer c.workers.Done()
				result, err := c.gw.readHandshake(ctx, conn)
				if err != nil {
					_ = conn.Close()
					return
				}
				switch result.connType {
				case connTypeMain:
					_ = c.gw.serveMain(ctx, conn, result.deviceID)
				case connTypeChan:
					tap := newRealNPCWireTap(conn)
					c.mu.Lock()
					c.taps = append(c.taps, tap)
					close(c.changed)
					c.changed = make(chan struct{})
					c.mu.Unlock()
					_ = c.gw.serveChan(ctx, tap, result.deviceID)
				}
				c.signal()
			}()
		}
	}()
	pc, stop := context.WithCancel(ctx)
	c.stop = stop
	cmd := exec.CommandContext(pc, bin, "-server="+c.listener.Addr().String(), "-vkey="+credential.VKey)
	cmd.Dir = t.TempDir()
	if err := cmd.Start(); err != nil {
		close(c.npcDone)
		t.Fatal("start pinned NPC:", err)
	}
	go func() { _ = cmd.Wait(); close(c.npcDone) }()
	// IO progress is a wakeup, not readiness truth. A periodic real ping also
	// wakes this loop if the first chan IO preceded runtime installation.
	for {
		c.mu.Lock()
		change := c.changed
		var tap *realNPCWireTap
		if len(c.taps) > 0 {
			tap = c.taps[len(c.taps)-1]
		}
		c.mu.Unlock()
		var wireChange <-chan struct{}
		if tap != nil {
			tap.mu.Lock()
			wireChange = tap.changed
			tap.mu.Unlock()
		}
		s, err := c.manager.CurrentForDevice(ctx, "device")
		if err == nil {
			actual := s.(*LegacyNpcSession)
			mux, generation, err := actual.snapshotMux()
			if err == nil {
				c.current = actual
				c.mux = mux
				c.generation = generation
				break
			}
		}
		select {
		case <-change:
		case <-wireChange:
		case <-ctx.Done():
			t.Fatal("real NPC companion readiness deadline")
		}
	}
	return c
}
func (c *realNPCCompanion) close(t *testing.T) {
	t.Helper()
	for i, stop := range c.extraStops {
		stop()
		select {
		case <-c.extraDone[i]:
		case <-time.After(5 * time.Second):
			t.Error("extra NPC did not exit")
		}
	}
	if c.stop != nil {
		c.stop()
		select {
		case <-c.npcDone:
		case <-time.After(5 * time.Second):
			t.Error("companion NPC did not exit")
		}
	}
	c.cancel()
	if c.listener != nil {
		_ = c.listener.Close()
		<-c.acceptDone
	}
	done := make(chan struct{})
	go func() { c.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("companion gateway workers did not exit")
	}
	if c.target != nil {
		_ = c.target.Close()
		<-c.targetDone
		c.targetMu.Lock()
		for conn := range c.targetConns {
			_ = conn.Close()
		}
		c.targetMu.Unlock()
		targetDone := make(chan struct{})
		go func() { c.targetWorkers.Wait(); close(targetDone) }()
		select {
		case <-targetDone:
		case <-time.After(5 * time.Second):
			t.Error("companion target workers did not exit")
		}
	}
	if c.gw != nil {
		c.gw.runtimeMu.Lock()
		remaining := len(c.gw.runtimes)
		c.gw.runtimeMu.Unlock()
		if remaining != 0 {
			t.Errorf("runtime leases remain: %d", remaining)
		}
	}
	for _, mux := range c.extraMuxes {
		_ = mux.Close()
		assertLegacyMuxShutdownCleared(t, mux)
	}
	if c.mux != nil {
		if err := c.mux.Close(); err != nil {
			t.Error(err)
		}
		assertLegacyMuxShutdownCleared(t, c.mux)
	}
	if _, err := c.manager.CurrentForDevice(context.Background(), "device"); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Error("manager retained current session")
	}
}
func (c *realNPCCompanion) stream(t *testing.T, size int) *LegacyStream {
	return c.streamFor(t, c.current, "tunnel", size)
}
func (c *realNPCCompanion) streamFor(t *testing.T, current *LegacyNpcSession, tunnelID domain.TunnelID, size int) *LegacyStream {
	t.Helper()
	opened, err := current.OpenStream(c.ctx, domain.StreamOpenRequest{TunnelID: tunnelID, Protocol: domain.TunnelProtocolTCP, RemoteAddr: "metadata-only"})
	if err != nil {
		t.Fatal(err)
	}
	s := opened.(*LegacyStream)
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 29)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(size))
	written := make(chan error, 1)
	go func() {
		err := writeAll(s, length[:])
		if err == nil {
			err = writeAll(s, payload)
		}
		written <- err
	}()
	got := make([]byte, size)
	_, err = io.ReadFull(s, got)
	if err != nil {
		_ = s.Close()
		t.Error("real stream echo read:", err)
	}
	if err := <-written; err != nil {
		t.Error("real stream write:", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("real stream mismatch")
	}
	buf := make([]byte, 1)
	if _, err := s.Read(buf); err != io.EOF {
		t.Error("target close did not produce EOF:", err)
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
	return s
}
func (c *realNPCCompanion) quiescent(t *testing.T) {
	t.Helper()
	for {
		c.mux.mu.Lock()
		change := c.mux.stateNotify
		done := len(c.mux.streams) == 0 && c.mux.dataCount == 0 && c.mux.openCount == 0 && c.mux.windowCount == 0 && c.mux.bufferedBytes == 0 && c.mux.tombstoneReservations == 0
		c.mux.mu.Unlock()
		if done {
			return
		}
		select {
		case <-change:
		case <-c.ctx.Done():
			t.Fatal("mux did not quiesce")
		}
	}
}
func TestRealNPCCompanionSequentialGenerationAndOwnership(t *testing.T) {
	c := newRealNPCCompanion(t)
	for i := 0; i < 129; i++ {
		s := c.stream(t, 257)
		c.quiescent(t)
		mux, generation, err := c.current.snapshotMux()
		if err != nil || mux != c.mux || generation != c.generation {
			t.Fatal("sequential matrix changed device mux generation")
		}
		c.mux.mu.Lock()
		bad := s.recvBuffered != 0 || s.recvBlocks != nil || s.dataQueue != nil || s.outstanding != 0 || s.tombstoneReserved
		bounded := len(c.mux.tombstones) <= c.mux.cfg.MaxTombstones
		c.mux.mu.Unlock()
		if bad || !bounded {
			t.Fatal("closed stream retained resources or exceeded tombstone bound")
		}
	}
	t.Log("129 sequential real NPC streams; unchanged mux generation; zero live streams/reservations/buffers after each; workers and runtime leases joined at cleanup")
}
func TestRealNPCCompanionFlowCredits(t *testing.T) {
	c := newRealNPCCompanion(t)
	c.mu.Lock()
	tap := c.taps[len(c.taps)-1]
	c.mu.Unlock()
	for _, size := range []int{122549, 122550, 122551, 131072, 262144} {
		c.stream(t, size)
		c.quiescent(t)
	}
	tap.mu.Lock()
	read, write, parseErr := tap.read, tap.write, tap.parseErr
	tap.mu.Unlock()
	if parseErr != nil {
		t.Fatal("wire tap parser:", parseErr)
	}
	if read.credits == 0 || write.credits == 0 || read.lastMax == 0 || write.lastMax != defaultLegacyMuxWindow {
		t.Fatal("real peer credit evidence missing")
	}
	if read.dataBytes < 262144 || write.dataBytes < 262144 {
		t.Fatal("large real transfers not observed")
	}
	t.Logf("unmodified initial allowance=%d; NPC consumed credit=%d advertised max=%d; server consumed credit=%d advertised max=%d; bytes NPC->server=%d server->NPC=%d", defaultLegacyMuxWindow, read.credits, read.lastMax, write.credits, write.lastMax, read.dataBytes, write.dataBytes)
}
func TestRealNPCCompanionIdlePingRecovery(t *testing.T) {
	c := newRealNPCCompanion(t)
	c.stream(t, 19)
	c.quiescent(t)
	c.mu.Lock()
	tap := c.taps[len(c.taps)-1]
	c.mu.Unlock()
	tap.mu.Lock()
	baseline := tap.write.frames[FrameFlagPing]
	tap.mu.Unlock()
	start := time.Now()
	for {
		tap.mu.Lock()
		change := tap.changed
		sent := tap.write.frames[FrameFlagPing]
		answered := tap.read.frames[FrameFlagPingResponse]
		parseErr := tap.parseErr
		tap.mu.Unlock()
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if sent >= baseline+3 && answered >= sent {
			break
		}
		select {
		case <-change:
		case <-c.ctx.Done():
			t.Fatal("real NPC ping response deadline")
		}
	}
	elapsed := time.Since(start)
	if elapsed <= 2*c.gw.muxConfig.PingInterval {
		t.Fatalf("idle span %s did not exceed two ping intervals", elapsed)
	}
	c.stream(t, 262144)
	c.quiescent(t)
	t.Logf("idle %s across >2 test ping intervals (%s), matching real responses, then 262144-byte echo on same mux", elapsed, c.gw.muxConfig.PingInterval)
}

func (c *realNPCCompanion) extraNPC(t *testing.T, id domain.DeviceID, previous domain.SessionID) (*LegacyNpcSession, *LegacyMux, uint64) {
	t.Helper()
	key := c.keys[id]
	if key == "" {
		if err := c.store.CreateDevice(c.ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		issued, err := c.store.IssueLegacyCredential(c.ctx, id, []byte("private 4B test secret"))
		if err != nil {
			t.Fatal(err)
		}
		key = issued.VKey
		c.keys[id] = key
		if err := c.store.CreateTunnel(c.ctx, domain.Tunnel{ID: domain.TunnelID("tunnel-" + string(id)), DeviceID: id, Protocol: domain.TunnelProtocolTCP, TargetAddr: c.target.Addr().String(), Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, stop := context.WithCancel(c.ctx)
	done := make(chan struct{})
	cmd := exec.CommandContext(ctx, os.Getenv("NPC_BIN"), "-server="+c.listener.Addr().String(), "-vkey="+key)
	cmd.Dir = t.TempDir()
	if err := cmd.Start(); err != nil {
		stop()
		t.Fatal("start extra NPC:", err)
	}
	c.extraStops = append(c.extraStops, stop)
	c.extraDone = append(c.extraDone, done)
	go func() { _ = cmd.Wait(); close(done) }()
	return c.waitCurrent(t, id, previous)
}
func (c *realNPCCompanion) waitCurrent(t *testing.T, id domain.DeviceID, previous domain.SessionID) (*LegacyNpcSession, *LegacyMux, uint64) {
	t.Helper()
	for {
		c.mu.Lock()
		change := c.changed
		var tap *realNPCWireTap
		if len(c.taps) > 0 {
			tap = c.taps[len(c.taps)-1]
		}
		c.mu.Unlock()
		var wireChange <-chan struct{}
		if tap != nil {
			tap.mu.Lock()
			wireChange = tap.changed
			tap.mu.Unlock()
		}
		s, err := c.manager.CurrentForDevice(c.ctx, id)
		if err == nil && s.ID() != previous {
			actual := s.(*LegacyNpcSession)
			mux, generation, err := actual.snapshotMux()
			if err == nil && (previous == "" || mux != c.mux && generation > c.generation) {
				c.extraMuxes = append(c.extraMuxes, mux)
				return actual, mux, generation
			}
		}
		select {
		case <-change:
		case <-wireChange:
		case <-c.ctx.Done():
			t.Fatal("extra real NPC readiness deadline")
		}
	}
}
func (c *realNPCCompanion) waitRuntimeAbsent(t *testing.T, id domain.DeviceID) {
	t.Helper()
	for {
		c.mu.Lock()
		change := c.changed
		c.mu.Unlock()
		c.gw.runtimeMu.Lock()
		entry := c.gw.runtimes[id]
		c.gw.runtimeMu.Unlock()
		if entry == nil {
			return
		}
		select {
		case <-change:
		case <-c.ctx.Done():
			t.Fatal("stopped device runtime retained leases")
		}
	}
}
func TestRealNPCCompanionTwoDeviceLeasesAndIsolation(t *testing.T) {
	c := newRealNPCCompanion(t)
	second, muxB, generationB := c.extraNPC(t, "second", "")
	if muxB == c.mux {
		t.Fatal("two devices share a mux")
	}
	c.streamFor(t, second, "tunnel-second", 262144)
	c.stream(t, 19)
	c.stop()
	select {
	case <-c.npcDone:
	case <-c.ctx.Done():
		t.Fatal("first NPC failed to stop")
	}
	c.waitRuntimeAbsent(t, "device")
	_ = c.mux.Close()
	assertLegacyMuxShutdownCleared(t, c.mux)
	current, err := c.manager.CurrentForDevice(c.ctx, "second")
	if err != nil || current.ID() != second.ID() {
		t.Fatal("device A stop changed device B current session")
	}
	mux, generation, err := second.snapshotMux()
	if err != nil || mux != muxB || generation != generationB {
		t.Fatal("device A stop replaced device B mux")
	}
	c.gw.runtimeMu.Lock()
	entry := c.gw.runtimes["second"]
	valid := entry != nil && entry.refs == 2 && entry.byKind[legacyRuntimeLeaseSession] == 1 && entry.byKind[legacyRuntimeLeaseChan] == 1 && entry.byKind[legacyRuntimeLeaseTransition] == 0
	c.gw.runtimeMu.Unlock()
	if !valid {
		t.Fatal("surviving device lease categories are not session+chan only")
	}
	c.streamFor(t, second, "tunnel-second", 262144)
	t.Log("device A runtime removed with workers joined; device B keeps session/mux generation and exactly session+chan leases, then echoes")
}
func TestRealNPCCompanionMainReplacementCleanup(t *testing.T) {
	c := newRealNPCCompanion(t)
	c.stream(t, 19)
	oldID := c.current.ID()
	_, _, _ = c.extraNPC(t, "device", oldID)
	c.stop()
	select {
	case <-c.npcDone:
	case <-c.ctx.Done():
		t.Fatal("first NPC failed to stop")
	}
	current, mux, generation := c.waitCurrent(t, "device", oldID)
	c.current = current
	c.stream(t, 262144)
	if mux == c.mux || generation <= c.generation {
		t.Fatal("new stock chan did not replace old device mux generation")
	}
	_ = c.mux.Close()
	assertLegacyMuxShutdownCleared(t, c.mux)
	t.Log("replacement main remains manager-current and usable after old process exits; new chan generation replaces old mux; old mux resources/workers cleared")
}
