//go:build linux

package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func adminPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "r")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(dir, "a.sock")
}
func TestAdminSocketOwnershipPeersAndJoinedCleanup(t *testing.T) {
	p := adminPath(t)
	e, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdminListener(p); err == nil {
		t.Fatal("active endpoint replaced")
	}
	done := make(chan error, 1)
	go func() {
		c, err := e.Listener.Accept()
		if err == nil {
			err = CheckAdminPeer(c)
			c.Close()
		}
		done <- err
	}()
	c, err := DialAdmin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("owned socket retained")
	}
	next, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestAdminSocketRecognizesOnlyOwnedStaleEndpoint(t *testing.T) {
	p := adminPath(t)
	e, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	e.Listener.Close()
	e.node.Close()
	e.lock.Close()
	e.dir.Close()
	next, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	unrelated, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	unrelated.SetUnlinkOnClose(false)
	unrelated.Close()
	os.Chmod(p, 0600)
	if _, err = OpenAdminListener(p); err == nil {
		t.Fatal("unrelated stale socket removed")
	}
	if _, err = os.Lstat(p); err != nil {
		t.Fatal("unrelated endpoint disappeared")
	}
}
func TestAdminSocketRejectsPathsAndPreservesReplacement(t *testing.T) {
	p := adminPath(t)
	dir := filepath.Dir(p)
	os.Chmod(dir, 0755)
	if _, e := OpenAdminListener(p); !errors.Is(e, ErrAdminSocket) {
		t.Fatal("public directory accepted")
	}
	os.Chmod(dir, 0700)
	os.Symlink("target", p)
	if _, e := OpenAdminListener(p); !errors.Is(e, ErrAdminSocket) {
		t.Fatal("symlink accepted")
	}
	os.Remove(p)
	e, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	os.Rename(p, p+".old")
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	os.Chmod(p, 0600)
	if err = e.Close(); err == nil {
		t.Fatal("replacement ownership loss not reported")
	}
	if _, err = os.Lstat(p); err != nil {
		t.Fatal("replacement unlinked")
	}
}
func TestAdminSocketPinsRuntimeDirectoryAcrossRename(t *testing.T) {
	p := adminPath(t)
	e, err := OpenAdminListener(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p)
	if err = os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(dir, 0700)
	replacement := filepath.Join(dir, "a.sock")
	os.WriteFile(replacement, []byte("preserve"), 0600)
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(replacement); err != nil || string(b) != "preserve" {
		t.Fatal("replacement directory touched")
	}
	if _, err = os.Lstat(filepath.Join(dir+".old", "a.sock")); !os.IsNotExist(err) {
		t.Fatal("pinned socket not cleaned")
	}
}
func TestAdminSocketConcurrentOpenHasOneOwner(t *testing.T) {
	path := adminPath(t)
	const count = 8
	results := make(chan *AdminEndpoint, count)
	release := make(chan struct{})
	var joined sync.WaitGroup
	for i := 0; i < count; i++ {
		joined.Add(1)
		go func() {
			defer joined.Done()
			endpoint, e := OpenAdminListener(path)
			if e != nil {
				results <- nil
				return
			}
			results <- endpoint
			<-release
			if e = endpoint.Close(); e != nil {
				t.Error(e)
			}
		}()
	}
	owners := 0
	for i := 0; i < count; i++ {
		if <-results != nil {
			owners++
		}
	}
	close(release)
	joined.Wait()
	if owners != 1 {
		t.Fatalf("owners=%d", owners)
	}
}
func TestAdminSocketRejectsSymlinkAncestorAndOwnershipSidecar(t *testing.T) {
	path := adminPath(t)
	dir := filepath.Dir(path)
	alias := dir + "-alias"
	os.Symlink(dir, alias)
	if _, e := OpenAdminListener(filepath.Join(alias, "a.sock")); e == nil {
		t.Fatal("symlink ancestor accepted")
	}
	target := filepath.Join(dir, "preserve")
	os.WriteFile(target, []byte("unchanged"), 0600)
	os.Symlink(target, path+".lock")
	if _, e := OpenAdminListener(path); e == nil {
		t.Fatal("symlink sidecar accepted")
	}
	if data, e := os.ReadFile(target); e != nil || string(data) != "unchanged" {
		t.Fatal("sidecar target changed")
	}
	os.Remove(path + ".lock")
	os.Link(target, path+".lock")
	if _, e := OpenAdminListener(path); e == nil {
		t.Fatal("hardlinked sidecar accepted")
	}
}
func TestAdminWindowAcceptsCanonicalLineageIncludingLeadingDashUnderscore(t *testing.T) {
	for _, first := range []byte{0xfb, 0xff} {
		raw := make([]byte, 16)
		raw[0] = first
		lineage := base64.RawURLEncoding.EncodeToString(raw)
		if _, e := (AdminWindow{Lineage: lineage, Epoch: "1"}).EpochValue(); e != nil {
			t.Fatal("valid store lineage rejected")
		}
	}
	for _, w := range []AdminWindow{{Lineage: "not-a-lineage", Epoch: "1"}, {Lineage: strings.Repeat("A", 21) + "B", Epoch: "1"}, {Epoch: "01"}, {Epoch: "1"}} {
		if _, e := w.EpochValue(); e == nil {
			t.Fatal("invalid window accepted")
		}
	}
	if n, e := (AdminWindow{Epoch: "0"}).EpochValue(); e != nil || n != 0 {
		t.Fatal("migration bootstrap rejected")
	}
}
func TestPrivateCredentialDestinationReplacementDoesNotConfirmDelivery(t *testing.T) {
	path := filepath.Join(filepath.Dir(adminPath(t)), "credential.json")
	file, e := CreatePrivateCredentialFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	file.Write([]byte("synthetic"))
	file.Sync()
	if e = VerifyPrivateCredentialFile(path, file); e != nil {
		t.Fatal(e)
	}
	os.Rename(path, path+".old")
	os.WriteFile(path, []byte("replacement"), 0600)
	if e = VerifyPrivateCredentialFile(path, file); e == nil {
		t.Fatal("replacement accepted as delivered destination")
	}
	if b, e := os.ReadFile(path); e != nil || string(b) != "replacement" {
		t.Fatal("replacement altered")
	}
}
func TestAdminSocketDoesNotOverwriteUnrelatedRegularOwnershipSidecar(t *testing.T) {
	path := adminPath(t)
	sidecar := path + ".lock"
	before := []byte("unrelated private data")
	os.WriteFile(sidecar, before, 0600)
	if _, e := OpenAdminListener(path); e == nil {
		t.Fatal("unrelated ownership file accepted")
	}
	after, e := os.ReadFile(sidecar)
	if e != nil || !bytes.Equal(after, before) {
		t.Fatal("unrelated sidecar overwritten")
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("endpoint created before ownership proof")
	}
}
func shortAdminBoundaryDirectory(t *testing.T) string {
	t.Helper()
	for a := 'a'; a <= 'z'; a++ {
		for b := 'a'; b <= 'z'; b++ {
			dir := fmt.Sprintf("/tmp/%c%c", a, b)
			if e := os.Mkdir(dir, 0700); e == nil {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			}
		}
	}
	t.Fatal("no short temporary directory available")
	return ""
}
func TestAdminSocketPathBoundariesPublishDialProbeAndCleanup(t *testing.T) {
	for _, length := range []int{99, 100, 101} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			dir := shortAdminBoundaryDirectory(t)
			path := filepath.Join(dir, strings.Repeat("s", length-len(dir)-1))
			endpoint, e := OpenAdminListener(path)
			if length > 100 {
				if e == nil {
					endpoint.Close()
					t.Fatal("over-limit path published")
				}
				entries, e := os.ReadDir(dir)
				if e != nil || len(entries) != 0 {
					t.Fatal("rejection left endpoint resources")
				}
				return
			}
			if e != nil {
				t.Fatal("valid boundary rejected", e)
			}
			verified, e := DialAdmin(context.Background(), path)
			if e != nil {
				endpoint.Close()
				t.Fatal("published boundary not reachable", e)
			}
			verified.Close()
			// Release the ownership lock while retaining a live listener: the actual
			// pinned-inode probe, rather than the lock alone, must prevent stale adoption.
			endpoint.lock.Close()
			if other, e := OpenAdminListener(path); e == nil {
				other.Close()
				t.Fatal("active boundary socket removed after lock release")
			}
			if _, e = os.Lstat(path); e != nil {
				t.Fatal("active socket disappeared")
			}
			// Model a stopped owner while preserving its published marker and pathname.
			endpoint.Listener.Close()
			endpoint.node.Close()
			endpoint.dir.Close()
			restarted, e := OpenAdminListener(path)
			if e != nil {
				t.Fatal("long stale endpoint not recovered", e)
			}
			verified, e = DialAdmin(context.Background(), path)
			if e != nil {
				restarted.Close()
				t.Fatal("recovered boundary not reachable", e)
			}
			verified.Close()
			if e = restarted.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Lstat(path); !os.IsNotExist(e) {
				t.Fatal("boundary socket retained")
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path)+".lock" {
				t.Fatal("temporary endpoint resources leaked")
			}
		})
	}
}
