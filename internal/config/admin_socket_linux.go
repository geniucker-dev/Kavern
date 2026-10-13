//go:build linux

package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var ErrAdminSocket = errors.New("private administrator socket unavailable or ownership invalid")

const adminOPath = 0x200000

// AdminEndpoint pins the runtime directory and socket inode, and retains an
// ownership lock until the HTTP server has joined its workers and calls Close.
type AdminEndpoint struct {
	Listener        net.Listener
	dir, node, lock *os.File
	name            string
	identity        socketIdentity
	once            sync.Once
	err             error
}

const adminOwnershipMagic = "kavern-admin-v1"

type socketIdentity struct {
	Owner       string
	Device      uint64
	Inode       uint64
	Seconds     int64
	Nanoseconds int64
}

func identity(st *syscall.Stat_t) socketIdentity {
	return socketIdentity{Owner: adminOwnershipMagic, Device: uint64(st.Dev), Inode: st.Ino, Seconds: int64(st.Ctim.Sec), Nanoseconds: int64(st.Ctim.Nsec)}
}
func adminDirectory(path string) (*os.File, string, error) {
	if len(path) > 100 {
		return nil, "", ErrAdminSocket
	}
	return privateDirectory(path)
}
func privateDirectory(path string) (*os.File, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return nil, "", ErrAdminSocket
	}
	name := filepath.Base(path)
	if name == "." || name == "/" {
		return nil, "", ErrAdminSocket
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, "", ErrAdminSocket
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, "", ErrAdminSocket
		}
		fd = next
	}
	var st syscall.Stat_t
	if e = syscall.Fstat(fd, &st); e != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		syscall.Close(fd)
		return nil, "", ErrAdminSocket
	}
	return os.NewFile(uintptr(fd), "admin-runtime"), name, nil
}
func socketNode(dir *os.File, name string) (*os.File, syscall.Stat_t, error) {
	return socketNodeMode(dir, name, true)
}
func socketNodeMode(dir *os.File, name string, requirePrivate bool) (*os.File, syscall.Stat_t, error) {
	fd, e := syscall.Openat(int(dir.Fd()), name, adminOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, syscall.Stat_t{}, e
	}
	var st syscall.Stat_t
	e = syscall.Fstat(fd, &st)
	if e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK || (requirePrivate && st.Mode&0777 != 0600) || st.Uid != uint32(os.Geteuid()) {
		syscall.Close(fd)
		return nil, st, ErrAdminSocket
	}
	return os.NewFile(uintptr(fd), "admin-socket-inode"), st, nil
}
func adminName() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrAdminSocket
	}
	return ".kavern-" + hex.EncodeToString(b[:]), nil
}
func renameExclusive(dir *os.File, from, to string) error {
	// Linux renameat2(RENAME_NOREPLACE) avoids overwriting a concurrently replaced
	// name. Architectures without a reviewed trap mapping fail explicitly.
	trap := adminRenameTrap()
	if trap == 0 {
		return ErrAdminSocket
	}
	a, e := syscall.BytePtrFromString(from)
	if e != nil {
		return e
	}
	b, e := syscall.BytePtrFromString(to)
	if e != nil {
		return e
	}
	_, _, errno := syscall.Syscall6(trap, dir.Fd(), uintptr(unsafe.Pointer(a)), dir.Fd(), uintptr(unsafe.Pointer(b)), 1, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// removeOwned captures the name atomically, then checks the pinned inode. It
// never unlinks a replacement; a racing replacement is restored without overwrite.
func removeOwned(dir *os.File, name string, want socketIdentity) error {
	node, st, e := socketNodeMode(dir, name, false)
	if errors.Is(e, syscall.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	node.Close()
	if st.Ino != want.Inode || uint64(st.Dev) != want.Device {
		return ErrAdminSocket
	}
	captured, e := adminName()
	if e != nil {
		return e
	}
	if e = renameExclusive(dir, name, captured); e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return nil
		}
		return e
	}
	moved, got, e := socketNodeMode(dir, captured, false)
	if moved != nil {
		moved.Close()
	}
	if e != nil || got.Ino != want.Inode || uint64(got.Dev) != want.Device {
		restore := renameExclusive(dir, captured, name)
		return errors.Join(ErrAdminSocket, restore)
	}
	return syscall.Unlinkat(int(dir.Fd()), captured)
}
func OpenAdminListener(path string) (result *AdminEndpoint, err error) {
	if adminRenameTrap() == 0 {
		return nil, ErrAdminSocket
	}
	dir, name, e := adminDirectory(path)
	if e != nil {
		return nil, e
	}
	endpoint := &AdminEndpoint{dir: dir, name: name}
	defer func() {
		if err != nil {
			if endpoint.Listener != nil {
				_ = endpoint.Listener.Close()
			}
			if endpoint.node != nil {
				_ = removeOwned(dir, name, endpoint.identity)
				_ = endpoint.node.Close()
			}
			if endpoint.lock != nil {
				_ = endpoint.lock.Close()
			}
			_ = dir.Close()
		}
	}()
	endpoint.lock, e = openAdminOwnership(dir, name+".lock")
	if e != nil {
		return nil, ErrAdminSocket
	}
	fd := int(endpoint.lock.Fd())
	var lockStat syscall.Stat_t
	if syscall.Fstat(fd, &lockStat) != nil || lockStat.Uid != uint32(os.Geteuid()) || lockStat.Mode&syscall.S_IFMT != syscall.S_IFREG || lockStat.Mode&0777 != 0600 || lockStat.Nlink != 1 || lockStat.Size > 512 || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrAdminSocket
	}
	var marker socketIdentity
	if DecodeJSON(io.LimitReader(endpoint.lock, 513), &marker) != nil || marker.Owner != adminOwnershipMagic {
		return nil, ErrAdminSocket
	}

	prior, st, e := socketNode(dir, name)
	if e == nil {
		defer prior.Close()
		if marker != identity(&st) {
			return nil, ErrAdminSocket
		}
		c, dialErr := net.DialTimeout("unix", fmt.Sprintf("/proc/self/fd/%d", prior.Fd()), 100*time.Millisecond)
		if c != nil {
			c.Close()
			return nil, ErrAdminSocket
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, ErrAdminSocket
		}
		if e = removeOwned(dir, name, marker); e != nil {
			return nil, ErrAdminSocket
		}
	} else if !errors.Is(e, syscall.ENOENT) {
		return nil, ErrAdminSocket
	}
	tmp, e := adminName()
	if e != nil {
		return nil, e
	}
	addr := fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), tmp)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if e != nil {
		return nil, ErrAdminSocket
	}
	listener.SetUnlinkOnClose(false)
	endpoint.Listener = listener
	// Pin the freshly created inode before following /proc for chmod. O_PATH plus
	// NOFOLLOW ensures chmod cannot be redirected to an unrelated symlink target.
	nodeFD, e := syscall.Openat(int(dir.Fd()), tmp, adminOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdminSocket
	}
	endpoint.node = os.NewFile(uintptr(nodeFD), "admin-socket-inode")
	var created syscall.Stat_t
	if syscall.Fstat(nodeFD, &created) != nil || created.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return nil, ErrAdminSocket
	}
	endpoint.identity = identity(&created)
	defer func() {
		if err != nil {
			_ = removeOwned(dir, tmp, endpoint.identity)
		}
	}()
	if e = os.Chmod(fmt.Sprintf("/proc/self/fd/%d", nodeFD), 0600); e != nil {
		return nil, ErrAdminSocket
	}

	if e = renameExclusive(dir, tmp, name); e != nil {
		return nil, ErrAdminSocket
	}
	if e = syscall.Fstat(nodeFD, &created); e != nil {
		return nil, ErrAdminSocket
	}
	endpoint.identity = identity(&created)
	if e = writeAdminMarker(endpoint.lock, endpoint.identity); e != nil {
		return nil, ErrAdminSocket
	}
	return endpoint, nil
}
func (e *AdminEndpoint) Close() error {
	e.once.Do(func() {
		if e.Listener != nil {
			_ = e.Listener.Close()
		}
		e.err = removeOwned(e.dir, e.name, e.identity)
		_ = e.node.Close()
		_ = e.lock.Close()
		_ = e.dir.Close()
	})
	return e.err
}
func CheckAdminPeer(conn net.Conn) error {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return ErrAdminSocket
	}
	raw, e := unix.SyscallConn()
	if e != nil {
		return ErrAdminSocket
	}
	var inner error
	e = raw.Control(func(fd uintptr) {
		peer, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil || peer.Uid != uint32(os.Geteuid()) {
			inner = ErrAdminSocket
		}
	})
	if e != nil || inner != nil {
		return ErrAdminSocket
	}
	return nil
}
func DialAdmin(ctx context.Context, path string) (net.Conn, error) {
	dir, name, e := adminDirectory(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	node, before, e := socketNode(dir, name)
	if e != nil {
		return nil, ErrAdminSocket
	}
	defer node.Close()
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d", node.Fd()))
	if e != nil {
		return nil, ErrAdminSocket
	}
	afterNode, after, e := socketNode(dir, name)
	if afterNode != nil {
		afterNode.Close()
	}
	if e != nil || before.Ino != after.Ino || before.Dev != after.Dev || CheckAdminPeer(conn) != nil {
		conn.Close()
		return nil, ErrAdminSocket
	}
	return conn, nil
}

// CreatePrivateCredentialFile reserves a new issuance destination before mutation.
// Only descriptor-based writes/chmod occur; existing names are never overwritten.
func CreatePrivateCredentialFile(path string) (*os.File, error) {
	dir, name, e := privateDirectory(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, ErrAdminSocket
	}
	f := os.NewFile(uintptr(fd), "credential-output")
	if syscall.Fchmod(fd, 0600) != nil || dir.Sync() != nil {
		f.Close()
		return nil, ErrAdminSocket
	}
	return f, nil
}

// Regular bounded input prevents FIFOs/devices from turning CLI parsing into an
// unbounded blocking read. Request files carry business data, not credentials.
func OpenAdminRequestFile(path string) (*os.File, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAdminSocket
	}
	f := os.NewFile(uintptr(fd), "admin-request")
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > MaxJSONBytes {
		f.Close()
		return nil, ErrAdminSocket
	}
	return f, nil
}

func adminRenameTrap() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 316
	case "arm64", "riscv64", "loong64":
		return 276
	default:
		return 0
	}
}

// VerifyPrivateCredentialFile confirms that the caller-selected name still
// refers to the descriptor we wrote, without following replacement symlinks.
func VerifyPrivateCredentialFile(path string, file *os.File) error {
	dir, name, e := privateDirectory(path)
	if e != nil {
		return ErrAdminSocket
	}
	defer dir.Close()
	fd, e := syscall.Openat(int(dir.Fd()), name, adminOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return ErrAdminSocket
	}
	defer syscall.Close(fd)
	var want, got syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &want) != nil || syscall.Fstat(fd, &got) != nil || got.Dev != want.Dev || got.Ino != want.Ino || got.Mode&syscall.S_IFMT != syscall.S_IFREG || got.Mode&0777 != 0600 || got.Nlink != 1 || got.Uid != uint32(os.Geteuid()) {
		return ErrAdminSocket
	}
	return nil
}

func writeAdminMarker(file *os.File, marker socketIdentity) error {
	data, e := json.Marshal(marker)
	if e != nil {
		return ErrAdminSocket
	}
	if file.Truncate(0) != nil {
		return ErrAdminSocket
	}
	n, e := file.WriteAt(data, 0)
	if e != nil || n != len(data) || file.Sync() != nil {
		return ErrAdminSocket
	}
	return nil
}

// Publish the new ownership file only after initialization and lock acquisition,
// so a concurrent opener can never win an uninitialized-file creation gap.
func openAdminOwnership(dir *os.File, name string) (*os.File, error) {
	for attempt := 0; attempt < 3; attempt++ {
		fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e == nil {
			return os.NewFile(uintptr(fd), "admin-ownership"), nil
		}
		if !errors.Is(e, syscall.ENOENT) {
			return nil, ErrAdminSocket
		}
		tmp, e := adminName()
		if e != nil {
			return nil, e
		}
		fd, e = syscall.Openat(int(dir.Fd()), tmp, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return nil, ErrAdminSocket
		}
		file := os.NewFile(uintptr(fd), "new-admin-ownership")
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil {
			file.Close()
			return nil, ErrAdminSocket
		}
		fail := func() { _ = removeOwnedRegular(dir, tmp, identity(&st)); _ = file.Close() }
		if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil || writeAdminMarker(file, socketIdentity{Owner: adminOwnershipMagic}) != nil {
			fail()
			return nil, ErrAdminSocket
		}
		if e = renameExclusive(dir, tmp, name); e == nil {
			return file, nil
		}
		fail()
		if !errors.Is(e, syscall.EEXIST) {
			return nil, ErrAdminSocket
		}
	}
	return nil, ErrAdminSocket
}
func regularAdminNode(dir *os.File, name string) (*os.File, syscall.Stat_t, error) {
	fd, e := syscall.Openat(int(dir.Fd()), name, adminOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, syscall.Stat_t{}, e
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) {
		syscall.Close(fd)
		return nil, st, ErrAdminSocket
	}
	return os.NewFile(uintptr(fd), "owned-file-inode"), st, nil
}
func removeOwnedRegular(dir *os.File, name string, want socketIdentity) error {
	node, st, e := regularAdminNode(dir, name)
	if errors.Is(e, syscall.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	node.Close()
	if st.Ino != want.Inode || uint64(st.Dev) != want.Device {
		return ErrAdminSocket
	}
	captured, e := adminName()
	if e != nil {
		return e
	}
	if e = renameExclusive(dir, name, captured); e != nil {
		return e
	}
	moved, got, e := regularAdminNode(dir, captured)
	if moved != nil {
		moved.Close()
	}
	if e != nil || got.Ino != want.Inode || uint64(got.Dev) != want.Device {
		return errors.Join(ErrAdminSocket, renameExclusive(dir, captured, name))
	}
	return syscall.Unlinkat(int(dir.Fd()), captured)
}

// ValidatePrivateCredentialDirectory verifies an existing owned private directory.
// It does not create a directory, destination or credential.
func ValidatePrivateCredentialDirectory(path string) error {
	d, _, e := privateDirectory(filepath.Join(path, "kavern-credential-check"))
	if e != nil {
		return e
	}
	return d.Close()
}
