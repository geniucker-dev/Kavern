//go:build !linux

package config

import (
	"context"
	"errors"
	"net"
	"os"
)

var ErrAdminSocket = errors.New("private administrator sockets require supported Linux")

type AdminEndpoint struct{ Listener net.Listener }

func OpenAdminListener(string) (*AdminEndpoint, error)    { return nil, ErrAdminSocket }
func (*AdminEndpoint) Close() error                       { return ErrAdminSocket }
func CheckAdminPeer(net.Conn) error                       { return ErrAdminSocket }
func DialAdmin(context.Context, string) (net.Conn, error) { return nil, ErrAdminSocket }

func CreatePrivateCredentialFile(string) (*os.File, error) { return nil, ErrAdminSocket }

func OpenAdminRequestFile(string) (*os.File, error)      { return nil, ErrAdminSocket }
func VerifyPrivateCredentialFile(string, *os.File) error { return ErrAdminSocket }
