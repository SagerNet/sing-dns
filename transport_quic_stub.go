//go:build !with_quic

package dns

import (
	"context"
	"os"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func NewQUICTransport(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) (Transport, error) {
	return nil, os.ErrInvalid
}

func NewHTTP3Transport(dialer N.Dialer, destination string) (Transport, error) {
	return nil, os.ErrInvalid
}
