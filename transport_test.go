package dns_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-dns"
	_ "github.com/sagernet/sing-dns/quic"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestTransports(t *testing.T) {
	serverAddressList := []string{
		"114.114.114.114",
		"tcp://114.114.114.114",
		"tls://223.5.5.5",
		"https://223.5.5.5/dns-query",
		"quic://dns.alidns.com",
		"h3://dns.alidns.com/dns-query",
	}
	for _, serverAddressItem := range serverAddressList {
		serverAddress := serverAddressItem
		t.Run(serverAddress, func(t *testing.T) {
			transport, err := dns.CreateTransport(dns.TransportOptions{
				Context: context.Background(),
				Logger:  logger.NOP(),
				Address: serverAddress,
				Dialer:  N.SystemDialer,
			})
			require.NoError(t, err)
			require.NotNil(t, transport)
			client := dns.NewClient(dns.ClientOptions{
				Logger: logger.NOP(),
			})
			addresses, err := client.Lookup(context.Background(), transport, "cloudflare.com", dns.DomainStrategyAsIS)
			require.NoError(t, err)
			require.NotEmpty(t, addresses)
		})
	}
}
