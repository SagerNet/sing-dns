package test_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	t.Parallel()
	servers := []string{
		"tcp://1.0.0.1",
		"udp://1.0.0.1",
		"tls://1.0.0.1",
		"https://1.0.0.1/dns-query",
		"quic://dns.adguard.com",
		"h3://8.8.8.8/dns-query",
	}
	for _, server := range servers {
		t.Log(server)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		client := dns.NewClient(dns.DomainStrategyAsIS, false, false)
		dnsTransport, err := dns.NewTransport(context.Background(), N.SystemDialer, server)
		if err == os.ErrInvalid {
			cancel()
			continue
		}
		require.NoError(t, err)
		response, err := client.Exchange(ctx, dnsTransport, makeQuery())
		require.NoError(t, err)
		require.NotEmpty(t, response.Answers, "no answers")
		response, err = client.Exchange(ctx, dnsTransport, makeQuery())
		require.NoError(t, err)
		require.NotEmpty(t, response.Answers, "no answers")
		addresses, err := client.Lookup(ctx, dnsTransport, "www.google.com", dns.DomainStrategyAsIS)
		require.NoError(t, err)
		require.NotEmpty(t, addresses, "no answers")
		cancel()
	}
}
