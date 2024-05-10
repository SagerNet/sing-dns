package dns

import (
	"context"
	"net/netip"
)

type disableCacheKey struct{}

func ContextWithDisableCache(ctx context.Context, val bool) context.Context {
	return context.WithValue(ctx, (*disableCacheKey)(nil), val)
}

func DisableCacheFromContext(ctx context.Context) bool {
	val := ctx.Value((*disableCacheKey)(nil))
	if val == nil {
		return false
	}
	return val.(bool)
}

type rewriteTTLKey struct{}

func ContextWithRewriteTTL(ctx context.Context, val uint32) context.Context {
	return context.WithValue(ctx, (*rewriteTTLKey)(nil), val)
}

func RewriteTTLFromContext(ctx context.Context) (uint32, bool) {
	val := ctx.Value((*rewriteTTLKey)(nil))
	if val == nil {
		return 0, false
	}
	return val.(uint32), true
}

type transportKey struct{}

func contextWithTransportName(ctx context.Context, transportName string) context.Context {
	return context.WithValue(ctx, transportKey{}, transportName)
}

func transportNameFromContext(ctx context.Context) (string, bool) {
	value, loaded := ctx.Value(transportKey{}).(string)
	return value, loaded
}

type clientSubnetKey struct{}

func ContextWithClientSubnet(ctx context.Context, clientSubnet netip.Prefix) context.Context {
	return context.WithValue(ctx, clientSubnetKey{}, clientSubnet)
}

func ClientSubnetFromContext(ctx context.Context) (netip.Prefix, bool) {
	clientSubnet, ok := ctx.Value(clientSubnetKey{}).(netip.Prefix)
	return clientSubnet, ok
}
