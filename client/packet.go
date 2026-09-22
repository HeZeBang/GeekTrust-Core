package client

import "context"

// PacketTransport is optional and owns no system interfaces. ExchangePacket
// returns a real response or an error; it never synthesizes Echo success.
// Currently only authorized, unfragmented IPv4 ICMP Echo is supported.
type PacketTransport interface {
	ExchangePacket(context.Context, []byte) ([]byte, error)
}

func (c *Client) ExchangePacket(parent context.Context, packet []byte) ([]byte, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	return c.dialer.ExchangePacket(ctx, packet)
}
