# Embedded aTrust client

The `client` package provides authentication, controller resource policy and
TCP/UDP data transport. It does not open local proxy listeners, create a TUN,
install routes or change DNS. The embedding application owns those resources.

Create a client with an HTTPS controller origin, a persistent device ID and an
`Authenticator`. `PasskeyAuthenticator` accepts ECNU and ShanghaiTech keystores
through an application-owned `BlobStore`. The store must durably save updates
and protect its contents. Reuse one authenticator per credential; do not use the
same imported credential concurrently in another program. A failed counter save
prevents assertion submission.

```go
c, err := client.New(client.Options{
    ControllerURL: "https://vpn.example.edu",
    DeviceID: deviceID,
    Authenticator: &client.PasskeyAuthenticator{Store: credentials},
    SessionStore: sessions,
})
if err != nil { return err }
defer c.Close()
info, err := c.Connect(ctx)
if err != nil { return err }
_ = info // controller resources, DNS and protocol capabilities
conn, err := c.DialContext(ctx, "tcp", "authorized.example.edu:443")
if err != nil { return err }
defer conn.Close()
```

UDP connections retain datagram boundaries and reject payloads exceeding the
1372-byte tunnel limit. Set connection deadlines for data
I/O; dialing and authentication accept cancellation and have bounded setup
timeouts. `Close` is repeatable and closes the client's active connections.
Events contain typed lifecycle transitions without credentials or server bodies.

The optional `PacketTransport` accepts unfragmented IPv4 ICMP Echo requests.
It returns a genuine matching reply or an error. It does not synthesize successful
ping responses. IPv6 target transport is not implemented; IPv6 gateway addressing
is supported separately. Packet implementation alone does not imply that a given
deployment authorizes ICMP.

Applications are selected from controller policy, including protocol and port.
TCP uses L3 only when the selected application requests it. An absent assigned
gateway group is an error, not a reason to use another group. There is no public
Internet redial after a tunnel failure.

## Development status

This interface is under development and is not a released library version.
ECNU Passkey login, aTrust session establishment, and authorized UDP/TCP DNS
round trips and an HTTPS 200 response from the school homepage have been exercised
on Windows. An authorized ICMP exchange timed out; Echo is not verified on ECNU.
L3 TCP, ShanghaiTech
live login and macOS/Linux live connections still require deployment testing.
The CLI login and dial commands use this interface. Proxy/web-panel wiring
is being moved over; it currently retains
internal wiring for the web panel and device-management commands.

Protocol behavior was reviewed against the aTrust implementation used by
[EZ4Connect](https://github.com/chenx-dust/EZ4Connect), in
[zju-connect](https://github.com/Mythologyli/zju-connect/tree/4031c52214478d4082189b778ffc6e9744f1d256/client/atrust).
No source files or Go module dependency were imported from that implementation.
Upstream contribution should separate resource/transport corrections, credential
injection and lifecycle changes, and the public package. Public library/product
release remains pending upstream authorization.
