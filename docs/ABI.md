# libgeektrust C ABI

The whole contract between this repository and the app. The app owns the session
(it authenticates), this library owns the packets. Nothing else crosses the
boundary: no controller URL, no cookie jar, no config file.

## Functions

```c
const char *geektrust_version(void);

int  geektrust_init(const char *session_json, const char *policy_json,
                    char *err, int err_len);
int  geektrust_start_proxies(const char *socks_addr, const char *http_addr,
                             char *err, int err_len);
int  geektrust_attach_tun_fd(int fd, char *err, int err_len);
int  geektrust_status(char *out_json, int out_json_len);
void geektrust_close(void);
```

All of them return `0` on success and non-zero on failure. On failure the
message written into `err` is UTF-8, human-readable and NUL-terminated; a
message longer than `err_len` is truncated, never overflowed. Every call is safe
before `geektrust_init` — `geektrust_version`, `geektrust_status` and
`geektrust_close` never touch uninitialised state, and a double close is a
no-op.

| Call | Notes |
|---|---|
| `geektrust_version` | returns `"<abi>:<version>:<source digest>"`, e.g. `"1:v0.1.0-3-gabc1234:9f2c…"`. Static string, never freed. |
| `geektrust_init` | takes the session and the policy, brings the tunnel up. Repeatable: a second call replaces the session (the app re-authenticates, then hands the new one over). |
| `geektrust_start_proxies` | starts SOCKS5 and/or HTTP CONNECT on loopback. An empty string disables that listener. This is the desktop and in-app shape. |
| `geektrust_attach_tun_fd` | hands over the tun file descriptor a platform VPN shell created (OHOS `VpnConnection.create`, Android `VpnService`) and carries what the device sends through the tunnel. The system-VPN shape; see [The tun-fd attachment](#the-tun-fd-attachment). |
| `geektrust_status` | JSON snapshot; cheap, call it on a timer. |
| `geektrust_close` | tears the tunnel, the tun attachment and the listeners down. It never closes a descriptor the app handed over. |

### The tun-fd attachment

`geektrust_attach_tun_fd` needs a **live tunnel**, because the address the stack
answers for is the tunnel's own VIP: wait until `geektrust_status` reports
`"alive": true`, then attach. A call that arrives earlier fails with a message
saying so and attaches nothing. Re-attach after a session change whose VIP
moved.

The descriptor is a packet device: one read yields one IPv4 packet, one write
sends one. The library duplicates it, sets its own copy non-blocking and reads
through a pollable handle, so:

- it **never closes the descriptor** — the app still owns it (and must close it
  itself after `geektrust_close`),
- the attachment can be stopped (`geektrust_close`) and replaced (attach again;
  a failed attach leaves the previous one running),
- a descriptor that cannot be polled is refused, because it could not be
  stopped.

Because the copy is non-blocking, the file description itself becomes
non-blocking; do not read or write that descriptor from the app while it is
attached.

What the attachment carries, through the same tunnel, policy, gateway selection
and per-connection authorization as the proxies:

| Traffic | State |
|---|---|
| TCP | carried: the stack terminates the device's connection and relays it through the tunnel dialer. |
| UDP | carried: each device-side flow becomes a tunnel UDP flow, up to one datagram of 1372 bytes (the tunnel MTU). |
| ICMP echo to the tunnel VIP | carried: the stack answers it itself — this is what the offline test proves. |
| ICMP to any other address | **not carried**: there is no per-connection authorization for an ICMP flow in the tunnel, and the stack drops it rather than reflect it. |
| IPv6 | **not carried**: only IPv4 packets are read; the tunnel path is IPv4-only. |
| UDP datagrams larger than the tunnel MTU | **not carried**: dropped instead of fragmented locally. |

## `session_json`

```json
{
  "sid":           "<controller session id>",
  "device_id":     "<32 uppercase hex>",
  "username":      "2023533189",
  "base_url":      "https://vpn.shanghaitech.edu.cn",
  "gateways":      ["10.13.90.147:441", "119.78.254.241:441"],
  "dns":           ["10.15.44.11"],
  "connection_id": "<optional, controller echo>"
}
```

- `base_url` is the controller the session came from; `{{sdpcHost}}` in the
  policy's gateway lines is expanded from it.
- `gateways` is the flattened list. The policy's per-app node groups take
  priority when they are present; this list is the fallback and the L3 path.
- `dns` may be empty — the policy's servers are used then.

## `policy_json`

The controller's `clientResource` response **`data` object, verbatim**. The app
fetches it (it already talks to the controller) and passes it through untouched,
so the routing rules are parsed in exactly one place — `sdpc.ParseResource`.

## `geektrust_status` output

```json
{
  "alive": true,
  "abi": 1,
  "vip": "10.20.205.16",
  "gateway": "10.13.90.147:441",
  "device_id": "E8483C84D8C0BFA3450C98945BD8E7FF",
  "username": "2023533189",
  "gateways": ["10.13.90.147:441"],
  "dial_attempts": 12,
  "tun": {
    "packets_in": 412,
    "bytes_in": 38904,
    "packets_out": 398,
    "bytes_out": 42110,
    "not_ipv4": 0,
    "tcp_flows": 6,
    "udp_flows": 3,
    "refused_flows": 1,
    "failed_flows": 0
  }
}
```

`alive` is the tunnel's own liveness, not the controller's. The app decides
whether the *session* is still good by asking the controller (`onlineInfo`).

`tun` is present only while a descriptor is attached (`geektrust_attach_tun_fd`),
and it is the attachment's own count of what it carried. It exists because a
platform with no log channel — OHOS forwards no native stderr to hilog — would
otherwise report every data-plane failure as the same silence: `packets_in`
rising with `tcp_flows`/`udp_flows` at zero means the device's packets reach the
stack but no flow is ever terminated, `refused_flows` counts flows the policy or
the resolver rejected, and `failed_flows` counts flows the tunnel could not dial.
Counting starts when a descriptor is attached, so it describes one attachment,
not the process's history.

## Compatibility

The `abi` integer is the only compatibility promise. The app compares it with
its own constant at load time and refuses a library that disagrees; anything
else in the strings is informational. Bump it for any change to a signature, a
JSON field, or the meaning of a return value.

The app also verifies the artifact's provenance without a Go toolchain: the
build embeds `TECHPIE-GEEKTRUST=<abi>:<version>:<source digest>` into the
library's read-only data, and the app recomputes the digest from the submodule
tree it pinned. A library built from different sources therefore fails the
app's test suite instead of drifting silently.
