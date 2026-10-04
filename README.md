# GeekTrust-Core

The **data plane** of the campus aTrust client, packaged as a shared library for
the TechPie Flutter app.

```
Flutter app (control plane)                this repo (data plane)
  authConfig → CAS → reportEnv            ┌──────────────────────────────┐
  → authCheck → SMS → sidTicket           │  frame  0x05 codec            │
  → sessionIdExchange → onlineInfo        │  tunnel TLS to the gateway    │
  → clientResource (policy JSON)          │  l3     gVisor fallback       │
            │                             │  resolver  policy matching    │
            └── session + policy ────────►│  inbound  SOCKS5 / HTTP       │
                                          └──────────────────────────────┘
                                                        libgeektrust.so
```

Authentication, session persistence, SMS prompting and every byte of UI live in
the app. This repository is handed **a session and a policy** (plain JSON) and
answers with packets.

## Scope

| | |
|---|---|
| **Kept** | `internal/frame`, `internal/tunnel`, `internal/l3`, `internal/resolver`, `internal/inbound`, `internal/sdpc` (policy parsing only), `internal/session` (the credential types only) |
| **Removed** | the CLI (`cmd/geektrust`), the IDS passkey client (`internal/idsauth`), the login/session provider, the web panel, the config file, the packaging scripts |
| **Status** | the data plane is trimmed and green (`go build ./...`, `go test ./...`); the C ABI shell and the build script are the next step — see `docs/ABI.md` for the frozen contract |

## Naming

One library, one prefix, no exceptions:

| Thing | Name |
|---|---|
| shared library | `libgeektrust.so` (`.dylib` / `.dll` on the other desktops) |
| C ABI | `geektrust_init`, `geektrust_start_proxies`, `geektrust_attach_tun_fd`, `geektrust_status`, `geektrust_close`, `geektrust_version` |
| provenance marker embedded in the artifact | `TECHPIE-GEEKTRUST=<abi>:<version>:<source digest>` |

`aTrust` (the Sangfor product, its SDP 2.0 protocol and the campus controller)
keeps its own name in prose and comments: it is the thing being talked to, not a
name of ours.

## How the app consumes it

The app pins this repository as a git submodule and commits the built library per
platform, because an OHOS build needs the vendor SDK and therefore cannot run in
CI:

| Platform | Artifact lives at |
|---|---|
| OHOS | `ohos/entry/libs/arm64-v8a/libgeektrust.so` |
| Android | `android/app/src/main/jniLibs/arm64-v8a/libgeektrust.so` |
| Linux | `linux/libgeektrust.so`, installed into the bundle's `lib/` |
| Windows | `windows/libgeektrust.dll`, next to the executable |
| macOS | `macos/Frameworks/` (needs signing with the app) |
| iOS | not supported — `dlopen` of a foreign dylib is not allowed; it would need static linking and a network extension |

The pin plus the digest embedded in the artifact is what keeps the two in step:
the app recomputes the digest from the submodule's tree and refuses a library
that was not built from it.

## Upstream

A fork of [ShanghaitechGeekPie/geektrust](https://github.com/ShanghaitechGeekPie/geektrust)
(which keeps the CLI, the passkey login and the web panel). Data-plane fixes are
pulled from `upstream`, never edited in both places:

```sh
git remote add upstream https://github.com/ShanghaitechGeekPie/geektrust.git
git fetch upstream && git cherry-pick <commit>
```

## License

MIT — see `LICENSE`.
