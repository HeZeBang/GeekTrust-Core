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
| **Added for the library** | `internal/core` (the session the app hands over, the tunnel stack built from it, the proxy listeners) and `cmd/geektrustcore` (the C ABI shell — see `docs/ABI.md`) |
| **Removed** | the CLI (`cmd/geektrust`), the IDS passkey client (`internal/idsauth`), the login/session provider, the web panel, the config file, the packaging scripts |
| **Status** | the C ABI is implemented and `build.sh` builds `libgeektrust.so` for linux/amd64 and openharmony/arm64 — an artifact is installed into the app by hand, see [Building](#building). The one call still to come is `geektrust_attach_tun_fd` (the system-VPN shape): it fails with a message saying so rather than pretending to work |

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

## Building

```sh
bash build.sh
```

`build.sh` is the only build entry point (there is deliberately no CI: an OHOS
build needs the vendor SDK). It computes the provenance, builds both shared
libraries into `dist/`, and fails unless the OHOS artifact carries the arm64
`R_AARCH64_TLSDESC` relocation, both artifacts export all six `geektrust_*`
symbols, and both contain the `TECHPIE-GEEKTRUST=` marker. It is safe to re-run.

The commands it runs are:

```sh
# provenance: version from git, digest over the tree (see below)
marker="TECHPIE-GEEKTRUST=1:$(git describe --tags --always --dirty):$digest"

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -trimpath \
  -ldflags "-s -w -X geektrust/internal/core.provenance=$marker" \
  -o dist/libgeektrust-linux-amd64.so ./cmd/geektrustcore

CGO_ENABLED=1 GOOS=openharmony GOARCH=arm64 \
  GOROOT=/home/zambar/dev/ohos_golang_go \
  CC=/home/zambar/dev/command-line-tools/sdk/default/openharmony/native/llvm/bin/aarch64-unknown-linux-ohos-clang \
  PATH=/home/zambar/dev/ohos_golang_go/bin:$PATH \
  /home/zambar/dev/ohos_golang_go/bin/go build -buildmode=c-shared -trimpath \
    -ldflags "-s -w -X geektrust/internal/core.provenance=$marker" \
    -o dist/libgeektrust-openharmony-arm64.so ./cmd/geektrustcore
```

The toolchain, then: the **OpenHarmony Go fork** (upstream Go has no
`openharmony` port — the path above is what this machine has; override it with
`OHOS_GOROOT`), the OHOS SDK's **`aarch64-unknown-linux-ohos-clang`** (override
with `OHOS_CC`), and for the linux target whatever Go and C compiler are on
`PATH` (override with `LINUX_GO`). No other tool does anything: `readelf`, `nm`,
`sha256sum` and `git` are used for the checks.

### Provenance

The app recomputes the digest from the submodule checkout it pinned and refuses
a library that disagrees, so the recipe is a contract and not an implementation
detail:

- `version` = `git describe --tags --always --dirty` (the short SHA when there
  is no tag).
- `digest` = SHA-256 over every file in the tree, excluding anything under
  `.git/`, taking one line for each file — `<path relative to the repo root>`
  then its own SHA-256 as lowercase hex — with the paths sorted by byte order
  and the concatenation UTF-8. Nothing else participates: no filters, no
  prefixes, no suffixes.

Build output is removed before hashing, so a re-run of `build.sh` hashes the same
tree and prints the same digest. A *modified* tree hashes differently, which is
the point: build from the commit the app pins.

`dist/` holds the two `.so` files plus the C headers cgo generates next to them.
The libraries are copied into the app repository by hand — OHOS
`ohos/entry/libs/arm64-v8a/libgeektrust.so`, Android
`android/app/src/main/jniLibs/arm64-v8a/`, `linux/`, `windows/` — and committed
there; that checkout is what the app's digest check reads.

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
