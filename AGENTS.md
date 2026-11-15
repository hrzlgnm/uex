# AGENTS.md — uex

## Build & check

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
typos
```

No codegen. Sockets need no root (port 1900 is shared via SO_REUSEADDR/PORT).
Headless run (no TTY) prints discovery events to stdout.

## Layout

* `src/main.rs` — CLI, rotating file logger, TUI init/restore.
* `src/ssdp.rs` — transport: shared port-1900 listeners (v4 + v6 link/site
  groups) observe NOTIFY and foreign M-SEARCH. By default the listener also
  sends M-SEARCH per interface, so unicast replies hit port 1900 (one
  firewall rule); `--search-port N` uses a separate search socket instead
  (a second socket on 1900 would double every multicast packet). HTTPU parse, ingress interface via IP_PKTINFO.
  Interface policy mirrors mex (`lo`/`docker`/`veth` skipped unless `-i`).
* `src/describe.rs` — LOCATION fetch (http only, 5s, 1 MiB cap, no
  redirects) and namespace-agnostic description parse. Link-local v6 hosts
  connect with the advert's ingress ifindex as scope via a ureq `Resolver`
  (semver-exempt `ureq::unversioned` API; Host header stays zone-free).
* `src/app.rs` — advert cache keyed by UUID → USN, expiry, search
  scheduling, issue checks, selection/input.
* `src/ui.rs` — ratatui rendering only, no state mutations.

## Protocol rules (UDA 2.0 §1)

* Startup burst of 3 searches (0/1/3s), then 60s doubling to 1/hour.
* Entries expire at 100% max-age (1800 assumed if absent); byebye lingers 30s.
* `ssdp:update` keeps timers and records NEXTBOOTID; CONFIGID or LOCATION
  change triggers a description refetch.
* Multicast loop stays on (local devices must see our searches); our own
  M-SEARCH is recognized by search port + local address.

## Workflow

* Commit messages follow Conventional Commits.
* `cargo fmt` before commit; clippy with `-D warnings` must pass.
* No new deps without need.
