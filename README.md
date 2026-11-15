# uex

Terminal UI to browse and debug SSDP/UPnP on the local network: live
devices, advertisements, device descriptions, and raw packets. It is a
sibling of [mex](https://github.com/hrzlgnm/mex), which does the same for mDNS.

Built with Rust ([ratatui](https://ratatui.rs/),
[crossterm](https://github.com/crossterm-rs/crossterm),
[ureq](https://github.com/algesten/ureq),
[roxmltree](https://github.com/RazrFalcon/roxmltree)). It listens on UDP
port 1900 (`239.255.255.250`, `[FF02::C]`, `[FF05::C]`), sends
`M-SEARCH` from its own socket, and fetches each advertised `LOCATION`
over plain HTTP to show the device description.

## Usage

```sh
cargo run --release
uex --passive                 # listen only, never send M-SEARCH
uex -i eth0,br0               # restrict to these interfaces
uex -t upnp:rootdevice --mx 3 # custom search target and MX
uex --search-port 1901        # fixed reply port (see Firewalls)
```

Without a TTY (piped or under a service manager), uex runs headless and
prints one line per discovery event to stdout:
`+` new device, `=` description fetched, `-` byebye, `x` expired.

## Layout

* **Devices** (left): one row per UUID. Embedded devices sit under their
  root once its description is fetched. `!` marks protocol issues.
  `(control points)` lists the `M-SEARCH` requests seen from other hosts
  and from uex itself.
* **Adverts**: every USN the device announces (NT/ST), how it was learned
  (`NOTIFY`, a `200` search reply, or `byebye`), the time left of its
  `max-age`, the source address with its ingress interface, and any issues found.
* **Description**: the parsed device description: identity, icons,
  services with resolved SCPD/control/event URLs, embedded devices.
* **Packets**: raw packets for the selection, newest first.

## Keys

| Key | Action |
| --- | --- |
| `↑`/`↓`, `j`/`k`, `g`/`G` | select device |
| `Tab`, `←`/`→`, `1`–`3` | switch view |
| `PgUp`/`PgDn`, `J`/`K` | scroll / move packet cursor |
| `r` | rescan (restart the search burst) |
| `f` | refetch the selected device's description |
| `c` | clear packet log |
| `Ctrl+Z` | suspend |
| `q`, `Esc`, `Ctrl+C` | quit |

## Searching

On startup uex sends `M-SEARCH` three times (at roughly 0, 1, and 3 s)
because SSDP runs over unreliable UDP. It then searches again after 60 s,
doubling the interval each time up to one hour. Devices re-announce on
their own before `max-age` runs out. A cache entry expires at 100% of
`max-age`. After `ssdp:byebye`, it stays visible (greyed out) for 30 s.

## Firewalls

Search replies come back as unicast to the port the search was sent from.
Stateful firewalls (ufw, firewalld) cannot match those replies to a
multicast request, so they drop them. uex shows a hint when searches get
no replies. Pin the reply port and allow it, for example:

```sh
sudo ufw allow proto udp from 192.168.0.0/16 to any port 1901
uex --search-port 1901
```

To see IPv6 SSDP traffic under ufw, also allow `ff02::c` port 1900 in
`/etc/ufw/before6.rules`. The stock rules only allow the IPv4 group.

## Checks

Advertisements are checked against UDA 2.0 §1. Checks cover required
headers per message type, `CACHE-CONTROL: max-age` (missing or below
1800), USN shape (`uuid:` prefix, `::NT` suffix), `LOCATION` scheme and
host (compared with the sender), `SERVER` lacking a `UPnP/x.y` token,
`BOOTID` changes without `ssdp:update`, a byebye for an unknown advert,
failed description fetches, and a UUID missing from its own description.
Observed searches are checked for `MAN`, `MX`, and `ST`.

## License

MIT
