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
uex --search-port 0           # search from an ephemeral port instead of 1900
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
  IPv6 link-local `LOCATION`s (`http://[fe80::…]/`) are fetched through
  the interface the advert arrived on, because a URL cannot carry the zone.
  When a fetch fails, the view shows what the server sent: status,
  `Content-Type`, size, and the first lines of the body. XML errors
  quote the text at the failing position.
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
| `m` | metrics overlay (`j`/`k` scroll, `h`/`l` pan, `m`/`Esc` close) |
| `Ctrl+Z` | suspend |
| `q`, `Esc`, `Ctrl+C` | quit |

## Searching

On startup uex sends `M-SEARCH` three times (at roughly 0, 1, and 3 s)
because SSDP runs over unreliable UDP. It then searches again after 60 s,
doubling the interval each time up to one hour. Devices re-announce on
their own before `max-age` runs out. A cache entry expires at 100% of
`max-age`. After `ssdp:byebye`, it stays visible (greyed out) for 30 s.

## Firewalls

Search replies come back as unicast to the port the search was sent
from. Stateful firewalls (ufw, firewalld) cannot match those replies to
a multicast request. By default uex therefore sends `M-SEARCH` from port
1900 itself, so one firewall rule covers both announcements and replies:

```sh
sudo ufw allow proto udp from 192.168.0.0/16 to any port 1900
```

If port 1900 cannot be opened, uex falls back to an ephemeral search
port and shows a hint when searches get no replies.

To see IPv6 SSDP traffic under ufw, also allow port 1900 from
`fe80::/10` and allow `ff02::c` in `/etc/ufw/before6.rules`. The stock
rules only allow the IPv4 group.

## Metrics

`m` opens a scrollable overlay modeled on mex's. It has these sections:

* **Session**: uptime, packets per IP family, packet rates, bytes, last packet.
* **Traffic**: NOTIFY broken down by NTS, search replies, M-SEARCH seen
  (foreign vs. our own looped back), and which socket received what.
* **Discovery**: devices (current, ever, expired, byebye), the tree shape,
  adverts by origin, the `max-age` distribution, the next expiry,
  advertised types, and the most common `SERVER` strings.
* **Descriptions**: fetch states, link-local fetches, timing and size,
  UPnP spec versions, and the number of services described.
* **Searching**: mode, ST/MX/port, rounds sent, the next search, and
  replies per round.
* **Control points**: other hosts sending M-SEARCH with their
  `USER-AGENT` (hosts on this machine are tagged), plus their search targets.
* **Links**: joined interfaces, packets received per interface, top talkers.
* **Issues**: every current finding, worst first, grouped by device or
  control point.

## Checks

Each finding has a severity: error (breaks interoperability), warning
(deviates from a SHOULD), or info (notable but legitimate). Errors and
warnings mark rows with a colored `!`.

Advertisements are checked against UDA 2.0 §1. Checks cover required
headers per message type, `CACHE-CONTROL: max-age` (missing or below
1800), USN shape (`uuid:` prefix, `::NT` suffix), `LOCATION` scheme and
host (compared with the sender), `SERVER` lacking a `UPnP/x.y` token,
`BOOTID` changes without `ssdp:update`, a byebye for an unknown advert,
failed description fetches, and a UUID missing from its own description.
Observed searches are checked for `MAN`, `MX`, and `ST`.

## License

MIT
