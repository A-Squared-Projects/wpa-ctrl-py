# wpa-ctrl

A pure-Python client for the wpa_supplicant / hostapd control interface.

No dependencies, no build step, and no `libwpa_client`: the control
interface is a UNIX datagram socket carrying one command per datagram, so a
client is a socket rather than a subprocess or a C extension.

```python
from wpa_ctrl import WpaCtrl

with WpaCtrl("wlan0") as wpa:
    print(wpa.status()["wpa_state"])
    for network in wpa.list_networks():
        print(network.id, network.ssid, network.current)
```

## Events

wpa_supplicant emits unsolicited events — association, disconnection, scan
completion — to any connection that has attached. Use a second connection
for them, as the protocol documentation recommends, so a command's reply is
never interleaved with an event:

```python
with WpaCtrl("wlan0") as monitor:
    monitor.attach()
    while True:
        event = monitor.next_event(timeout=10)
        if event and event.name == "CTRL-EVENT-DISCONNECTED":
            ...
```

A single connection works too — `request()` sets aside any event that
arrives mid-command and hands it to `next_event()` afterwards — but two is
simpler to reason about.

## Finding the interfaces

`wlan0` is a default, not a promise: udev rules, systemd's predictable names
and plain renames all produce something else, and wpa_supplicant is equally
happy managing several interfaces at once. `find_interfaces()` answers the
question properly:

```python
from wpa_ctrl import WpaCtrl, find_interfaces

for ifname in find_interfaces():
    with WpaCtrl(ifname) as wpa:
        print(ifname, wpa.status().get("wpa_state"))
```

Pass `global_path` where wpa_supplicant was started with `-g`, and its own
account of itself is preferred over reading the directory:

```python
find_interfaces(global_path="/run/wpa_supplicant-global")
```

`control_sockets()` is the same list without the tidying, and stats each
entry rather than trusting the directory listing, so a file left behind by a
crashed daemon is not offered up as an interface:

```python
from wpa_ctrl import control_sockets

control_sockets()   # one socket per interface wpa_supplicant is managing
```

What `find_interfaces()` drops is an interface the kernel has never heard
of — a socket that outlived its interface. That is an existence check and
deliberately not a wireless one: wpa_supplicant also handles wired 802.1X,
so an ethernet interface with a control socket is a real interface this
library can talk to, and filtering on wirelessness would hide it. Pass
`wireless_only=True` if you want them gone anyway.

Where there is no sysfs to consult at all — a container with no `/sys`, or a
host that is not Linux — those checks are skipped rather than applied blind.
"Cannot tell" is not the same answer as "none", and reporting the second
would strand a caller with no interfaces at all.

### Is this interface wireless?

That is the kernel's question rather than this package's, and
`is_wireless()` is a two-line sysfs check offered because it is cheap:

```python
from wpa_ctrl import is_wireless, wireless_interfaces

is_wireless("wlp2s0")   # reads the phy80211 symlink in sysfs
wireless_interfaces()   # every wireless interface, managed or not
```

It reads `phy80211` rather than the `wireless/` directory, which comes from
wireless-extensions compatibility and is missing on a kernel built without
it. For anything richer — interface type, phy, whether it is a P2P
device — use nl80211 through [pyroute2](https://pyroute2.org/) or `iw`.
This package does not try to be that.

## Sockets

`WpaCtrl("wlan0")` resolves to `/var/run/wpa_supplicant/wlan0`. Pass
`ctrl_dir` if the daemon was pointed elsewhere, or `path` to address a
socket directly — that is how to reach the global socket wpa_supplicant is
given with `-g`:

```python
with WpaCtrl(path="/run/wpa_supplicant-global") as glob:
    print(glob.interfaces())
```

The client binds a socket of its own to receive replies, by default under
`/tmp`; set `client_dir` if that is not writable.

## hostapd

The same protocol, and upstream implements it once: `src/common/wpa_ctrl.c`
is what both `wpa_cli` and `hostapd_cli` link, which is where this package
takes its name. Point the client at hostapd's socket directory and
everything here — commands, events, discovery — works unchanged:

```python
from wpa_ctrl import WpaCtrl, HOSTAPD_CTRL_DIR, control_sockets

control_sockets(HOSTAPD_CTRL_DIR)

with WpaCtrl("wlan0", ctrl_dir=HOSTAPD_CTRL_DIR) as ap:
    print(ap.ping())
```

The directory differs because the daemons differ —
`/var/run/wpa_supplicant` against `/var/run/hostapd` — and nothing else
does.

What the typed command surface below covers is wpa_supplicant's documented
commands. hostapd's own `hostapd_ctrl_iface.doxygen` documents exactly one
command, `PING`, so there is nothing else there to implement faithfully;
its other commands — `STA`, `ALL_STA`, `DEAUTHENTICATE`, `GET_CONFIG`, the
`WPS_*` family — are documented only in `hostapd_cli.c`, and go through
`request()`:

```python
ap.request("ALL_STA")
```

## Command surface

Every command in wpa_supplicant's [`ctrl_iface.doxygen`][doc] has a method,
including the P2P ones, and the documented events have constants in
`wpa_ctrl.events`. Two undocumented but widely used commands are included
because the document has not kept pace with the daemon: `SIGNAL_POLL` and
`BSS_EXPIRE_COUNT`.

Anything else — a newer command, a hostapd-only one — goes through
`request()`, which returns the reply verbatim:

```python
wpa.request("WPS_PBC")
```

Commands that answer `OK`/`FAIL` raise `WpaCtrlCommandFailed` when refused.
Where a refusal is an expected outcome rather than an error, `try_command()`
returns a bool instead. Nothing retries: the caller knows whether a repeat
is safe.

[doc]: https://w1.fi/cgit/hostap/tree/doc/ctrl_iface.doxygen

## Migrating from wpa_cli

`wpa_ctrl.compat.execute_command()` takes the same arguments as a typical
`wpa_cli` subprocess wrapper and returns the same `(success, output)` pairs,
so existing parsing can move across before it is rewritten:

```python
from wpa_ctrl.compat import execute_command

success, output = execute_command("status")
```

It differs from a subprocess wrapper in one way worth stating plainly: when
the daemon cannot be reached it returns `(False, None)`. Wrappers that
reacted to a failed `wpa_cli` by killing the process — to make a watchdog
reboot the device, say — need that policy at the call site, because a
library is the wrong place to decide it.

## Development

Tooling is [uv](https://docs.astral.sh/uv/):

```
uv sync
uv run python -m unittest discover -s tests
```

`.python-version` pins 3.14, matching the devices this is used on; uv will
fetch it if it is not already present. The package itself needs nothing
newer than 3.7.

The tests drive a fake supplicant over a real UNIX datagram socket rather
than a mocked one. The framing is the part most likely to be wrong, and a
mock would only assert the implementation's own assumptions back at it.

## Licence

MIT — see [LICENSE](LICENSE).
