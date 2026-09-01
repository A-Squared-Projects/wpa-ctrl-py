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

### From an event loop

`fileno()` gives the control socket's descriptor, so a caller with its own
loop can wait on events without a thread and without a poll interval:

```python
monitor = WpaCtrl("wlan0").open()
monitor.attach()

def on_readable():
    while monitor.pending():          # one wakeup can mean several events
        event = monitor.next_event()
        if event is None:
            break
        handle(event)

loop.add_reader(monitor.fileno(), on_readable)
```

Drain while `pending()` is true, since a readable socket can hold more than
one datagram. Unregister the descriptor before `close()` — it is closed with
the socket, and a loop still watching it will spin. Use a connection that is
attached and does nothing else, so everything arriving is an event.

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
its other commands — `DEAUTHENTICATE`, `GET_CONFIG`, the `WPS_*` family —
are documented only in `hostapd_cli.c`, and go through `request()`. The
`STA` family is the exception: wpa_supplicant answers it too in AP and
mesh modes, and `sta()` / `iter_stations()` below cover it.

```python
ap.request("ALL_STA")
```

## What an AP offers

The `flags` column of a scan result is a compact spelling of the BSS's
RSN/WPA information elements. `ScanResult.security` parses it, and
`parse_security()` does the same for a flags string on its own:

```python
for result in wpa.scan_results():
    security = result.security
    if security.transition_mode:
        print(f"{result.ssid}: WPA2 and WPA3 together")
    elif security.sae_only:
        print(f"{result.ssid}: WPA3 only")
    elif security.psk:
        print(f"{result.ssid}: WPA2")
    elif security.open:
        print(f"{result.ssid}: open")
```

`psk`, `sae`, `enterprise`, `owe`, `open` and `wep` say what is on offer;
`transition_mode` and `sae_only` distinguish the two ways an AP can present
SAE, which is the distinction that decides how a network has to be
configured. `pmf_required` and `pmf_capable` report the `MFPR`/`MFPC` flags.
`key_mgmt` and `protocols` hold the parsed names for anything the
predicates do not cover, and `flags` keeps every group that was not one of
those, so a name added upstream is visible rather than discarded.

Two vocabularies are in play and they are not the same. A scan result
spells WPA2 Personal `PSK`, while the `key_mgmt` network variable and
`GET_CAPABILITY key_mgmt` spell it `WPA-PSK`. `Security.key_mgmt` reports
the first; `KeyMgmt` holds the second, for configuring a network:

```python
if wpa.supports_key_mgmt(KeyMgmt.SAE):        # i.e. built with CONFIG_SAE
    wpa.set_network(net, "key_mgmt", f"{KeyMgmt.WPA_PSK} {KeyMgmt.SAE}")
    wpa.set_network(net, "ieee80211w", Pmf.OPTIONAL)
```

`Pmf` holds the `ieee80211w` values: `DISABLED`, `OPTIONAL`, `REQUIRED`.
SAE requires management frame protection and WPA2 predates it, so a network
that has to work with both wants `OPTIONAL` rather than either extreme.

## Every BSS in detail

A scan result is one summary line per BSS. The `BSS` command reports one
BSS in full — information elements included — and `iter_bss()` walks the
whole table with it, the same iteration `wpa_cli all_bss` performs:

```python
from wpa_ctrl import BssMask

for info in wpa.iter_bss(mask=BssMask.BSSID | BssMask.LEVEL | BssMask.SSID):
    print(info.bssid, info.signal_level, info.ssid)
```

Each reply is a `Bss`: the variable block as a dict under the daemon's own
names, with typed properties over the fields worth typing — `frequency`
and `signal_level` as `ScanResult` spells them, `security` parsed the same
way, `ie` as bytes. The block is open-ended — the mask decides what is
present, and upstream adds fields freely — which is why it is a dict
underneath rather than a fixed record: a field this package has never
heard of is still in the dict. A property answers `None` where its field
was not reported, because "not asked for" must not read as a value — a
`Bss` fetched without flags is not an open network.

Iterating is the point, not a convenience. A reply is one datagram, so
asking for the whole table at once (`BSS RANGE=ALL`) is answered with as
many BSSes as fit and no sign that the rest exist. The walk goes id by id
— `BSS FIRST`, then `BSS NEXT-<id>` — so each BSS gets a datagram of its
own, and a table that changes underneath the walk cannot slip it the way
an index would.

`iter_bss()` is a generator, because each BSS is a round trip of its own:
a caller that finds what it wanted stops the commands too, and one that
wants the whole table says `list(wpa.iter_bss())`.

`BssMask` selects which fields each reply carries, with the bit values
from `wpa_ctrl.h`; `id` is always included, because the walk is keyed on
it. `bss()` reports a single BSS — addressed by BSSID, scan-result index,
`ID-<id>`, `FIRST`, `LAST`, `NEXT-<id>` or `CURRENT` — and takes the same
mask:

```python
wpa.bss("CURRENT", mask=BssMask.SSID | BssMask.LEVEL)
```

## However many networks

`LIST_NETWORKS` answers in one datagram like `SCAN_RESULTS` does, so a
long list is cut short with no sign the rest exist. The daemon's
`LAST_ID=` continuation exists for exactly that, and `iter_networks()`
walks it — a generator like `iter_bss()`, asking again from the last id
seen until a page brings nothing new:

```python
for network in wpa.iter_networks():
    print(network.id, network.ssid_text, network.current)
```

`list_networks()` remains the single-reply form. A daemon too old for
`LAST_ID=` answers the continuation with `UNKNOWN COMMAND`, and the walk
simply ends with the first page — every network such a daemon was ever
going to show.

## Stations, and P2P peers

The same one-entry-per-datagram walk serves two more tables, and the CLIs
iterate both themselves. `iter_stations()` is `hostapd_cli all_sta` —
`STA-FIRST`, then `STA-NEXT <address>` until the reply is empty — and
works against hostapd or a wpa_supplicant in AP or mesh mode; anything
else answers the first command with `UNKNOWN COMMAND` and the walk simply
yields nothing. `iter_p2p_peers()` is `wpa_cli p2p_peers`: `P2P_PEER
FIRST`, then `P2P_PEER NEXT-<address>` until `FAIL`:

```python
with WpaCtrl("wlan0", ctrl_dir=HOSTAPD_CTRL_DIR) as ap:
    for station in ap.iter_stations():
        print(station.address, station["flags"])
```

Both replies put the MAC alone on the reply's first line — not as a
variable — so `Station` and `P2pPeer` carry it as `.address` beside the
dict of what the daemon sent. `sta()` and `p2p_peer()` are the
single-entry forms, answering `None` where there is no such entry. A
station's `flags` speak hostapd's vocabulary (`[AUTH][ASSOC]...`), not
the BSS one, so `parse_security()` does not apply to them.

## SSIDs are octet strings

802.11 says nothing about what the 0–32 bytes of an SSID mean. A person's
access point almost certainly holds UTF-8; an embedded system can put any
bytes there at all. The daemon prints SSIDs printf-escaped — `Café`
arrives as `Caf\xc3\xa9` — so the `ssid` a `ScanResult`, a `Network`, a
`Bss` or a `status()` reply carries is that escaped ASCII, which matches
against itself and is wrong to show to anyone.

All of them carry the decoded forms alongside it. `ssid_bytes` is an
`Ssid` — a `bytes` subclass, because the octets are the identity: it
compares and hashes as the plain bytes do, so it drops into sets and dict
keys unannounced. `ssid_text` (also spelled `Ssid.text`) reads those
bytes as UTF-8 when they are UTF-8, and answers `None` when they are not,
rather than a replacement-character rendering under which two different
networks could look identical:

```python
result.ssid          # 'Caf\\xc3\\xa9' — the wire's escaped ASCII
result.ssid_bytes    # Ssid(b'Caf\xc3\xa9') — what the air carried
result.ssid_text     # 'Café' — or None for bytes that are not UTF-8
```

`Ssid.from_printf()` parses the escaped spelling anywhere else it turns
up, and `printf_decode()` is the escape reversal on its own. The decoder
speaks the daemon's whole dialect, including what its encoder never emits
but its own decoder accepts, so both ends read the wire the same way.

The configuration side spells the same octets differently: `ssid="..."`
in a config file, a `GET_NETWORK` reply or a `SET_NETWORK` value is a
quoted *literal* — no escape processing at all — with `P"..."` for a
printf-escaped variant and bare hex for anything. Comparing that text
against the wire's escaped text is the classic mistake; both sides meet
as octets instead:

```python
Ssid.from_printf(wpa.status()["ssid"]) == Ssid.from_config('"Café"')
```

`Ssid.from_config()` reads all three config spellings, refusing what the
daemon's parser would refuse, and `config_value()` writes one back by the
daemon's own rule — quoted when every octet is printable ASCII, hex for
everything else, UTF-8 included.

## DPP (Wi-Fi Easy Connect)

Both daemons implement DPP, and all 29 of its commands have methods. The
onboarding flow is the one in `wpa_supplicant/README-DPP` — a Configurator
hands credentials to an Enrollee, having bootstrapped trust from something
out of band, usually a QR code:

```python
# On the Enrollee: publish a bootstrapping key as a QR code, then wait
bootstrap = wpa.dpp_bootstrap_gen(type="qrcode", mac="001122334455",
                                  chan="81/1")
print(wpa.dpp_bootstrap_get_uri(bootstrap))   # DPP:C:81/1;M:...;K:...;;
wpa.dpp_listen(2412)                          # MHz, so 2.4 GHz channel 1

# On the Configurator: read that URI from the QR code and provision
configurator = wpa.dpp_configurator_add()
peer = wpa.dpp_qr_code(uri)
wpa.dpp_auth_init(peer=peer, conf="sta-dpp", ssid=ssid_hex,
                  configurator=configurator)
```

Parameters are passed as keywords and become DPP's `key=value` arguments.
Values are used verbatim, because a key, an SSID hexdump or a passphrase
hexdump means exactly what its bytes say. A trailing underscore is stripped,
so `pass_=` expresses DPP's `pass=`, which Python will not accept as a
keyword:

```python
wpa.dpp_auth_init(peer=peer, conf="sta-psk", ssid=ssid_hex,
                  pass_=passphrase_hex)
```

### Describing the network to hand over

The `conf=`, `ssid=` and `pass=` parameters above are the ones easiest to get
wrong, and the control interface reports none of it: a command with an empty
or unencoded field is accepted, and the exchange is built and torn down later
with no event and no log line. `dpp_configurator_params()` builds them, and
refuses rather than producing a string that will fail silently:

```python
from wpa_ctrl import DppConf, dpp_channel, dpp_configurator_params

params = dpp_configurator_params(DppConf.STA_PSK_SAE, ssid,
                                 passphrase=passphrase,
                                 configurator=configurator)
# conf=sta-psk-sae ssid=6578616d706c65 pass=... configurator=1

wpa.set("dpp_configurator_params", params)   # answering a chirp
wpa.dpp_pkex_add(own=bootstrap, init=1, code=code, **...)
```

`passphrase=` and `psk=` are deliberately different arguments. SAE derives
from the passphrase itself, so a passphrase serves WPA2 and WPA3 while a
derived 64-character key can only ever serve WPA2 — and only the passphrase
is hex-encoded, the key being hex already. Supplying both, neither, or a
passphrase where a key belongs raises rather than provisioning something
that cannot work.

`DppConf` names the `conf=` values. The choice decides which AKMs the
provisioned network offers, and a wrong one is invisible: an Enrollee given
`sta-psk` associates over WPA2 against an access point that would have
offered SAE, and stays there, because a stored network is never rewritten.

`dpp_channel()` converts a frequency to the `81/6` form a bootstrapping URI
carries. A peer announces itself on the channel its own URI names, so a
listener anywhere else hears nothing — a failure indistinguishable from a
peer that never announced.

Progress arrives as events — `DPP-AUTH-SUCCESS`, `DPP-CONF-RECEIVED`,
`DPP-CONF-SENT`, `DPP-FAILED` and the rest of the 43 in `wpa_ctrl.events` —
so an onboarding flow wants an attached connection alongside the one issuing
commands.

The README documents the happy path rather than the lifecycle, so
`dpp_stop_listen()`, the `_remove` and `_set` calls, PKEX, chirping, the TCP
controller and the NFC handover pairs come from the daemons' command tables
instead. A few are one-sided: `dpp_reconfig()`, `dpp_ca_set()` and
`dpp_conf_set()` are wpa_supplicant's, and the relay controller pair is
hostapd's.

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

The verb is upper-cased on the way out, because the control interface is
case sensitive and answers `UNKNOWN COMMAND` to anything else, while
`wpa_cli` let you type it in lower case. Arguments are passed through
untouched — a variable name like `ssid` has to stay lower case, and
changing the case of a value would change the credential.

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

This is an independent implementation and contains no hostap code, but the
event names and BSS mask values are taken from `src/common/wpa_ctrl.h` and
some test fixtures from `doc/ctrl_iface.doxygen`. hostap is BSD-3-Clause, which MIT combines
with freely; its notice is reproduced in [NOTICE](NOTICE) on account of
those two. Neither this package nor its authors are affiliated with or
endorsed by the hostap project.
