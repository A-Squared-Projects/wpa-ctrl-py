# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Tooling is uv; `.python-version` pins 3.14 for development (uv fetches it if missing).

```sh
uv sync                                          # set up the environment
uv run python -m unittest discover -s tests      # run all tests
uv run python -m unittest tests.test_security    # run one module
uv run python -m unittest tests.test_wpa_ctrl.TestWpaCtrl.test_ping   # run one test
uv run ruff check                                # lint (E, F, I, B; line length 100)
```

## Hard constraints

- **The package must run on Python 3.7** even though development pins 3.14 (`requires-python = ">=3.7"` — see the comment in pyproject.toml). No walrus operator, no `X | Y` unions, no `list[str]` generics; use `typing.Optional`, `Dict`, `List`, etc. Tests may use anything the dev interpreter has.
- **Zero dependencies, stdlib only.** `tests/test_imports.py` enforces an explicit whitelist of stdlib imports (`EXPECTED_STDLIB_IMPORTS`) via AST scanning, because OpenEmbedded derives packaging RDEPENDS from it. Adding any import to `wpa_ctrl/` means updating that set deliberately.
- **No hostap code may be copied in.** This is an independent implementation; only event names (from `src/common/wpa_ctrl.h`) and some test fixtures (from `doc/ctrl_iface.doxygen`) derive from hostap, acknowledged in NOTICE. Keep it that way.
- Comments are Doxygen-style (`## @package`, `##` block comments, `# @param`, `# @return`), not docstrings. Match this style; explain *why*, as the existing comments do.

## Architecture

Pure-Python client for the wpa_supplicant/hostapd control interface — a UNIX **datagram** socket carrying one command or event per datagram. One protocol serves both daemons; only the socket directory differs (`DEFAULT_CTRL_DIR` vs `HOSTAPD_CTRL_DIR`).

Layers, bottom up:

- `wpa_ctrl/transport.py` — socket mechanics only, no knowledge of commands. The client binds its own socket (abstract namespace where available, else a file under `client_dir`) and connects to the daemon's. Kept separate so an asyncio transport could later drive the same command surface.
- `wpa_ctrl/events.py` — unsolicited event messages (`<3>CTRL-EVENT-...`): priority-prefix parsing and the full list of event-name constants, **generated from hostap's `wpa_ctrl.h`** (version noted in the file header — regenerate rather than hand-edit when upstream moves; `parse_event()` copes with unknown names).
- `wpa_ctrl/client.py` — the bulk of the package: `WpaCtrl` with a typed method per documented command (including all 29 DPP commands), reply parsing into NamedTuples (`Network`, `ScanResult`, `Security`, ...), and the DPP configurator-params helpers. Anything undocumented goes through `request()` verbatim. Commands answering `OK`/`FAIL` raise `WpaCtrlCommandFailed`; `try_command()` returns a bool where refusal is expected.
- `wpa_ctrl/discovery.py` — finding interfaces: stats sockets in the control directory, cross-checks against sysfs where sysfs exists (skipping, not failing, where it doesn't — "cannot tell" ≠ "none").
- `wpa_ctrl/compat.py` — `execute_command()`, a wpa_cli-subprocess-shaped shim returning `(success, output)` for migrating callers; keeps one shared connection per interface.

A connection receives events only after `attach()`; the recommended pattern is one connection for commands and a second, attached, for events. `request()` on a single connection sets aside events that arrive mid-command for `next_event()`.

## Tests

Tests drive a `FakeSupplicant` (`tests/fake_supplicant.py`) over a **real** UNIX datagram socket, not mocks — the framing is the part most likely to be wrong, and a mock would only assert the implementation's assumptions back at it. It answers from a command→reply table and can push unsolicited events. Follow this pattern for new protocol-level tests.

Design intent throughout (see README): the library never retries, never decides policy (e.g. what to do when the daemon is unreachable), and values passed to the daemon are used verbatim — case and encoding of credentials are meaningful.
