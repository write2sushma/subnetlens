# SubnetLens — Python Port Plan

This document is the authoritative planning reference for porting **SubnetLens** from Go to Python.  
Branch: `python-port-plan` | Date: 2026-03-31

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Go → Python Concept Mapping](#2-go--python-concept-mapping)
3. [Python Package Structure](#3-python-package-structure)
4. [Dependency Choices](#4-dependency-choices)
5. [Data Model Translation](#5-data-model-translation)
6. [Scanner Module Breakdown](#6-scanner-module-breakdown)
7. [CLI Translation](#7-cli-translation)
8. [TUI Translation](#8-tui-translation)
9. [Phased Implementation Plan](#9-phased-implementation-plan)
10. [Local Development & Testing Guide](#10-local-development--testing-guide)
11. [Platform Notes](#11-platform-notes)
12. [Known Challenges & Mitigations](#12-known-challenges--mitigations)

---

## 1. Motivation

| Reason | Detail |
|---|---|
| Ecosystem reach | Python has first-class libraries for networking (`scapy`, `icmplib`, `zeroconf`) with no CGO requirement |
| Contributor friendliness | Lower barrier to entry compared to compiled Go |
| Extensibility | Rich TUI ecosystem (`textual`, `rich`) and easy async I/O with `asyncio` |
| Roadmap items | JSON/CSV export, GUI graph, and `watch` mode are easier to prototype in Python |

The Go implementation remains the production baseline. The Python port is a parallel effort targeting feature parity.

---

## 2. Go → Python Concept Mapping

| Go construct | Python equivalent | Notes |
|---|---|---|
| `goroutine` | `asyncio` coroutine **or** `ThreadPoolExecutor` thread | Use `asyncio` for I/O-bound probes; `ThreadPoolExecutor` for raw-socket calls that block |
| `sync.WaitGroup` | `asyncio.gather()` / `concurrent.futures.as_completed()` | — |
| `chan T` (channel) | `asyncio.Queue` | Bounded queues replicate Go channel back-pressure |
| `sync.Mutex` / `sync.Map` | `threading.Lock` + `dict` | Used when mixing threads with shared state |
| `context.Context` (cancellation) | `asyncio.Event` + structured task cancellation | `asyncio.timeout()` (Python 3.11+) for per-probe deadlines |
| `struct` + methods | `@dataclass` | `__slots__` for memory efficiency on large host lists |
| `interface{}` | `typing.Protocol` | Structural subtyping |
| `cobra.Command` | `click.group` / `click.command` | Flag parity is 1:1 |
| Bubble Tea (TUI) | `textual` App | Reactive widget model similar to BubbleTea's Elm architecture |
| `gopacket` (ARP raw frames) | `scapy` | `scapy.layers.l2.ARP` + `scapy.sendrecv.srp` |
| `golang.org/x/net/icmp` | `icmplib` | Handles ICMP socket creation and privilege elevation |
| mDNS listener | `zeroconf` (`python-zeroconf`) | Passive service browser |
| OUI CSV lookup | stdlib `csv` + `dict` | Loaded once at import time into an in-memory dict |
| Build tags (`_linux`, `_darwin`, `_windows`) | `sys.platform` guards + conditional imports | `platform.system()` for runtime dispatch |
| `go build -o subnetlens` | `pyinstaller --onefile` or `pipx install` | Single-file distributable via PyInstaller |
| `go.mod` | `pyproject.toml` (PEP 517/518) | `[project.optional-dependencies]` for dev extras |

---

## 3. Python Package Structure

```
subnetlens/                        # repo root
├── pyproject.toml                 # replaces go.mod + goreleaser
├── README_PYTHON.md               # Python-specific quickstart
├── src/
│   └── subnetlens/
│       ├── __init__.py
│       ├── __main__.py            # python -m subnetlens entry-point
│       ├── cli.py                 # click CLI  ← cmd/root.go
│       ├── models.py              # dataclasses ← models/models.go
│       ├── engine.py              # scan orchestrator ← scanner/engine.go
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── discovery.py       # ← scanner/discovery.go
│       │   ├── tcp_probe.py       # ← scanner/tcp_probe.go
│       │   ├── portscan.py        # ← scanner/portscan.go
│       │   ├── icmp.py            # ← scanner/icmp.go
│       │   ├── arp.py             # ← scanner/arp.go + arp_sweep*.go
│       │   ├── mdns.py            # ← scanner/mdns*.go
│       │   ├── osdetect.py        # ← scanner/osdetect.go
│       │   ├── oui.py             # ← scanner/helpers.go (OUI CSV loader)
│       │   └── resolver.py        # ← scanner/resolver.go
│       └── ui/
│           ├── __init__.py
│           └── tui.py             # textual TUI ← ui/tui/tui.go
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_tcp_probe.py
│   ├── test_portscan.py
│   ├── test_icmp.py
│   ├── test_arp.py
│   ├── test_mdns.py
│   ├── test_osdetect.py
│   ├── test_oui.py
│   ├── test_resolver.py
│   ├── test_engine.py
│   └── test_cli.py
└── docs/
    └── python-port-plan.md        # this file
```

---

## 4. Dependency Choices

### Runtime dependencies

| Library | Version | Replaces | Purpose |
|---|---|---|---|
| `click` | `>=8.1` | `github.com/spf13/cobra` | CLI argument parsing, sub-commands, flags |
| `textual` | `>=0.60` | `github.com/charmbracelet/bubbletea` | Full-featured terminal UI framework |
| `rich` | `>=13` | (used by textual internally) | Rich text / tables in plain-text mode |
| `scapy` | `>=2.5` | `github.com/google/gopacket` | ARP sweep, raw packet construction & capture |
| `icmplib` | `>=3.0` | `golang.org/x/net/icmp` | ICMP echo probes with privilege handling |
| `zeroconf` | `>=0.131` | internal mDNS listener | mDNS passive service discovery |
| `dnspython` | `>=2.6` | stdlib `net.LookupAddr` | Async reverse DNS resolution |

### Development / test dependencies

| Library | Purpose |
|---|---|
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support |
| `pytest-mock` | `mocker` fixture for patching |
| `ruff` | Linter + formatter |
| `mypy` | Static type checking |
| `pyinstaller` | Single-binary packaging (optional) |

---

## 5. Data Model Translation

### Go → Python (`models/models.go` → `src/subnetlens/models.py`)

```python
# src/subnetlens/models.py
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


@dataclass
class Port:
    number:   int
    protocol: str       = "tcp"
    state:    PortState = PortState.OPEN
    service:  str       = ""
    banner:   str       = ""


@dataclass
class Host:
    ip:         str
    hostname:   str             = ""
    mac:        str             = ""
    vendor:     str             = ""
    latency_ms: float           = 0.0
    open_ports: list[Port]      = field(default_factory=list)
    os:         str             = ""
    device:     str             = ""
    seen_at:    datetime | None = None
    updated_at: datetime | None = None
    source:     str             = ""   # "arp"|"mdns"|"icmp"|"tcp"|"mixed"
    _alive:     bool            = field(default=False, repr=False)

    def mark_seen(self, source: str) -> None:
        now = datetime.now()
        if self.seen_at is None:
            self.seen_at = now
        self.updated_at = now
        if not self.source:
            self.source = source
        elif self.source != source and self.source != "mixed":
            self.source = "mixed"

    @property
    def is_alive(self) -> bool:
        return self._alive

    def set_alive(self, v: bool) -> None:
        self._alive = v


@dataclass
class ScanResult:
    subnet:      str
    started_at:  datetime
    finished_at: datetime | None = None
    hosts:       list[Host]      = field(default_factory=list)

    def duration(self) -> timedelta:
        if self.finished_at is None:
            return timedelta(0)
        return self.finished_at - self.started_at

    def alive_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.is_alive]


@dataclass
class ScanOptions:
    subnet:       str
    ports:        list[int] = field(default_factory=list)
    timeout_ms:   int       = 500
    concurrency:  int       = 100
    grab_banners: bool      = False
    all_alive:    bool      = False


COMMON_PORTS: list[int] = [
    # Standard services
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 587, 993, 995,
    # Databases
    3306, 5432, 6379, 9200,
    # Remote access / desktop
    3389, 5900,
    # HTTP alternates
    8080, 8443, 8888,
    # Apple / iOS / macOS
    548, 5000, 7000, 62078,
    # Android / Samsung
    5555, 7676, 8200, 49152,
]
```

---

## 6. Scanner Module Breakdown

### 6.1 `tcp_probe.py` ← `scanner/tcp_probe.go`

- Use `asyncio.open_connection()` with `asyncio.wait_for()` for per-host TCP connect probe.
- Return `(is_alive: bool, latency_ms: float)`.

### 6.2 `portscan.py` ← `scanner/portscan.go`

- Use `asyncio.Semaphore(concurrency)` to cap parallel connections (replaces Go semaphore channel).
- Banner grabbing: `reader.read(1024)` after connection with timeout.
- Service name lookup: `socket.getservbyport(port)` with a fallback dict.

### 6.3 `icmp.py` ← `scanner/icmp.go`

- Use `icmplib.async_ping()` for non-blocking ICMP echo.
- Requires root/admin — checked at runtime; falls back silently if unprivileged.

### 6.4 `arp.py` ← `scanner/arp.go` + `arp_sweep*.go`

- **Linux/macOS**: `scapy.sendrecv.srp(ARP(pdst=subnet), timeout=2, iface=iface, verbose=False)`
- **Windows**: same Scapy path but requires Npcap; detected at import.
- Platform dispatch via `sys.platform` (replaces Go build tags).
- Returns `dict[str, str]` mapping IP → MAC.

### 6.5 `mdns.py` ← `scanner/mdns*.go`

- Use `zeroconf.ServiceBrowser` with a custom listener to collect `(name, ip, hostname)` tuples.
- Run browser in a background thread with `threading.Thread(daemon=True)`.
- Results funnelled into an `asyncio.Queue` via `loop.call_soon_threadsafe()`.
- Cache: a simple `threading.Lock`-protected `dict`.

### 6.6 `osdetect.py` ← `scanner/osdetect.go`

- Pure Python heuristic: inspect open ports, banners, TTL, MAC OUI prefix.
- Returns `(os_name: str, device_type: str)`.
- No external library needed — direct translation of the Go heuristic rules.

### 6.7 `oui.py` ← `scanner/helpers.go` (OUI loading)

- Load `scanner/oui.csv` once at module import using `csv.DictReader`.
- Store as `dict[str, str]` keyed on 6-char uppercase hex OUI prefix (e.g. `"AABBCC"`).
- Expose `lookup_vendor(mac: str) -> str`.

### 6.8 `resolver.py` ← `scanner/resolver.go`

- Use `dnspython` (`dns.asyncresolver.Resolver`) for async reverse DNS.
- Fallback: `socket.gethostbyaddr()` in a thread pool if `dnspython` unavailable.

### 6.9 `discovery.py` ← `scanner/discovery.go`

- Orchestrates all discovery methods concurrently using `asyncio.gather()`.
- Generates IP list from subnet using `ipaddress.ip_network(subnet, strict=False)`.
- Merges results from TCP probe, ICMP, ARP, mDNS into the shared `hosts` dict.

### 6.10 `engine.py` ← `scanner/engine.go`

```python
# src/subnetlens/engine.py  (sketch)
import asyncio
from collections.abc import Callable
from .models import Host, ScanOptions, ScanResult

class Engine:
    def __init__(
        self,
        opts:        ScanOptions,
        on_progress: Callable[[int, int], None] | None = None,
        on_host:     Callable[[Host], None]      | None = None,
    ): ...

    def run(self) -> ScanResult:
        """Synchronous entry-point; runs the asyncio event loop internally."""
        return asyncio.run(self._run_async())

    async def _run_async(self) -> ScanResult: ...
```

---

## 7. CLI Translation

### Cobra → Click flag parity

| Go flag | Click option | Default |
|---|---|---|
| `--ports / -p` | `--ports / -p` (comma-sep string → list[int]) | `COMMON_PORTS` |
| `--timeout / -t` | `--timeout / -t` (int, ms) | `500` |
| `--concurrency / -c` | `--concurrency / -c` (int) | `100` |
| `--banners / -b` | `--banners / -b` (flag) | `False` |
| `--plain` | `--plain` (flag) | `False` |
| `--all-alive` | `--all-alive` (flag) | `False` |

```python
# src/subnetlens/cli.py  (sketch)
import click
from .models import ScanOptions, COMMON_PORTS
from .engine import Engine
from .ui.tui import run_tui

@click.group()
def cli(): ...

@cli.command("scan")
@click.argument("subnet")
@click.option("-p", "--ports",       default="",  help="Comma-separated ports")
@click.option("-t", "--timeout",     default=500, type=int)
@click.option("-c", "--concurrency", default=100, type=int)
@click.option("-b", "--banners",     is_flag=True)
@click.option("--plain",             is_flag=True)
@click.option("--all-alive",         is_flag=True)
def scan(subnet, ports, timeout, concurrency, banners, plain, all_alive):
    port_list = [int(p) for p in ports.split(",") if p] or COMMON_PORTS
    opts = ScanOptions(subnet, port_list, timeout, concurrency, banners, all_alive)
    if plain:
        _run_plain(opts)
    else:
        run_tui(opts)
```

---

## 8. TUI Translation

### Bubble Tea (Go) → Textual (Python)

| Bubble Tea concept | Textual equivalent |
|---|---|
| `tea.Model` | `textual.app.App` subclass |
| `tea.Cmd` (side-effects) | `App.call_from_thread()` or `worker` |
| `tea.Msg` (messages) | `textual.message.Message` subclass |
| `lipgloss` (styling) | `textual` CSS + `rich` markup |
| `table` widget | `textual.widgets.DataTable` |
| progress / spinner | `textual.widgets.ProgressBar` + `LoadingIndicator` |

The TUI will stream host rows into a `DataTable` as `on_host` callbacks fire, replicating
the real-time streaming behaviour of the Go TUI.

---

## 9. Phased Implementation Plan

| Phase | Scope | Est. effort |
|---|---|---|
| **1** | `models.py` — all dataclasses, enums, `COMMON_PORTS` | 0.5 day |
| **2** | `pyproject.toml`, `__main__.py`, stub `cli.py` | 0.5 day |
| **3** | `tcp_probe.py` — async TCP connect + latency | 1 day |
| **4** | `discovery.py` — IP enumeration + TCP discovery loop | 1 day |
| **5** | `icmp.py` — ICMP probe with privilege fallback | 1 day |
| **6** | `arp.py` — ARP sweep Linux/macOS + Windows Npcap path | 1.5 days |
| **7** | `mdns.py` — zeroconf browser, asyncio queue bridge | 1 day |
| **8** | `portscan.py` — port scan + banner grabbing | 1 day |
| **9** | `oui.py` + `resolver.py` | 0.5 day |
| **10** | `osdetect.py` — heuristic OS/device fingerprinting | 1 day |
| **11** | `engine.py` — orchestrate all scanners | 1 day |
| **12** | `cli.py` — full Click CLI wired to engine | 0.5 day |
| **13** | `ui/tui.py` — Textual streaming TUI | 2 days |
| **14** | `tests/` — full pytest coverage | 2 days |
| **15** | Packaging (`pyproject.toml` entry-points, PyInstaller) | 0.5 day |
| **Total** | | **~15.5 days** |

---

## 10. Local Development & Testing Guide

### Prerequisites

- Python **3.11+** (required for `asyncio.timeout()`)
- `git`
- On Linux/macOS: `sudo` access for ICMP/ARP tests against a real network
- On Windows: [Npcap](https://npcap.com) for ARP

---

### Step 1 — Clone and switch to the port branch

```bash
git clone https://github.com/write2sushma/subnetlens.git
cd subnetlens
git checkout python-port-plan
```

---

### Step 2 — Create a virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows PowerShell

pip install -e ".[dev]"
```

The `pyproject.toml` (created in Phase 2) will declare:

```toml
[project]
name = "subnetlens"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "textual>=0.60",
    "rich>=13",
    "scapy>=2.5",
    "icmplib>=3.0",
    "zeroconf>=0.131",
    "dnspython>=2.6",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-asyncio",
    "pytest-mock",
    "ruff",
    "mypy",
]

[project.scripts]
subnetlens = "subnetlens.cli:cli"

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"
```

---

### Step 3 — Run the unit tests (no root required — all network calls are mocked)

```bash
pytest                                              # all tests
pytest -v                                           # verbose
pytest tests/test_tcp_probe.py -v                  # single module
pytest --cov=subnetlens --cov-report=term-missing  # with coverage
```

All tests mock actual network I/O using `pytest-mock`, so they run safely without
root or a live network. Example pattern:

```python
# tests/test_tcp_probe.py
import pytest
from unittest.mock import AsyncMock
from subnetlens.scanner.tcp_probe import tcp_probe

@pytest.mark.asyncio
async def test_tcp_probe_alive(mocker):
    mocker.patch(
        "asyncio.open_connection",
        return_value=(AsyncMock(), AsyncMock()),
    )
    alive, latency = await tcp_probe("192.168.1.1", timeout_ms=500)
    assert alive is True
    assert latency >= 0

@pytest.mark.asyncio
async def test_tcp_probe_dead(mocker):
    mocker.patch("asyncio.open_connection", side_effect=OSError)
    alive, latency = await tcp_probe("192.168.1.99", timeout_ms=500)
    assert alive is False
```

---

### Step 4 — Run the CLI in plain-text mode

```bash
# TCP-only (no root needed)
python -m subnetlens scan 192.168.1.0/24 --plain

# Custom ports + banner grabbing
python -m subnetlens scan 192.168.1.1 --ports 22,80,443 --plain --banners

# With ARP + ICMP (requires root/admin)
sudo python -m subnetlens scan 192.168.1.0/24 --plain
```

---

### Step 5 — Run the TUI

```bash
python -m subnetlens scan 192.168.1.0/24
# or after pip install -e .:
subnetlens scan 192.168.1.0/24
```

---

### Step 6 — Debug mode

```bash
SLENS_DEBUG=1 python -m subnetlens scan 192.168.1.0/24 --plain
SLENS_DEBUG=1 python -m subnetlens scan 192.168.1.0/24 --plain 2>debug.log
cat debug.log
```

`SLENS_DEBUG=1` enables `logging.DEBUG` on the `subnetlens` logger, matching the Go behaviour.

---

### Step 7 — Interactive REPL testing

```python
import asyncio
from subnetlens.scanner.tcp_probe import tcp_probe
from subnetlens.scanner.oui import lookup_vendor

alive, ms = asyncio.run(tcp_probe("192.168.1.1", timeout_ms=1000))
print(f"alive={alive}, latency={ms:.1f}ms")

print(lookup_vendor("AA:BB:CC:11:22:33"))
```

---

### Step 8 — Lint and type-check

```bash
ruff check src/ tests/ --fix
ruff format src/ tests/
mypy src/subnetlens --strict
```

---

### Step 9 — Build a standalone binary (optional, Phase 15)

```bash
pip install pyinstaller
pyinstaller --onefile --name subnetlens src/subnetlens/__main__.py
sudo mv dist/subnetlens /usr/local/bin/
```

---

## 11. Platform Notes

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| TCP scan | ✔ (no root) | ✔ (no root) | ✔ (no admin) |
| ICMP | ✔ (root) | ✔ (root) | ✔ (admin) |
| ARP sweep | ✔ (root + scapy) | ✔ (root + scapy) | ✔ (Npcap + scapy) |
| mDNS | ✔ | ✔ | ✔ (untested) |

**Windows:** Install [Npcap](https://npcap.com) before running ARP scans.

---

## 12. Known Challenges & Mitigations

| Challenge | Mitigation |
|---|---|
| Go goroutines are lighter than Python threads | Use `asyncio` for all I/O-bound probes; threads only for blocking raw-socket calls |
| `scapy` requires root on Linux/macOS | Detect privileges at startup; degrade gracefully to TCP-only if not root |
| Python GIL limits CPU parallelism | OS fingerprinting is lightweight; keep it on the async event loop |
| `asyncio.timeout()` requires Python 3.11+ | Enforce `requires-python = ">=3.11"` in `pyproject.toml` |
| Textual reactive model differs from BubbleTea Elm loop | Use `App.call_from_thread()` to post events from engine thread into Textual |
| Windows raw-socket restrictions | Document Npcap requirement; provide no-ARP fallback |
| OUI CSV is 3.5 MB | Load lazily on first `lookup_vendor()` call; cache in module-level dict |

---

*Plan*
