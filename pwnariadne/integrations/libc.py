"""libc helpers: one_gadget enumeration and a pwntools backed checksec.

Both are optional and read only. one_gadget lists libc one shot addresses the
same way its CLI does; pwntools checksec cross checks our own mitigation
reading. If the tool or library is absent, the caller gets an empty result with
a note instead of an error.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

_ADDR_RE = re.compile(r"^(0x[0-9a-fA-F]+)\b")


@dataclass
class OneGadget:
    """A single one_gadget candidate: its offset, call, and constraints."""

    offset: int
    call: str  # e.g. execve("/bin/sh", rsp+0x40, environ)
    constraints: list[str] = field(default_factory=list)


@dataclass
class OneGadgetResult:
    """libc one shot gadgets discovered by one_gadget."""

    libc: str | None
    offsets: list[int] = field(default_factory=list)  # kept for compatibility
    gadgets: list[OneGadget] = field(default_factory=list)
    note: str = ""


# A gadget header line: "0x4f2a5 execve("/bin/sh", rsp+0x40, environ)".
_HEADER_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s+(.*execve.*|.*posix_spawn.*|.*)$")


def parse_one_gadget(output: str) -> list[OneGadget]:
    """Parse the default (non-raw) one_gadget output into gadgets + constraints.

    Format per gadget::

        0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
        constraints:
          rsp & 0xf == 0
          rcx == NULL
    """

    gadgets: list[OneGadget] = []
    current: OneGadget | None = None
    in_constraints = False

    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            in_constraints = False
            continue
        header = _HEADER_RE.match(stripped)
        if header and stripped.startswith("0x") and not line.startswith(" "):
            current = OneGadget(offset=int(header.group(1), 16), call=header.group(2).strip())
            gadgets.append(current)
            in_constraints = False
            continue
        if stripped.lower() == "constraints:":
            in_constraints = True
            continue
        if in_constraints and current is not None:
            current.constraints.append(stripped)
    return gadgets


def find_one_gadgets(libc_path: str, timeout: int = 60) -> OneGadgetResult:
    """Return libc one shot gadgets with their constraints, or a note."""

    if not shutil.which("one_gadget"):
        return OneGadgetResult(
            libc=libc_path,
            note="one_gadget not installed (gem install one_gadget)",
        )
    try:
        proc = subprocess.run(
            ["one_gadget", libc_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return OneGadgetResult(libc=libc_path, note=f"one_gadget failed: {exc}")

    gadgets = parse_one_gadget(proc.stdout)
    offsets = [g.offset for g in gadgets]
    note = "" if gadgets else "one_gadget returned no gadgets"
    return OneGadgetResult(
        libc=libc_path, offsets=offsets, gadgets=gadgets, note=note
    )


@dataclass
class ChecksecResult:
    """A second opinion on mitigations, from pwntools when available."""

    available: bool
    data: dict[str, object] = field(default_factory=dict)
    note: str = ""


def pwntools_checksec(path: str) -> ChecksecResult:
    """Cross check mitigations using pwntools ELF, if pwntools is installed."""

    try:
        from pwn import ELF  # type: ignore
    except Exception:  # noqa: BLE001 - pwntools optional and import heavy
        return ChecksecResult(available=False, note="pwntools not installed")

    try:
        elf = ELF(path, checksec=False)
        data = {
            "arch": elf.arch,
            "bits": elf.bits,
            "relro": elf.relro,  # 'Full' | 'Partial' | None
            "canary": bool(elf.canary),
            "nx": bool(elf.nx),
            "pie": bool(elf.pie),
        }
        return ChecksecResult(available=True, data=data)
    except Exception as exc:  # noqa: BLE001 - surface any pwntools parse failure
        return ChecksecResult(available=False, note=f"pwntools checksec failed: {exc}")
