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
class OneGadgetResult:
    """libc one shot gadget offsets discovered by one_gadget."""

    libc: str | None
    offsets: list[int] = field(default_factory=list)
    note: str = ""


def find_one_gadgets(libc_path: str, timeout: int = 60) -> OneGadgetResult:
    """Return libc one shot gadget offsets, or a note if unavailable."""

    if not shutil.which("one_gadget"):
        return OneGadgetResult(
            libc=libc_path,
            note="one_gadget not installed (gem install one_gadget)",
        )
    try:
        proc = subprocess.run(
            ["one_gadget", "--raw", libc_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return OneGadgetResult(libc=libc_path, note=f"one_gadget failed: {exc}")

    offsets: list[int] = []
    for token in proc.stdout.split():
        try:
            offsets.append(int(token, 0) if token.startswith("0x") else int(token))
        except ValueError:
            continue
    note = "" if offsets else "one_gadget returned no offsets"
    return OneGadgetResult(libc=libc_path, offsets=offsets, note=note)


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
