# Pwnariadne v0.1.0

Trigger-guided review and observe-only multi-tool debugging companion for Linux
binaries. Built for CTF practice and authorised security testing. It points at
suspicious spots and helps you observe them at runtime; it does not generate
exploits or payloads.

## Highlights

- **Review**: memory-unsafe sink catalogue over the ELF PLT (`.plt` and CET
  `.plt.sec`) and C source. Source uses a **tree-sitter** backend (accurate:
  knows the enclosing function, skips constant `printf` formats) with a regex
  fallback.
- **Classify**: bug class, severity, and **intraprocedural taint notes**
  (tainted / local / constant) on each sink argument.
- **Techniques**: advisory study map (saved-ret overwrite, canary leak,
  ret2shellcode, ROP/ret2libc, ret2win, ret2system, format-string read,
  GOT overwrite, heap UAF/double-free), gated by the observed mitigations.
- **Debugger**: observe-only scripts flavored for **pwndbg / GEF / gdb**, with
  bug-class aware dumps (canary, got, heap/bins/vis_heap_chunks). Unknown
  commands are skipped gracefully.
- **Orchestration**: drives ROPgadget / ropper, one_gadget, pwntools checksec,
  and angr static reachability when present, with a clear note when absent.
- **Indirect dispatch detection** and **arch-aware disassembly**
  (x86/x64 full, ARM/AArch64/MIPS indirect).
- **Reports**: terminal, endpoints, markdown, json.
- **54 tests** (1 skipped without angr).

## Install

```bash
pip install -e .                   # core
pip install -e ".[source]"         # tree-sitter accurate C review
pip install -e ".[integrations]"   # ROPgadget + pwntools
pip install -e ".[reachability]"   # angr (heavy)
```

## Quick start

```bash
pwnariadne ./target --gadgets --indirect --gdb breakpoints.gdb
gdb -q -x breakpoints.gdb ./target
```

Author: HaiND, Post and Telecommunication Institute of Technology
