# Changelog

All notable changes to Pwnariadne are documented here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.1.0]

First public version.

### Added

- Review: memory-unsafe sink catalogue over the ELF PLT (`.plt` and CET
  `.plt.sec`) and C source. Source review uses a tree-sitter backend (accurate:
  resolves the enclosing function, skips constant `printf` formats) with a
  regex fallback.
- Classify: bug class, severity, and intraprocedural taint notes
  (tainted / local / constant) on each sink argument.
- Techniques: advisory study map gated by the observed mitigations
  (saved-return overwrite, canary leak, ret2shellcode, ROP/ret2libc, ret2win,
  ret2system, format-string read, GOT overwrite, heap UAF/double-free).
- Debugger: observe-only scripts flavored for pwndbg, GEF and gdb, with
  bug-class aware dumps (canary, got, heap, bins, vis_heap_chunks). Unknown
  commands are skipped gracefully.
- Orchestration: drives ROPgadget / ropper, one_gadget, pwntools checksec and
  angr static reachability when present, with a clear note when absent.
- Indirect dispatch detection and arch-aware disassembly (x86/x64 full,
  ARM/AArch64/MIPS indirect).
- Reports: terminal, endpoints, markdown and json. 54 tests.

### Notes

- Defensive and educational use only. Pwnariadne points at suspicious spots and
  helps observe them at runtime; it does not generate exploits or payloads.

[0.1.0]: https://github.com/Haind03/Pwnariadne/releases/tag/v0.1.0
