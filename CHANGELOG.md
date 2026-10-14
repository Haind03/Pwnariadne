# Changelog

All notable changes to Pwnariadne are documented here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

### Added

- Overflow offset solver now handles frame-pointer-less functions (the rsp
  frame: it tracks push/sub/add/pop stack growth and `mov reg, rsp` buffers),
  not just rbp frames. frame_kind records which.
- Cyclic (De Bruijn) helpers (`core/cyclic.py`) and `--cyclic` / `--cyclic-find`
  to generate and resolve an offset-verification pattern (pwntools compatible).

- Overflow offset is now canary-aware (`offset_to_canary` at rbp-8) and the
  report notes when the canary must be leaked first.
- seccomp detection (`Binary.uses_seccomp`): when a filter is installed the
  technique map drops ret2system and recommends an ORW (open-read-write) chain.
- Generated GDB script annotates each stack-overflow breakpoint with the
  computed offset to saved RIP and a live `x/2gx $rbp`, and emits a
  `pa_onegadget` command that checks each one-gadget's constraints at the stop.

- Overflow offset solver (`core/offsets.py`): for each stack-writing sink it
  reads the enclosing function's instructions and computes the byte distance
  from the destination buffer to the saved RBP and saved RIP, and shows the
  disassembly it used. x86-64 register-arg layout. Shown in every report format.

- Deeper ROP-chain analysis (`techniques/rop.py`): ret2libc chain, ret2system,
  ret2csu, stack pivot, syscall ROP / SROP and ret2dlresolve, each listing the
  gadget/symbol pieces present and still missing. Uses the `--gadgets` set.
- Deeper heap analysis (`techniques/heap.py`): UAF, double-free / tcache
  poisoning, overflow into chunk metadata, arbitrary-alloc tcache poisoning and
  unsorted-bin libc leak, gated by allocator version and required primitive.
- TechniqueHint gains `present` / `missing` fields, shown in terminal, markdown
  and json.
- Advanced heap family: House of Force / Spirit, FSOP / _IO_FILE vtable hijack
  (gated on stdio use), and large bin attack.
- `one_gadget` integration now parses each candidate's constraints (not just the
  offset) and shows them in every report format.

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
