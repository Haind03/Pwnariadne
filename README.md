<p align="center">
  <img src="assets/logo.svg" alt="Pwnariadne" width="620">
</p>

<p align="center">
  <em>Follow the thread from input to crash.</em><br>
  <img alt="CI" src="https://github.com/Haind03/Pwnariadne/actions/workflows/ci.yml/badge.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

# Pwnariadne

**Pwnariadne** is a trigger-guided review and **observe-only** debugging
companion for Linux binaries. Like Ariadne's thread through the labyrinth, it
walks an ELF (and optionally its C source), flags call sites of memory-unsafe
functions, guesses the likely bug class, and emits a ready-to-run **GDB script**
that breaks at those sites so you can *watch* what the program does when they
execute.

It is built for **CTF practice and authorised security testing / code audits**
anywhere you are allowed to analyse the target.

> **Scope.** Pwnariadne points at suspicious spots and helps you observe them at
> runtime. It does **not** generate exploits, payloads, or ROP chains, and the
> GDB scripts it writes only read state: they never modify memory or redirect
> execution. Use it only on binaries you own or are authorised to test.

---

## Why it exists

The usual pwn toolchain is powerful but disjointed: `checksec` tells you the
mitigations, you read disassembly to find dangerous calls, then you hand-type
`break *0x...` in GDB and guess which inputs reach them. Tools like
[`cwe_checker`](https://github.com/fkie-cad/cwe_checker),
[`pwndbg`](https://github.com/pwndbg/pwndbg),
[`GEF`](https://github.com/hugsy/gef) and
[`pwntools`](https://github.com/Gallopsled/pwntools) each own one slice.

Pwnariadne is the **thread that connects review to the debugger**. It does not
reimplement the ecosystem; it **orchestrates** it. One command turns a binary
into a ranked finding list, a candidate-technique study map, a curated ROP
gadget list, *and* a breakpoint script tuned for whichever debugger you run.

## What it combines

| Job | Tool Pwnariadne drives (if present) | Fallback when absent |
|-----|-------------------------------------|----------------------|
| Mitigations | `checksec` / pwntools `ELF` | built-in pyelftools reader |
| Debugger context | **pwndbg** (preferred), then GEF | plain gdb commands |
| Gadget recon | ROPgadget, then ropper | section skipped with a note |
| libc one-shots | one_gadget | section skipped |

Run `pwnariadne --toolbox` to see what was detected on your machine. Pick a
debugger front end with `--debugger pwndbg|gef|gdb` (default `auto`, preferring
pwndbg).

## Pipeline

```
 ELF  >  review   >  classify  >  techniques  >  gdbgen   >  report
 src     (sinks)     (bugclass)   (advisory)     (pwndbg)    (md/json)
                                  + gadgets
```

1. **review**: locate calls to memory-unsafe functions (`gets`, `strcpy`,
   `sprintf`, `scanf` without width, user-controlled `printf`, `system`,
   `free`, `memcpy`, …) in the ELF's PLT (`.plt` and CET `.plt.sec`) and,
   optionally, in C source.
2. **classify**: tag each hit with its likely bug class (stack overflow,
   format string, UAF/double-free, command injection …) and a severity.
3. **gdbgen**: emit an observe-only debugger script that breaks at every finding
   and, on hit, dumps context tuned to the bug class and the chosen front end
   (pwndbg `context`/`canary`/`got`/`heap`/`vis_heap_chunks`, GEF equivalents,
   or plain gdb `info registers`/`x`). Unknown commands are skipped gracefully.
4. **report**: print a terminal table or write Markdown / JSON for your
   write-up or audit note, including a **candidate-techniques** advisory and a
   curated **ROP gadget** list.

## Technique awareness (advisory)

Beyond listing sinks, Pwnariadne reasons from the mitigations + findings +
binary signals (a `/bin/sh` string, a `win`-looking symbol, imported `system`)
to name the **classes of technique worth investigating**, and which mitigation
gates each. This is a study map, not an exploit generator: it never emits
payloads, ROP chains, or offsets.

| Observed condition | Technique surfaced | Gate |
|---|---|---|
| stack overflow, `canary=False` | saved-return-address overwrite | no leak needed |
| stack overflow, `canary=True` | canary leak → overwrite | needs info-leak first |
| stack overflow, `nx=False` | ret2shellcode | W^X disabled |
| stack overflow, `nx=True` | ROP / ret2libc | PIE needs a base leak |
| `win`/backdoor symbol present | ret2win | redirect return address |
| `system` import + shell string | ret2system territory | reach `system()` |
| format-string sink | arbitrary read (leak) | defeats ASLR via leak |
| format-string + RELRO ≠ full | GOT overwrite (`%n`) | writable GOT |
| `malloc`/`free` present | UAF / double-free / tcache study | allocator-dependent |

### ROP and heap detail

With `--gadgets`, the ROP analysis gets concrete: it checks the curated gadget
set and the binary's symbols to surface **ret2libc chain**, **ret2system**,
**ret2csu**, **stack pivot**, **syscall ROP / SROP** and **ret2dlresolve**, and
for each one lists the pieces already **present** and still **missing** (for
example `pop rdi ; ret` present, `pop rsi ; ret` missing).

When heap findings are present, the heap analysis surfaces the glibc ptmalloc
techniques to study: **use-after-free**, **double-free / tcache poisoning**,
**overflow into chunk metadata**, **tcache poisoning (arbitrary alloc)** and an
**unsorted-bin libc leak**, each gated by the allocator version and the
primitive it needs.

These are study maps: Pwnariadne names the pieces and the gaps, it never
assembles a chain or emits a payload.

Suppress the section with `--no-techniques`.

## Install

Requires Python 3.10+ and (for the debugger step) GDB.

```bash
git clone https://github.com/Haind03/Pwnariadne
cd Pwnariadne
pip install -e .          # installs the `pwnariadne` command
# or just: pip install pyelftools capstone rich
```

## Usage

```bash
# Review a binary, print the finding table, and write a GDB script:
pwnariadne ./target --gdb breakpoints.gdb

# Also scan C source alongside the binary:
pwnariadne ./target --source src/ --gdb breakpoints.gdb

# Install as a command and run anywhere:
pip install -e .            # or: make install
pwnariadne ./target --gdb breakpoints.gdb

# Just the trigger points, one per line (greppable / pipe-friendly):
pwnariadne ./target --format endpoints
#   0x4011c2	gets	stack-buffer-overflow
#   0x4011f9	strcpy	stack-buffer-overflow
# e.g. feed the addresses straight into GDB:
pwnariadne ./target --format endpoints | cut -f1

# See which external tools were detected, add ROP gadget recon, pick pwndbg:
pwnariadne ./target --toolbox --gadgets --debugger pwndbg --gdb breakpoints.gdb

# Add a pwntools checksec cross check and libc one_gadget offsets:
pwnariadne ./target --checksec --libc ./libc.so.6 --gadgets

# List indirect dispatch points (function pointer / vtable / GOT calls):
pwnariadne ./target --indirect

# Check which sink sites are reachable from entry (needs angr):
pwnariadne ./target --reachability

# Machine-readable output for your pipeline / write-up:
pwnariadne ./target --gadgets --format json   --output report.json
pwnariadne ./target --gadgets --format markdown --output report.md

# Source-only review (tree-sitter when installed, else regex):
pwnariadne --source src/ --source-backend auto --format markdown --output report.md
```

### Install optional integrations

```bash
pip install -e ".[source]"         # tree-sitter accurate C review
pip install -e ".[integrations]"   # ROPgadget + pwntools
pip install -e ".[reachability]"   # angr (heavy)
# pwndbg / GEF / one_gadget: install per their own docs; auto-detected at runtime
```

Then load the script into GDB:

```bash
gdb -q -x breakpoints.gdb ./target
(gdb) run
```

The script auto-detects pwndbg / GEF if they are loaded and falls back to plain
GDB otherwise.

### Example

```bash
cd examples && make           # builds vuln_demo and heap_demo
cd ..
pwnariadne examples/vuln_demo --gdb demo.gdb
```

```
Mitigations: arch=x64/64 relro=partial canary=False nx=True pie=False
┏━━━┳━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ Sev ┃ Sink   ┃ Bug class             ┃ Location              ┃
┡━━━╇━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │  95 │ gets   │ stack-buffer-overflow │ echo_name @ 0x4011c2  │
│ 2 │  85 │ printf │ format-string         │ echo_name @ 0x4011b1  │
│ 4 │  80 │ strcpy │ stack-buffer-overflow │ copy_input @ 0x4011f9 │
└───┴─────┴────────┴───────────────────────┴───────────────────────┘
```

## Project layout

```
pwnariadne/
├── core/          # ELF loading, mitigations, PLT/call-site disasm, strings/symbols
├── review/        # sink catalogue + binary scan + tree-sitter/regex source scan
├── classify/      # map call sites to ranked, classified findings
├── techniques/    # advisory technique inference (ret2win/ROP/fmt/GOT/heap)
├── integrations/  # detect + drive pwndbg/GEF/ROPgadget/ropper/one_gadget/pwntools/angr
├── gdbgen/        # observe-only debugger-script generator (pwndbg/GEF/gdb flavors)
├── report/        # terminal / endpoints / Markdown / JSON renderers
└── cli.py         # command-line entry point
assets/            # logo (SVG)
examples/          # deliberately-unsafe sample for testing (not an exploit)
tests/             # pytest suite (69 tests, 1 needs angr)
.github/           # CI (pytest on Python 3.10 to 3.12 + CLI smoke test)
```

## Limitations (v0.1)

- Disassembly covers **x86 / x86-64** direct calls into the PLT. Indirect calls
  (through registers / vtables) and other architectures are not resolved yet.
- Source review uses **tree-sitter** when installed (accurate: knows the
  enclosing function, skips constant `printf` formats) and falls back to a
  regex line scanner otherwise. Either way, verify each finding.
- Mitigation detection mirrors common `checksec` heuristics.

## Roadmap

- [x] pwndbg / GEF aware context dumps, bug-class specific
- [x] Multi-tool orchestration (ROPgadget/ropper, toolbox detection)
- [x] `one_gadget` + pwntools `ELF`/`checksec` wiring into the report
- [x] `tree-sitter` backend for accurate source analysis
- [x] Indirect-call detection; arch-aware disassembly (x86/x64 full, ARM/AArch64/MIPS indirect)
- [x] Optional `angr` static reachability (is a sink reachable from entry)
- [x] Taint note: whether a sink argument is constant or externally influenced

## Contributing & license

Issues and PRs welcome. MIT licensed.

---

_Pwnariadne: authored by **HaiND from the Post and Telecommunication Institute
of Technology**._
