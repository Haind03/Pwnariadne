"""ELF inspection: security mitigations and call sites into the PLT.

Built on pyelftools (parsing) and capstone (disassembly). The goal is only to
*find* where risky functions are called, not to modify or run anything.
"""

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


@dataclass
class Mitigations:
    """Standard Linux exploit mitigations, as reported by checksec-style checks."""

    arch: str
    bits: int
    relro: str  # "full", "partial", or "none"
    canary: bool
    nx: bool
    pie: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "relro": self.relro,
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
        }


@dataclass
class CallSite:
    """A direct call instruction targeting an imported function."""

    address: int  # virtual address of the call instruction
    target_symbol: str  # resolved imported name, e.g. "gets"
    in_function: str  # nearest preceding function symbol, or "?"


class Binary:
    """A loaded ELF, offering mitigation and call-site queries."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "rb")  # noqa: SIM115 - kept open for lazy section reads
        self.elf = ELFFile(self._fh)
        self.bits = 64 if self.elf.elfclass == 64 else 32
        self.arch = self.elf.get_machine_arch()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "Binary":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- mitigations -------------------------------------------------------

    def mitigations(self) -> Mitigations:
        return Mitigations(
            arch=self.arch,
            bits=self.bits,
            relro=self._relro(),
            canary=self._has_canary(),
            nx=self._has_nx(),
            pie=self._is_pie(),
        )

    def _relro(self) -> str:
        has_gnu_relro = any(
            seg["p_type"] == "PT_GNU_RELRO" for seg in self.elf.iter_segments()
        )
        if not has_gnu_relro:
            return "none"
        dyn = self._dynamic_section()
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    return "full"
                if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8:
                    return "full"  # DF_BIND_NOW
                if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x1:
                    return "full"  # DF_1_NOW
        return "partial"

    def _has_canary(self) -> bool:
        for name in ("__stack_chk_fail", "__stack_chk_guard"):
            if self._imports_symbol(name):
                return True
        return False

    def _has_nx(self) -> bool:
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                return not bool(seg["p_flags"] & 0x1)  # PF_X cleared => NX on
        return True  # no GNU_STACK header => NX by default on modern toolchains

    def _is_pie(self) -> bool:
        if self.elf["e_type"] == "ET_DYN":
            dyn = self._dynamic_section()
            if dyn is not None:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x08000000:
                        return True  # DF_1_PIE
            return True  # ET_DYN without an explicit marker is treated as PIE
        return False

    # -- symbols -----------------------------------------------------------

    def _dynamic_section(self) -> DynamicSection | None:
        sec = self.elf.get_section_by_name(".dynamic")
        return sec if isinstance(sec, DynamicSection) else None

    def _imports_symbol(self, name: str) -> bool:
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name == name:
                        return True
        return False

    def defined_functions(self) -> dict[int, str]:
        """Map of function virtual address -> name, from the symbol tables."""

        funcs: dict[int, str] = {}
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
                        funcs[sym["st_value"]] = sym.name
        return funcs

    # -- PLT resolution ----------------------------------------------------

    def _plt_map(self) -> dict[int, str]:
        """Map each PLT stub address to the imported symbol it resolves.

        Uses the JMPREL relocations plus the dynamic symbol table. The Nth
        relocation matches the Nth PLT entry. Two layouts are handled:

        * Legacy ``.plt``: PLT[0] is reserved, so the first real stub sits at
          ``base + entry_size``.
        * CET ``.plt.sec`` (modern gcc/clang with ``-fcf-protection``): direct
          calls target this section, which has no reserved entry, so stub N is
          at ``base + N * entry_size``. We map both so either call target
          resolves.
        """

        rela = None
        for name in (".rela.plt", ".rel.plt"):
            sec = self.elf.get_section_by_name(name)
            if isinstance(sec, RelocationSection):
                rela = sec
                break
        if rela is None:
            return {}

        dynsym = self.elf.get_section_by_name(".dynsym")
        if not isinstance(dynsym, SymbolTableSection):
            return {}

        entry_size = 16  # standard PLT stub size on x86/x86-64
        plt = self.elf.get_section_by_name(".plt")
        plt_sec = self.elf.get_section_by_name(".plt.sec")

        mapping: dict[int, str] = {}
        for idx, reloc in enumerate(rela.iter_relocations()):
            name = dynsym.get_symbol(reloc["r_info_sym"]).name
            if plt is not None:
                # Legacy layout: skip reserved PLT[0].
                mapping[plt["sh_addr"] + (idx + 1) * entry_size] = name
            if plt_sec is not None:
                # CET layout: no reserved entry, calls land here.
                mapping[plt_sec["sh_addr"] + idx * entry_size] = name
        return mapping

    # -- call sites --------------------------------------------------------

    def call_sites(self) -> list[CallSite]:
        """Find direct calls into the PLT that resolve to imported functions."""

        if self.arch not in ("x86", "x64"):
            return []  # v0.1 disassembles x86 / x86-64 only

        text = self.elf.get_section_by_name(".text")
        if text is None:
            return []

        plt_map = self._plt_map()
        if not plt_map:
            return []

        mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = False

        code = text.data()
        base = text["sh_addr"]
        funcs = self.defined_functions()
        func_addrs = sorted(funcs)

        sites: list[CallSite] = []
        for insn in md.disasm(code, base):
            if insn.mnemonic != "call":
                continue
            op = insn.op_str.strip()
            # Direct near call with an absolute immediate target, e.g. "call 0x401030".
            if not op.startswith("0x"):
                continue
            try:
                target = int(op, 16)
            except ValueError:
                continue
            symbol = plt_map.get(target)
            if symbol is None:
                continue
            sites.append(
                CallSite(
                    address=insn.address,
                    target_symbol=symbol,
                    in_function=self._enclosing(insn.address, func_addrs, funcs),
                )
            )
        return sites

    @staticmethod
    def _enclosing(
        addr: int, func_addrs: list[int], funcs: dict[int, str]
    ) -> str:
        enclosing = "?"
        for start in func_addrs:
            if start <= addr:
                enclosing = funcs[start]
            else:
                break
        return enclosing
