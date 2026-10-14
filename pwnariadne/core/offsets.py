"""Assembly-level overflow offset solver.

For each stack-writing sink call, this reads the actual instructions of the
enclosing function and works out the byte distance from the destination buffer
to the saved return address: the number you pad before overwriting RIP.

It is pure static reasoning over the disassembly (capstone). It computes a
number and shows the instructions it used; it writes no input and runs nothing.
x86-64 System V only for now (where the destination buffer is passed in a
register); other layouts return no offset.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86 import (
    X86_REG_EBP,
    X86_REG_ESP,
    X86_REG_RBP,
    X86_REG_RSP,
)

# Which argument register holds the destination buffer, per sink (SysV x86-64).
_DEST_ARG_REG = {
    "gets": "rdi",
    "fgets": "rdi",
    "strcpy": "rdi",
    "strcat": "rdi",
    "sprintf": "rdi",
    "read": "rsi",
    "recv": "rsi",
    "scanf": "rsi",
    "__isoc99_scanf": "rsi",
    "fscanf": "rsi",
}


@dataclass
class OverflowOffset:
    """A computed overflow distance for one stack-writing sink call."""

    sink: str
    call_address: int
    in_function: str
    dest_reg: str
    buf_disp: int  # distance from the buffer to saved rbp (bytes)
    offset_to_saved_rbp: int  # -1 when the function has no frame pointer
    offset_to_ret: int
    # Distance to the stack canary slot when one is in use; the overflow must
    # preserve or leak this value before it reaches the saved RIP.
    offset_to_canary: int
    confidence: str  # "high" | "medium"
    frame_kind: str = "rbp"  # "rbp" (push rbp frame) or "rsp" (sub rsp frame)
    asm: list[str] = field(default_factory=list)


def solve_overflow_offsets(binary) -> list[OverflowOffset]:
    """Return computed overflow offsets for stack-writing sink calls."""

    if binary.arch != "x64":  # SysV register-arg layout only
        return []
    text = binary.elf.get_section_by_name(".text")
    if text is None:
        return []
    plt_map = binary._plt_map()
    if not plt_map:
        return []

    md = binary._disassembler()
    if md is None:
        return []
    md.detail = True

    funcs = binary.defined_functions()
    func_addrs = sorted(funcs)
    insns = list(md.disasm(text.data(), text["sh_addr"]))

    out: list[OverflowOffset] = []
    # rbp-relative displacement per register (negative), rsp-relative
    # displacement per register (non-negative), and the cumulative stack growth
    # from the function entry (push += 8, sub rsp,N += N, pop/add undo).
    reg_disp: dict[str, int] = {}
    reg_rsp: dict[str, int] = {}
    stack_adj = [0]
    recent: list = []
    cur_func = None

    for insn in insns:
        func = binary._enclosing(insn.address, func_addrs, funcs)
        if func != cur_func:
            reg_disp.clear()
            reg_rsp.clear()
            stack_adj[0] = 0
            cur_func = func
        recent.append(insn)
        if len(recent) > 8:
            recent.pop(0)

        mnem = insn.mnemonic
        if mnem == "push":
            stack_adj[0] += 8
        elif mnem == "pop":
            stack_adj[0] -= 8
        elif mnem in ("sub", "add"):
            _track_rsp_imm(insn, stack_adj, add=(mnem == "add"))
        elif mnem == "lea":
            _track_lea(insn, reg_disp, reg_rsp)
        elif mnem == "mov":
            _track_mov(insn, reg_disp, reg_rsp)
        elif mnem == "call":
            base = _sink_base(plt_map.get(_direct_target(insn)))
            dest = _DEST_ARG_REG.get(base) if base else None
            if dest is None:
                continue
            off = _compute(dest, reg_disp, reg_rsp, stack_adj[0])
            if off is None:
                continue
            kind, to_ret, to_rbp, to_canary, buf = off
            out.append(
                OverflowOffset(
                    sink=base,
                    call_address=insn.address,
                    in_function=func,
                    dest_reg=dest,
                    buf_disp=buf,
                    offset_to_saved_rbp=to_rbp,
                    offset_to_ret=to_ret,
                    offset_to_canary=to_canary,
                    confidence="high",
                    frame_kind=kind,
                    asm=[f"{i.address:#x}: {i.mnemonic} {i.op_str}".rstrip() for i in recent],
                )
            )
    return out


def _compute(dest, reg_disp, reg_rsp, stack_adj):
    """Return (frame_kind, to_ret, to_saved_rbp, to_canary, buf_disp) or None."""

    if dest in reg_disp and reg_disp[dest] < 0:
        x = -reg_disp[dest]
        # rbp frame: ret at rbp+8, saved rbp at rbp, canary at rbp-8.
        return ("rbp", x + 8, x, x - 8, x)
    if dest in reg_rsp and stack_adj > 0 and 0 <= reg_rsp[dest] < stack_adj:
        k = reg_rsp[dest]
        # rsp frame (no saved rbp): return address sits at entry rsp, which is
        # stack_adj bytes above the current rsp; the buffer is k above rsp.
        to_ret = stack_adj - k
        return ("rsp", to_ret, -1, to_ret - 8, k)
    return None


def _sink_base(sym: str | None) -> str | None:
    if not sym:
        return None
    name = sym.split("@")[0]
    # Normalise the fortified / isoc99 decorations we care about.
    if name in _DEST_ARG_REG:
        return name
    stripped = name.replace("__isoc99_", "")
    if stripped in _DEST_ARG_REG:
        return stripped
    if name.startswith("__") and name.endswith("_chk"):
        core = name[2:-4]
        if core in _DEST_ARG_REG:
            return core
    return None


def _direct_target(insn) -> int:
    op = insn.op_str.strip()
    if op.startswith("0x"):
        try:
            return int(op, 16)
        except ValueError:
            return -1
    return -1


def _track_rsp_imm(insn, stack_adj: list, add: bool) -> None:
    ops = insn.operands
    if (
        len(ops) == 2
        and ops[0].type == CS_OP_REG
        and insn.reg_name(ops[0].reg) in ("rsp", "esp")
        and ops[1].type == CS_OP_IMM
    ):
        stack_adj[0] += -ops[1].imm if add else ops[1].imm


def _track_lea(insn, reg_disp: dict[str, int], reg_rsp: dict[str, int]) -> None:
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != CS_OP_REG or ops[1].type != CS_OP_MEM:
        return
    dest = insn.reg_name(ops[0].reg)
    mem = ops[1].mem
    if mem.index != 0:
        reg_disp.pop(dest, None)
        reg_rsp.pop(dest, None)
        return
    if mem.base in (X86_REG_RBP, X86_REG_EBP):
        reg_disp[dest] = mem.disp
        reg_rsp.pop(dest, None)
    elif mem.base in (X86_REG_RSP, X86_REG_ESP):
        reg_rsp[dest] = mem.disp
        reg_disp.pop(dest, None)
    else:
        reg_disp.pop(dest, None)
        reg_rsp.pop(dest, None)


def _track_mov(insn, reg_disp: dict[str, int], reg_rsp: dict[str, int]) -> None:
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != CS_OP_REG:
        return
    dest = insn.reg_name(ops[0].reg)
    if ops[1].type == CS_OP_REG:
        src = insn.reg_name(ops[1].reg)
        if src in ("rsp", "esp"):  # mov reg, rsp -> buffer is rsp+0
            reg_rsp[dest] = 0
            reg_disp.pop(dest, None)
            return
        if src in reg_disp:
            reg_disp[dest] = reg_disp[src]
            reg_rsp.pop(dest, None)
            return
        if src in reg_rsp:
            reg_rsp[dest] = reg_rsp[src]
            reg_disp.pop(dest, None)
            return
    reg_disp.pop(dest, None)
    reg_rsp.pop(dest, None)
