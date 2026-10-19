"""Flow-ordered C source checks (tree-sitter).

Four heuristics that need statement order within a function, built on byte
offsets so they stay simple and robust:

* uninitialised-use   : a scalar local read before it is assigned.
* null-pointer-deref  : a malloc result dereferenced before a NULL check.
* race-condition      : access/stat a path, then open it separately (TOCTOU).
* out-of-bounds       : a loop bounded with <= that indexes an array by the
                        loop variable (classic off-by-one).

These are heuristics, so they favour recall and can produce false positives;
each finding is a lead to verify, never a proof.
"""

from __future__ import annotations

from pathlib import Path

from pwnariadne.classify.finding import Finding
from pwnariadne.review.sinks import Sink

_UNINIT_SINK = Sink(
    name="uninitialised-use", bug_class="uninitialized-use", severity=55,
    why="A local scalar is read before it is assigned, so it holds leftover stack "
    "data (an info leak or unpredictable control).",
    watch="The first read of the variable vs. where it is set.",
)
_NULLDEREF_SINK = Sink(
    name="unchecked-malloc", bug_class="null-pointer-dereference", severity=50,
    why="A malloc result is used before a NULL check; on allocation failure this "
    "dereferences NULL and crashes.",
    watch="Whether the pointer is checked between the allocation and its use.",
)
_TOCTOU_SINK = Sink(
    name="toctou", bug_class="race-condition", severity=55,
    why="A path is checked (access/stat) then opened separately; it can be swapped "
    "between the check and the use.",
    watch="Use the opened fd (openat/fstat) rather than re-resolving the path.",
)
_OBO_SINK = Sink(
    name="off-by-one-loop", bug_class="out-of-bounds", severity=55,
    why="A loop bounded with <= runs one iteration past the end; indexing an array "
    "with the loop variable then steps one element out of bounds.",
    watch="The loop bound vs. the array size (prefer < over <=).",
)

_ALLOC = {"malloc", "calloc", "realloc", "valloc", "alloca", "strdup"}
_CHECK_FUNCS = {"access", "faccessat", "stat", "lstat", "stat64", "lstat64"}
_USE_FUNCS = {"open", "open64", "openat", "fopen", "fopen64", "creat"}
_DEREF_FUNCS = {"strcpy", "strcat", "sprintf", "memcpy", "memmove", "memset",
                "strlen", "puts", "fputs", "free"}


def _text(n, src: bytes) -> str:
    return src[n.start_byte : n.end_byte].decode("utf-8", "replace")


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _callee(call, src):
    fn = call.child_by_field_name("function")
    return _text(fn, src) if fn is not None and fn.type == "identifier" else None


def _first_arg_ident(call, src):
    al = call.child_by_field_name("arguments")
    if al is None:
        return None
    for c in al.children:
        if c.is_named:
            return _base_ident(c, src)
    return None


def _args(call):
    al = call.child_by_field_name("arguments")
    return [c for c in al.children if c.is_named] if al else []


def _base_ident(node, src):
    cur = node
    guard = 0
    while cur is not None and guard < 12:
        guard += 1
        if cur.type == "identifier":
            return _text(cur, src)
        if cur.type in ("pointer_expression", "parenthesized_expression",
                        "cast_expression", "unary_expression", "subscript_expression",
                        "field_expression"):
            cur = cur.child_by_field_name("argument") or (
                cur.named_children[0] if cur.named_children else None)
        else:
            cur = cur.named_children[0] if cur.named_children else None
    return None


def _func_name(func, src):
    decl = func.child_by_field_name("declarator")
    stack = [decl] if decl else []
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.type == "function_declarator":
            d = n.child_by_field_name("declarator")
            return _text(d, src) if d is not None else "?"
        stack.extend(n.children)
    return "?"


def _mk(sink, node, src, path, func_name):
    snippet = _text(node, src).replace("\n", " ").strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    return Finding(
        sink=sink, address=None, in_function=func_name, source_file=str(path),
        line=node.start_point[0] + 1, snippet=snippet, taint="local",
    )


def flow_findings(root, src: bytes, path: Path) -> list[Finding]:
    out: list[Finding] = []
    for node in _walk(root):
        if node.type == "function_definition":
            fname = _func_name(node, src)
            out += _uninit(node, src, path, fname)
            out += _nullderef(node, src, path, fname)
            out += _toctou(node, src, path, fname)
            out += _offbyone(node, src, path, fname)
    return out


def _ident_role(ident, src):
    """Classify an identifier node: 'write', 'read', or 'skip'."""

    p = ident.parent
    if p is None:
        return "read"
    if p.type == "call_expression" and p.child_by_field_name("function") == ident:
        return "skip"
    if p.type == "field_expression" and p.child_by_field_name("field") == ident:
        return "skip"
    if p.type in ("init_declarator", "declaration", "array_declarator",
                  "pointer_declarator", "function_declarator", "parameter_declaration"):
        return "skip"
    # Address-of: &x is a write (output parameter) for uninit purposes.
    if p.type in ("pointer_expression", "unary_expression"):
        op = p.child_by_field_name("operator")
        if op is not None and src_op_raw(op, src) == "&":
            return "write"
    if p.type == "assignment_expression" and p.child_by_field_name("left") == ident:
        return "write"
    if p.type == "update_expression":  # x++ / x--
        return "write"
    return "read"


def _uninit(func, src, path, fname):
    body = func.child_by_field_name("body")
    if body is None:
        return []
    # Uninitialised scalar locals: `T x;` with no initialiser, not an array.
    uninit: dict[str, int] = {}
    for n in _walk(body):
        if n.type == "declaration":
            for d in n.named_children:
                if d.type == "init_declarator":
                    continue  # has a value
                if d.type == "identifier":
                    uninit[_text(d, src)] = d.start_byte
    out = []
    for name, decl_off in uninit.items():
        reads, writes = [], []
        for n in _walk(body):
            if n.type == "identifier" and _text(n, src) == name and n.start_byte > decl_off:
                role = _ident_role(n, src)
                if role == "read":
                    reads.append(n)
                elif role == "write":
                    writes.append(n.start_byte)
        if not reads:
            continue
        first_read = min(reads, key=lambda x: x.start_byte)
        first_write = min(writes) if writes else None
        if first_write is None or first_read.start_byte < first_write:
            out.append(_mk(_UNINIT_SINK, first_read, src, path, fname))
    return out


def _nullderef(func, src, path, fname):
    body = func.child_by_field_name("body")
    if body is None:
        return []
    out = []
    # malloc'd pointers: name -> allocation byte offset.
    allocated: dict[str, int] = {}
    for n in _walk(body):
        if n.type == "init_declarator":
            val = n.child_by_field_name("value")
            if val is not None and val.type == "call_expression" and _callee(val, src) in _ALLOC:
                name = _base_ident(n.child_by_field_name("declarator"), src)
                if name:
                    allocated[name] = n.start_byte
        elif n.type == "assignment_expression":
            right = n.child_by_field_name("right")
            if right is not None and right.type == "call_expression" and _callee(right, src) in _ALLOC:
                name = _base_ident(n.child_by_field_name("left"), src)
                if name:
                    allocated[name] = n.start_byte
    for name, alloc_off in allocated.items():
        check_off = _first_check(body, name, src)
        deref = _first_deref(body, name, src, after=alloc_off)
        if deref is not None and deref.start_byte < check_off:
            out.append(_mk(_NULLDEREF_SINK, deref, src, path, fname))
    return out


def _first_check(body, name, src):
    best = float("inf")
    for n in _walk(body):
        if n.type == "if_statement":
            cond = n.child_by_field_name("condition")
            if cond is not None and any(
                c.type == "identifier" and _text(c, src) == name for c in _walk(cond)
            ):
                best = min(best, n.start_byte)
    return best


def _first_deref(body, name, src, after):
    best = None
    for n in _walk(body):
        if n.start_byte <= after:
            continue
        hit = False
        if n.type == "pointer_expression":  # *p (deref), not &
            op = n.child_by_field_name("operator")
            if op is not None and src_op_raw(op, src) == "*" and _base_ident(n, src) == name:
                hit = True
        elif n.type in ("field_expression", "subscript_expression"):
            if _base_ident(n.child_by_field_name("argument"), src) == name:
                hit = True
        elif n.type == "call_expression" and _callee(n, src) in _DEREF_FUNCS:
            if _first_arg_ident(n, src) == name:
                hit = True
        if hit and (best is None or n.start_byte < best.start_byte):
            best = n
    return best


def src_op_raw(op, src):
    return src[op.start_byte : op.end_byte].decode("utf-8", "replace")


def _toctou(func, src, path, fname):
    body = func.child_by_field_name("body")
    if body is None:
        return []
    checks: dict[str, int] = {}   # path ident -> earliest check offset
    uses: list = []               # (path ident, use call node)
    for n in _walk(body):
        if n.type != "call_expression":
            continue
        name = _callee(n, src)
        arg = _first_arg_ident(n, src)
        if arg is None:
            continue
        if name in _CHECK_FUNCS:
            checks[arg] = min(checks.get(arg, n.start_byte), n.start_byte)
        elif name in _USE_FUNCS:
            uses.append((arg, n))
    out = []
    for arg, node in uses:
        if arg in checks and node.start_byte > checks[arg]:
            out.append(_mk(_TOCTOU_SINK, node, src, path, fname))
    return out


def _offbyone(func, src, path, fname):
    out = []
    for n in _walk(func):
        if n.type not in ("for_statement", "while_statement"):
            continue
        cond = n.child_by_field_name("condition")
        body = n.child_by_field_name("body")
        if cond is None or body is None:
            continue
        le = _find_le(cond, src)
        if le is None:
            continue
        loopvar = _text(le, src)
        # The body indexes an array with the loop variable.
        for s in _walk(body):
            if s.type == "subscript_expression":
                idx = s.child_by_field_name("index")
                if idx is not None and idx.type == "identifier" and _text(idx, src) == loopvar:
                    out.append(_mk(_OBO_SINK, n, src, path, fname))
                    break
    return out


def _find_le(cond, src):
    """Return the left identifier of an `i <= ...` comparison, else None."""

    for n in _walk(cond):
        if n.type == "binary_expression":
            op = n.child_by_field_name("operator")
            left = n.child_by_field_name("left")
            if op is not None and src_op_raw(op, src) == "<=" and left is not None \
                    and left.type == "identifier":
                return left
    return None
