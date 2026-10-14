"""Intraprocedural taint notes for C source findings.

For each function this computes a best-effort set of "tainted" identifiers:
function parameters, plus any variable assigned from an external input source or
written by an input routine. A sink call's key argument is then labelled:

* "tainted"  : the argument carries external input.
* "constant" : the argument is a string literal.
* "local"    : a local value with no visible external influence.
* None        : the backend cannot decide.

This is a heuristic. It ignores control flow and aliasing, so treat the note as
a prioritisation hint, not a proof. It is read only static analysis.
"""

from __future__ import annotations

# Calls whose return value is external input (rhs taint sources).
_RETURN_TAINT = {"getenv", "recv", "recvfrom", "read", "fread", "fgets"}

# Calls that write external input into a destination argument (by arg index).
_DEST_TAINT: dict[str, int] = {
    "gets": 0,
    "fgets": 0,
    "read": 1,
    "recv": 1,
    "recvfrom": 1,
    "fread": 0,
    "scanf": 1,  # scanf("%s", buf): destination is the arg after the format
    "__isoc99_scanf": 1,
}

# Sinks whose data is inherently external (stdin / socket / file input).
INHERENTLY_EXTERNAL = {
    "gets",
    "scanf",
    "__isoc99_scanf",
    "fscanf",
    "read",
    "recv",
    "recvfrom",
    "fgets",
    "fread",
}

# For other sinks, which argument indices carry the data worth judging.
_SOURCE_ARGS: dict[str, tuple[int, ...]] = {
    "strcpy": (1,),
    "strncpy": (1,),
    "strcat": (1,),
    "memcpy": (1,),
    "memmove": (1,),
    "sprintf": (1, 2, 3, 4),
    "system": (0,),
    "popen": (0,),
    "atoi": (0,),
    "atol": (0,),
    "strtol": (0,),
    "strtoul": (0,),
    "sscanf": (0,),
    "printf": (0,),
    "fprintf": (1,),
    "snprintf": (2,),
    "syslog": (1,),
}


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _base_identifier(node, src: bytes) -> str | None:
    """Reduce an argument expression to its base identifier name, if any.

    Strips address-of, casts, array indexing and member access so that
    ``&buf``, ``buf[0]`` and ``obj->buf`` all resolve to ``buf``/``obj``.
    """

    cur = node
    guard = 0
    while cur is not None and guard < 16:
        guard += 1
        t = cur.type
        if t == "identifier":
            return _text(cur, src)
        if t in (
            "pointer_expression",
            "parenthesized_expression",
            "cast_expression",
            "unary_expression",
        ):
            cur = cur.child_by_field_name("argument") or (
                cur.named_children[-1] if cur.named_children else None
            )
        elif t == "subscript_expression":
            cur = cur.child_by_field_name("argument")
        elif t == "field_expression":
            cur = cur.child_by_field_name("argument")
        else:
            cur = cur.named_children[0] if cur.named_children else None
    return None


def _args(call):
    al = call.child_by_field_name("arguments")
    if al is None:
        return []
    return [c for c in al.children if c.is_named]


def _callee(call, src: bytes) -> str | None:
    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "identifier":
        return _text(fn, src)
    return None


def _collect_params(func, src: bytes) -> set[str]:
    names: set[str] = set()
    decl = func.child_by_field_name("declarator")
    # Find the parameter_list anywhere under the declarator.
    stack = [decl] if decl else []
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.type == "parameter_declaration":
            ident = _declarator_identifier(n.child_by_field_name("declarator"), src)
            if ident:
                names.add(ident)
            continue
        stack.extend(n.children)
    return names


def _declarator_identifier(decl, src: bytes) -> str | None:
    cur = decl
    guard = 0
    while cur is not None and guard < 12:
        guard += 1
        if cur.type == "identifier":
            return _text(cur, src)
        cur = cur.child_by_field_name("declarator") or (
            cur.named_children[0] if cur.named_children else None
        )
    return None


def compute_tainted(func, src: bytes) -> set[str]:
    """Return the set of tainted identifier names in a function definition."""

    tainted: set[str] = set(_collect_params(func, src))

    # Forward pre-order pass over the function in document order.
    order: list = []

    def visit(n):
        order.append(n)
        for c in n.children:
            visit(c)

    body = func.child_by_field_name("body")
    if body is not None:
        visit(body)

    for node in order:
        if node.type == "init_declarator":
            name = _declarator_identifier(node.child_by_field_name("declarator"), src)
            value = node.child_by_field_name("value")
            if name and value is not None and _expr_is_tainted(value, src, tainted):
                tainted.add(name)
        elif node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            base = _base_identifier(lhs, src) if lhs else None
            if base and rhs is not None and _expr_is_tainted(rhs, src, tainted):
                tainted.add(base)
        elif node.type == "call_expression":
            name = _callee(node, src)
            if name in _DEST_TAINT:
                idx = _DEST_TAINT[name]
                args = _args(node)
                if idx < len(args):
                    dest = _base_identifier(args[idx], src)
                    if dest:
                        tainted.add(dest)
            elif name in ("strcpy", "strncpy", "strcat", "memcpy", "memmove"):
                args = _args(node)
                if len(args) >= 2 and _expr_is_tainted(args[1], src, tainted):
                    dest = _base_identifier(args[0], src)
                    if dest:
                        tainted.add(dest)

    return tainted


def _expr_is_tainted(node, src: bytes, tainted: set[str]) -> bool:
    """True if an expression reads a tainted identifier or a taint source call."""

    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "identifier" and _text(n, src) in tainted:
            return True
        if n.type == "call_expression":
            name = _callee(n, src)
            if name in _RETURN_TAINT:
                return True
        stack.extend(n.children)
    return False


def label_call(call, src: bytes, sink_name: str, tainted: set[str]) -> str | None:
    """Return the taint label for a sink call: tainted / constant / local."""

    if sink_name in INHERENTLY_EXTERNAL:
        return "tainted"

    indices = _SOURCE_ARGS.get(sink_name)
    args = _args(call)
    if not indices or not args:
        return None

    saw_arg = False
    all_constant = True
    for idx in indices:
        if idx >= len(args):
            continue
        saw_arg = True
        arg = args[idx]
        if arg.type not in ("string_literal", "concatenated_string"):
            all_constant = False
        if _expr_is_tainted(arg, src, tainted):
            return "tainted"
    if not saw_arg:
        return None
    return "constant" if all_constant else "local"
