"""Accurate C source review backed by tree-sitter.

Where the regex scanner only matches ``name(`` on a line, this backend parses
the real syntax tree. That buys three things:

1. The enclosing function name for every sink call.
2. Calls split across lines, inside macros, or after comments are handled.
3. Format string calls are triaged: ``printf(buf)`` is flagged, but
   ``printf("a constant")`` is not, because a constant format string is not
   attacker controlled. This removes the most common false positive.

tree-sitter is an optional dependency. ``available()`` reports whether it can be
used; callers fall back to the regex scanner when it cannot.
"""

from __future__ import annotations

from pathlib import Path

from pwnariadne.classify.finding import Finding
from pwnariadne.review import taint_c
from pwnariadne.review.sinks import Sink, lookup

# Synthetic sinks for language-level bug patterns (no libc function involved).
_OOB_SINK = Sink(
    name="array-index",
    bug_class="out-of-bounds",
    severity=70,
    why="An array is indexed with an externally influenced value; a too-large or "
    "negative index reads or writes outside the buffer.",
    watch="The index range vs. the array bounds.",
)
_DIVZERO_SINK = Sink(
    name="division",
    bug_class="denial-of-service",
    severity=45,
    why="Dividing by an externally influenced value crashes with SIGFPE when it "
    "is zero (and INT_MIN / -1 overflows).",
    watch="Whether the divisor can be zero or -1.",
)
_VLA_SINK = Sink(
    name="variable-length-array",
    bug_class="denial-of-service",
    severity=50,
    why="A variable-length / alloca-sized stack array with an unbounded size can "
    "exhaust or clash the stack.",
    watch="The size source and any upper bound.",
)

# Index of the format argument for the format string family, by function name.
# Only these are triaged for a constant (safe) format argument.
_FORMAT_ARG_INDEX: dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "dprintf": 1,
    "syslog": 1,
    "snprintf": 2,
    "vsnprintf": 2,
    "__printf_chk": 1,
}


def available() -> bool:
    """Return True if tree-sitter and the C grammar are importable."""

    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_c  # noqa: F401
    except Exception:  # noqa: BLE001 - optional dependency
        return False
    return True


def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_c

    language = Language(tree_sitter_c.language())
    try:
        return Parser(language), language
    except TypeError:  # older binding: set attribute instead
        parser = Parser()
        parser.language = language
        return parser, language


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _callee_name(call, src: bytes) -> str | None:
    fn = call.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "identifier":
        return _text(fn, src)
    # Calls like obj->fn(...) or (ptr)(...) are not simple sink names.
    return None


def _call_arguments(call):
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.is_named]


def _enclosing_function(node, src: bytes) -> str:
    cur = node.parent
    while cur is not None:
        if cur.type == "function_definition":
            decl = cur.child_by_field_name("declarator")
            name = _declarator_name(decl, src)
            if name:
                return name
        cur = cur.parent
    return "?"


def _declarator_name(decl, src: bytes) -> str | None:
    # Drill through pointer / function declarators to the leaf identifier.
    cur = decl
    seen = 0
    while cur is not None and seen < 12:
        seen += 1
        if cur.type == "identifier":
            return _text(cur, src)
        nxt = cur.child_by_field_name("declarator")
        if nxt is None:
            for c in cur.children:
                if c.type in ("identifier", "function_declarator", "pointer_declarator"):
                    nxt = c
                    break
        cur = nxt
    return None


def _format_arg_is_constant(name: str, args: list) -> bool:
    """True if the format argument is a plain string literal (so it is safe)."""

    idx = _FORMAT_ARG_INDEX.get(name)
    if idx is None or idx >= len(args):
        return False
    arg = args[idx]
    # concatenated_string covers "a" "b"; both are compile time constants.
    return arg.type in ("string_literal", "concatenated_string")


def review_file(path: Path) -> list[Finding]:
    """Parse one C file and return sink-call findings."""

    try:
        src = path.read_bytes()
    except OSError:
        return []

    parser, _ = _parser()
    tree = parser.parse(src)
    findings: list[Finding] = []

    # Cache each enclosing function's tainted identifier set by node id.
    taint_cache: dict[int, set[str]] = {}

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            finding = _finding_for_call(node, src, path, taint_cache)
            if finding is not None:
                findings.append(finding)
        elif node.type == "subscript_expression":
            findings.extend(_oob_finding(node, src, path, taint_cache))
        elif node.type == "binary_expression":
            findings.extend(_divzero_finding(node, src, path, taint_cache))
        elif node.type == "array_declarator":
            findings.extend(_vla_finding(node, src, path))
        stack.extend(node.children)

    return findings


def _tainted_for(node, src, taint_cache):
    func = _enclosing_function_node(node)
    if func is None:
        return set()
    t = taint_cache.get(id(func))
    if t is None:
        t = taint_c.compute_tainted(func, src)
        taint_cache[id(func)] = t
    return t


def _mk(sink, node, src, path, taint="tainted"):
    snippet = _text(node, src).replace("\n", " ").strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    return Finding(
        sink=sink,
        address=None,
        in_function=_enclosing_function(node, src),
        source_file=str(path),
        line=node.start_point[0] + 1,
        snippet=snippet,
        taint=taint,
    )


def _oob_finding(node, src, path, taint_cache):
    index = node.child_by_field_name("index")
    if index is None:
        return []
    tainted = _tainted_for(node, src, taint_cache)
    if taint_c._expr_is_tainted(index, src, tainted):
        return [_mk(_OOB_SINK, node, src, path)]
    return []


def _divzero_finding(node, src, path, taint_cache):
    op = node.child_by_field_name("operator")
    if op is None or _text(op, src) not in ("/", "%"):
        return []
    right = node.child_by_field_name("right")
    if right is None:
        return []
    tainted = _tainted_for(node, src, taint_cache)
    if taint_c._expr_is_tainted(right, src, tainted):
        return [_mk(_DIVZERO_SINK, node, src, path)]
    return []


def _vla_finding(node, src, path):
    # `char buf[n]` -> array_declarator with a "size" field that is not a literal.
    size = node.child_by_field_name("size")
    if size is None:
        return []
    if size.type in ("number_literal", "sizeof_expression"):
        return []
    # A runtime-sized stack array (VLA) is a stack-exhaustion risk.
    return [_mk(_VLA_SINK, node, src, path, taint="local")]


def _enclosing_function_node(node):
    cur = node.parent
    while cur is not None:
        if cur.type == "function_definition":
            return cur
        cur = cur.parent
    return None


def _finding_for_call(
    call, src: bytes, path: Path, taint_cache: dict[int, set[str]]
) -> Finding | None:
    name = _callee_name(call, src)
    if name is None:
        return None
    sink = lookup(name)
    if sink is None:
        return None

    # Triage format string calls: a constant format argument is not a bug.
    if sink.bug_class == "format-string" and _format_arg_is_constant(name, _call_arguments(call)):
        return None

    # Taint note from the enclosing function, computed once and cached.
    taint: str | None = None
    func = _enclosing_function_node(call)
    if func is not None:
        tainted = taint_cache.get(id(func))
        if tainted is None:
            tainted = taint_c.compute_tainted(func, src)
            taint_cache[id(func)] = tainted
        taint = taint_c.label_call(call, src, name, tainted)

    line = call.start_point[0] + 1
    snippet = _text(call, src).replace("\n", " ").strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    return Finding(
        sink=sink,
        address=None,
        in_function=_enclosing_function(call, src),
        source_file=str(path),
        line=line,
        snippet=snippet,
        taint=taint,
    )


def review_sources(paths: list[str]) -> list[Finding]:
    """Scan the given .c/.h files or directories with tree-sitter."""

    findings: list[Finding] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for ext in ("*.c", "*.h", "*.cc", "*.cpp"):
                for file in p.rglob(ext):
                    findings.extend(review_file(file))
        elif p.is_file():
            findings.extend(review_file(p))
    return sorted(findings, key=lambda f: f.severity, reverse=True)
