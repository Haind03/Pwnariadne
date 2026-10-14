"""Catalogue of memory-unsafe / high-risk libc functions ("sinks").

Each entry records why the function is risky, the bug class it most often
leads to, and a short note on what to watch for at runtime. This drives both
the static review and the GDB script generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Sink:
    """A library function worth stopping on."""

    name: str
    # Bug class most associated with misuse of this function.
    bug_class: str
    # Severity hint, used only for ranking the report (0-100).
    severity: int
    # Human explanation of the risk.
    why: str
    # What to inspect when execution reaches the call site.
    watch: str
    # Alternative aliases (e.g. the __isoc99_ scanf family, _chk variants).
    aliases: tuple[str, ...] = field(default_factory=tuple)


# Ordered roughly by how often they show up in real-world and CTF bugs.
SINKS: tuple[Sink, ...] = (
    Sink(
        name="gets",
        bug_class="stack-buffer-overflow",
        severity=95,
        why="Reads a line with no bound; always overflowable. Removed from C11.",
        watch="Destination buffer address and the saved return address above it.",
    ),
    Sink(
        name="strcpy",
        bug_class="stack-buffer-overflow",
        severity=80,
        why="Copies until NUL with no destination bound.",
        watch="Length of the source string vs. the destination buffer size.",
        aliases=("__strcpy_chk",),
    ),
    Sink(
        name="strcat",
        bug_class="stack-buffer-overflow",
        severity=75,
        why="Appends until NUL with no destination bound.",
        watch="Combined length vs. destination capacity.",
        aliases=("__strcat_chk",),
    ),
    Sink(
        name="sprintf",
        bug_class="stack-buffer-overflow",
        severity=78,
        why="Formats into a buffer with no size limit; use snprintf instead.",
        watch="Rendered length vs. destination buffer size.",
        aliases=("__sprintf_chk", "vsprintf"),
    ),
    Sink(
        name="scanf",
        bug_class="stack-buffer-overflow",
        severity=70,
        why="%s / %[ without a width specifier reads unbounded input.",
        watch="The conversion specifier and the destination buffer size.",
        aliases=("__isoc99_scanf", "sscanf", "__isoc99_sscanf", "fscanf"),
    ),
    Sink(
        name="printf",
        bug_class="format-string",
        severity=85,
        why="If the format argument is attacker-controlled, leaks or writes memory.",
        watch="Whether the first argument is a constant string or user data.",
        aliases=("fprintf", "vprintf", "vfprintf", "__printf_chk"),
    ),
    Sink(
        name="read",
        bug_class="buffer-overflow",
        severity=55,
        why="Can write more bytes than the destination holds if the count is wrong.",
        watch="The length argument vs. the destination buffer size.",
    ),
    Sink(
        name="memcpy",
        bug_class="buffer-overflow",
        severity=60,
        why="Copies a caller-supplied length; wrong length overflows.",
        watch="The length argument and both buffer sizes.",
        aliases=("__memcpy_chk", "memmove"),
    ),
    Sink(
        name="free",
        bug_class="use-after-free / double-free",
        severity=65,
        why="Freed pointers reused or freed twice corrupt the heap.",
        watch="The chunk address; whether it is freed again or used afterwards.",
    ),
    Sink(
        name="malloc",
        bug_class="heap-overflow",
        severity=40,
        why="Undersized allocations lead to heap overflow when later written.",
        watch="The requested size vs. how much is written into the chunk.",
        aliases=("calloc", "realloc"),
    ),
    Sink(
        name="system",
        bug_class="command-injection",
        severity=90,
        why="Executes a shell command; attacker-controlled argument is RCE.",
        watch="The command string and where it comes from.",
        aliases=("popen", "execve", "execl", "execlp"),
    ),
    Sink(
        name="alloca",
        bug_class="stack-clash",
        severity=50,
        why="Dynamic stack allocation with a large/user size can clash the stack.",
        watch="The size argument.",
    ),
    Sink(
        name="snprintf",
        bug_class="format-string",
        severity=45,
        why="Bounded, but a user-controlled format string still leaks/writes (%n).",
        watch="Whether the format argument is constant.",
        aliases=("vsnprintf", "__snprintf_chk"),
    ),
    Sink(
        name="syslog",
        bug_class="format-string",
        severity=60,
        why="Format argument is often attacker-influenced log data.",
        watch="Whether the format argument is a constant string.",
    ),
    Sink(
        name="atoi",
        bug_class="integer-overflow",
        severity=35,
        why="No error/range checking; result often feeds a size or index.",
        watch="How the parsed value is used (allocation size, loop bound, index).",
        aliases=("atol", "atoll", "strtol", "strtoul"),
    ),
    Sink(
        name="realpath",
        bug_class="buffer-overflow",
        severity=50,
        why="With a NULL/short resolved-path buffer, long paths overflow (PATH_MAX).",
        watch="The size of the resolved-path buffer.",
    ),
    Sink(
        name="getenv",
        bug_class="tainted-source",
        severity=30,
        why="Returns attacker-influenced data in many contexts; a taint source.",
        watch="Where the returned string flows (into a sink above).",
    ),
    Sink(
        name="recv",
        bug_class="buffer-overflow",
        severity=50,
        why="A wrong length argument writes past the destination buffer.",
        watch="The length argument vs. the destination buffer size.",
        aliases=("recvfrom", "fgets"),
    ),
    Sink(
        name="memset",
        bug_class="buffer-overflow",
        severity=30,
        why="A wrong length argument writes past the destination buffer.",
        watch="The length argument vs. the destination buffer size.",
    ),
)


def _index() -> dict[str, Sink]:
    table: dict[str, Sink] = {}
    for sink in SINKS:
        table[sink.name] = sink
        for alias in sink.aliases:
            table[alias] = sink
    return table


_INDEX = _index()


def lookup(symbol: str) -> Sink | None:
    """Return the Sink for a symbol name, resolving common decorations.

    Handles GOT/PLT decorations such as a trailing ``@plt`` and the glibc
    ``_chk`` / ``__isoc99_`` prefixes already covered by aliases.
    """

    name = symbol.strip()
    for suffix in ("@plt", "@got.plt", "@GLIBC", "@@GLIBC"):
        cut = name.find(suffix)
        if cut != -1:
            name = name[:cut]
    return _INDEX.get(name)


def all_names() -> frozenset[str]:
    """Every symbol name (including aliases) that counts as a sink."""

    return frozenset(_INDEX)
