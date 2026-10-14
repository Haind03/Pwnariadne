"""Pwnariadne: the thread through the binary labyrinth.

A trigger-guided review and debugging companion for Linux binaries. It walks an
ELF (and optionally its C source), flags call sites of memory-unsafe functions,
guesses the likely bug class, and emits a ready-to-run GDB script that sets
breakpoints at those sites so you can *observe* program state when they execute.

Defensive / educational use only: Pwnariadne points at suspicious spots and
helps you watch them at runtime. It does not generate exploits or payloads.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""

SIGNATURE = "HaiND from the Post and Telecommunication Institute of Technology"
__version__ = "0.1.0"
__author__ = SIGNATURE

__all__ = ["SIGNATURE", "__version__", "__author__"]
