"""Advisory technique hints.

Given the mitigations, the sink findings, and a few binary signals, this layer
names the *classes* of exploitation technique an analyst would investigate, and
which mitigation gates each one. It is an educational / defensive aid: it points
at what to study, it does not build or suggest payloads.
"""

from pwnariadne.techniques.analyze import TechniqueHint, infer_techniques

__all__ = ["TechniqueHint", "infer_techniques"]
