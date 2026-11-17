"""agent-shield: audit a codebase for what an AI reverse-engineering agent
can extract — secrets, internal endpoints, architecture leaks."""

__version__ = "1.0.0"

from .scan import Finding, redact_tree, scan_tree, score

__all__ = ["Finding", "redact_tree", "scan_tree", "score", "__version__"]
