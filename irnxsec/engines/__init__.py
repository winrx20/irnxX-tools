"""Engine registry.

Engines are imported lazily so an installation without the optional ``dnspython``
package can still run web and network assessments (and vice versa).
"""

from __future__ import annotations

from typing import Callable

KINDS = ("web", "network", "dns")

_MODULES = {"web": "webscan", "network": "net", "dns": "dns"}


def get_engine(kind: str) -> Callable:
    """Return the ``run(request, result)`` entry point for a scan kind."""
    import importlib

    key = (kind or "web").lower()
    module_name = _MODULES.get(key)
    if not module_name:
        raise ValueError(f"Unsupported scan kind '{kind}'. Choose one of: {', '.join(KINDS)}.")
    module = importlib.import_module(f".{module_name}", __name__)
    return module.run


class _LazyEngines(dict):
    """Mapping-compatible registry that resolves engines on first access."""

    def __contains__(self, key) -> bool:
        return (key or "").lower() in _MODULES

    def __getitem__(self, key):
        return get_engine(key)

    def get(self, key, default=None):
        try:
            return get_engine(key)
        except ValueError:
            return default

    def keys(self):
        return list(KINDS)

    def __iter__(self):
        return iter(KINDS)

    def __len__(self) -> int:
        return len(KINDS)


ENGINES = _LazyEngines()

__all__ = ["ENGINES", "KINDS", "get_engine"]
