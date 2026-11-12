from .base import Adapter, register_adapter, get_adapter, available
from . import agentdojo  # noqa: F401  (registers the "agentdojo" adapter on import)

__all__ = ["Adapter", "register_adapter", "get_adapter", "available"]
