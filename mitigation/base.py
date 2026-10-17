from abc import ABC, abstractmethod

from core.models import MitigationAction


class MitigationAdapter(ABC):
    """
    Abstract base class for domain-specific mitigation backends.

    Each domain that can receive mitigation commands from the Orchestration
    layer implements this interface.
    """

    @abstractmethod
    def apply(self, action: MitigationAction) -> bool:
        """
        Apply a mitigation action.
        Returns True if the action was applied successfully.
        """
        ...
