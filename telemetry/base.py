from abc import ABC, abstractmethod
from typing import List

from core.models import TelemetryEvent, MitigationAction


class DomainAdapter(ABC):
    """
    Abstract base class for all network domain adapters.

    Each domain (OpenFlow/SDN, Mobile/O-RAN, Fixed Broadband,
    Enterprise Services, BGP Peering) implements this interface to:
      - Provide normalized TelemetryEvents to the Correlation layer.
      - Receive and apply MitigationActions from the Orchestration layer.
    """

    domain_name: str = "unknown"

    @abstractmethod
    def collect(self) -> List[TelemetryEvent]:
        """
        Return normalized telemetry events accumulated since the last call.
        Called periodically by the monitoring loop.
        """
        ...

    @abstractmethod
    def apply_mitigation(self, action: MitigationAction) -> bool:
        """
        Apply a mitigation action dispatched by the Orchestration layer.
        Returns True if the action was applied successfully.
        """
        ...

    def is_connected(self) -> bool:
        """Returns True if the domain endpoint is reachable."""
        return True
