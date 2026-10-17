from collections import defaultdict
from typing import Dict, List, Tuple

from core.models import CorrelatedEvent, TelemetryEvent

# Internal bucket key. (dst_ip,) in multidomain mode -- any domain's
# events toward the same destination land in the same bucket. (domain,
# dst_ip) in isolated mode -- a bucket can never hold more than one
# domain's events, so CorrelatedEvent.domains is always a singleton and
# detection/engine.py's own cross-domain checks (len(set(domains)) > 1)
# can never fire. Always a 2-tuple so correlate() has one key shape to
# unpack regardless of mode.
_BucketKey = Tuple[str, str]


class MultidomainCorrelator:
    """
    Multidomain Correlation layer.

    Aggregates TelemetryEvents from all domain adapters and groups them
    by destination IP address. When multiple network domains independently
    report traffic toward the same destination, the resulting CorrelatedEvent
    carries that multidomain context, which the Detection Engine uses to
    boost attack confidence.

    Usage (called once per monitoring cycle):

        correlator.ingest(openflow_events)
        correlator.ingest(mobile_events)
        ...
        correlated = correlator.correlate()   # clears internal buffer

    `cross_domain` (default True, the historical/only behavior before
    this flag existed) controls whether that grouping happens across
    domains at all -- see config/settings.py's
    DETECTION_CROSS_DOMAIN_CORRELATION for the full "isolated vs.
    multidomain detection" rationale this implements. False gives
    "isolated detection": each domain's own telemetry is analyzed on its
    own, never merged with another domain's, with the exact same
    downstream detection/decision code -- no CorrelatedEvent this
    produces can span more than one domain.
    """

    def __init__(self, cross_domain: bool = True):
        self.cross_domain = cross_domain
        # bucket key -> list of TelemetryEvents accumulated in current window
        self._buckets: Dict[_BucketKey, List[TelemetryEvent]] = defaultdict(list)

    def _bucket_key(self, ev: TelemetryEvent) -> _BucketKey:
        return ("*", ev.dst_ip) if self.cross_domain else (ev.domain, ev.dst_ip)

    def ingest(self, events: List[TelemetryEvent]) -> None:
        """
        Add normalized events from one domain adapter into the current window.
        """
        for ev in events:
            self._buckets[self._bucket_key(ev)].append(ev)

    def correlate(self) -> List[CorrelatedEvent]:
        """
        Aggregate all ingested events by bucket key and return
        CorrelatedEvents. Clears the internal buffer after processing.
        """
        results: List[CorrelatedEvent] = []

        for (_, dst_ip), events in self._buckets.items():

            if not events:
                continue

            total_pps = sum(e.pps for e in events)
            total_bps = sum(e.bps for e in events)

            # Unique domain names that contributed events for this
            # bucket -- always a singleton in isolated mode (cross_domain
            # =False), by construction of _bucket_key above.
            domains = list({e.domain for e in events})

            results.append(CorrelatedEvent(
                dst_ip=dst_ip,
                total_pps=total_pps,
                total_bps=total_bps,
                domains=domains,
                events=list(events),
            ))

        self._buckets.clear()
        return results
