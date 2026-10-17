"""
telemetry/bgp_adapter.py — BGP Peering domain adapter.

Telemetry : ingress flow records decoded from nfcapd/softflowd IPFIX
            captures (see collectors/peering_flow_collector.py).
Mitigation: BGP FlowSpec discard route, announced to r1's `flow`
            instance (github.com/hack3ric/flow -- not FRR, see
            docs/peering-plan.md §2.1) via mitigation/peering_backend.py.

is_connected() reflects whether the last collect() cycle could read the
nfcapd capture directory at all -- it does NOT confirm the BGP session
to r1 is up. Real nftables installation via `flow` IS confirmed (see
docs/peering-plan.md §2.2), but only against a standalone spike, not
yet against `br` in the VM lab; apply_mitigation()
logs this caveat explicitly rather than reporting a confirmed block.
"""
import logging
import time
from typing import List, Optional

import config.settings as settings
from collectors.peering_flow_collector import PeeringFlowCollector
from core.log_format import log_line
from core.models import MitigationAction, TelemetryEvent
from mitigation.peering_backend import PeeringBackend
from telemetry.base import DomainAdapter



class BGPPeeringAdapter(DomainAdapter):
    domain_name = "bgp"

    def __init__(
        self,
        collector: Optional[PeeringFlowCollector] = None,
        backend: Optional[PeeringBackend] = None,
        device_id: str = "r1",
        logger: Optional[logging.Logger] = None,
        clock=time.time,
        async_poll=False,
    ):
        self.collector = collector or PeeringFlowCollector()
        self.backend = backend or PeeringBackend()
        self.device_id = device_id
        self.logger = logger or logging.getLogger(__name__)
        self.clock = clock
        self._last_poll_ok = False
        self._async_poll = async_poll
        self._poll_pending = False
        self._poll_ready = None
        self._poll_started = None

    def is_connected(self) -> bool:
        return self._last_poll_ok

    def _poll_background(self):
        try:
            self._poll_ready = self.collector.poll()
            self._last_poll_ok = True
        except Exception:
            self.logger.exception("Peering asynchronous collection failed")
            self._poll_ready = []
            self._last_poll_ok = False
        finally:
            self.logger.info("Peering poll completed in %.3f seconds", self.clock()-self._poll_started)
            self._poll_pending = False

    def collect(self) -> List[TelemetryEvent]:
        if self._async_poll:
            from ryu.lib import hub
            records = self._poll_ready or []
            self._poll_ready = None
            if not self._poll_pending:
                self._poll_pending = True
                self._poll_started = self.clock()
                hub.spawn(self._poll_background)
            if not records:
                return []
            return self._events(records)
        try:
            records = self.collector.poll()
            self._last_poll_ok = True
        except OSError as exc:
            self.logger.warning("Peering flow collector failed: %s", exc)
            self._last_poll_ok = False
            return []

        return self._events(records)

    def _events(self, records):
        now = self.clock()
        return [
            TelemetryEvent(
                domain=self.domain_name,
                device_id=self.device_id,
                src_ip=record["src_ip"],
                dst_ip=record["dst_ip"],
                dst_port=record["dst_port"],
                protocol=record["protocol"],
                pps=record["pps"],
                bps=record["bps"],
                timestamp=now,
            )
            for record in records
            # softflowd captures BOTH directions of traffic on br's
            # external interface -- without this, the victim stand-in's
            # own reply traffic (e.g. the kernel's automatic ICMP "port
            # unreachable" backscatter to a UDP flood hitting a closed
            # port) gets treated as an inbound attack too. Denylist, not
            # an allowlist of the one known external peer: a DDoS
            # scenario needs spoofed traffic from many different (fake)
            # source IPs to still pass through. See
            # PEERING_CENTRAL_SERVER_IP's own comment in config/settings.py
            # for the real incident this fixes.
            if record["src_ip"] not in (
                settings.PEERING_CENTRAL_SERVER_IP,
                settings.PEERING_DIST_BR_PEERING_IP,
            )
        ]

    def apply_mitigation(self, action: MitigationAction) -> bool:
        if action.action == "bgp_flowspec_discard":
            announced = self.backend.announce(action.dst_ip, action.dst_port, action.protocol)
            if announced:
                self.logger.warning(log_line(
                    self.domain_name, "MITIGATION", "FLOWSPEC_ANNOUNCED",
                    f"destination={action.dst_ip}:{action.dst_port}/{action.protocol} "
                    f"-- BGP announcement sent to exabgp; dataplane installation on r1 "
                    f"is NOT verified (see docs/peering-plan.md spike)",
                ))
            return announced

        if action.action == "unblock":
            return self.backend.withdraw(action.dst_ip, action.dst_port, action.protocol)

        self.logger.warning(
            "Peering adapter received unsupported action=%r", action.action
        )
        return False
