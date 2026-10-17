import dataclasses
import json
import logging
import urllib.error
import urllib.request
from typing import Dict, List, Optional

import config.settings as settings
from core.log_format import log_line
from core.models import TelemetryEvent, MitigationAction
from mitigation.mobile_mitigator import RCMitigator
from telemetry.base import DomainAdapter


class MobileNetworkAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Mobile Network Domain (real
    srsRAN Project + Open5GS VM lab -- see docs/ran-testing.md).

    Built entirely on real, live testbed state.

    Telemetry (collect()): a single HTTP GET per cycle to
    oran_bridge/ue_telemetry_api.py -- a small persistent service that
    runs on core5g itself (NOT on this process), since that's the one
    place both halves of what this domain needs actually live:

      - identity (amf_ue_ngap_id -> imsi -> ip), from Open5GS's own
        AMF/SMF docker logs -- there is no live query API in Open5GS
        for this (WebUI's own REST API is subscriber CRUD against
        MongoDB only, confirmed by reading its server/routes/db.js --
        no live session state ever reaches Mongo).
      - real per-(UE ip, destination) volumetric flow data, from the
        kernel's own conntrack table on core5g -- every UE's uplink
        traffic is decapsulated onto core5g's single ogstun interface,
        so this is a real, complete, OpenFlow/enterprise-domain-
        independent view of exactly what each UE is sending where.

    This adapter itself never tails a log or opens an SSH connection --
    it only ever does a plain, cheap HTTP GET, the same shape
    telemetry/broadband_adapter.py's own _read_active_scenario() already
    uses for suscriptor's /active_scenario endpoint. ue_telemetry_api.py
    already joins the two halves above server-side, so each row it
    returns maps directly onto one TelemetryEvent.

    Mitigation (apply_mitigation()): this adapter is the only place a
    src_ip can be resolved back to the subscriber's imsi (MitigationAction
    only ever carries the IP DDoSDetectionEngine classified). It resolves
    that identity, hands a copy of the action with action.imsi filled in
    to mitigation/mobile_mitigator.py's RCMitigator, and returns False
    without delegating at all if resolution fails -- see RCMitigator's
    own module docstring for what it does with a resolved action (E2SM-RC
    Control Request delivery to the Near-RT RIC).
    """

    domain_name = "mobile"

    def __init__(
        self,
        telemetry_api_url: str = None,
        mitigator: Optional[RCMitigator] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.telemetry_api_url = telemetry_api_url or settings.MOBILE_DIST_TELEMETRY_API_URL
        self.mitigator = mitigator or RCMitigator(logger=logger)
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)

        # Tracks the last-logged connection state so collect() logs a
        # "telemetry source connected/lost" event only on the transition
        # -- not once per cycle -- the same way ryu_controller_2.py logs
        # "Switch connected" once per actual connection, not once per
        # stats-poll cycle.
        self._was_connected = False

        # ip -> imsi, refreshed from every collect() response -- the
        # only place apply_mitigation() can resolve a src_ip back to a
        # subscriber, since MitigationAction only ever carries the IP
        # DDoSDetectionEngine classified, never the imsi itself.
        self._imsi_by_ip: Dict[str, str] = {}

        # ip -> latest UL KPM dict (DRB.UEThpUl etc), refreshed from the
        # telemetry "sessions" list on every collect(). Unlike the per-flow
        # KPM (only present while a conntrack flow exists), this is
        # flow-independent: the bridge reports each UE's radio KPM every
        # period regardless of whether the UE is passing IP traffic, and
        # ue_telemetry_api joins it onto the persistent session by imsi. It
        # is what lets recovery detection see a UE's UL collapse to ~0 after
        # a real RC throttle (which kills the conntrack flow, so the UE
        # vanishes from the per-flow view entirely) -- see
        # OrchestrationController.check_mobile_unblocks.
        self._ul_kpm_by_ip: Dict[str, dict] = {}

    def is_connected(self) -> bool:
        try:
            with urllib.request.urlopen(
                self.telemetry_api_url, timeout=settings.MOBILE_DIST_TELEMETRY_API_TIMEOUT_S
            ):
                return True
        except (urllib.error.URLError, OSError, TimeoutError):
            return False

    def collect(self) -> List[TelemetryEvent]:
        # Plain HTTP GET, not SSH -- eventlet's own monkey-patching
        # (applied by ryu-manager's startup, before this module ever
        # imports) already makes plain socket/urllib I/O cooperative, so
        # this doesn't need broadband_adapter.py's tpool.execute()
        # workaround (that exists specifically for subprocess.run()'s
        # fork/exec/waitpid, which isn't covered by that patching -- see
        # that module's own _ssh() docstring). Same reasoning as
        # broadband_adapter.py's own _read_active_scenario().
        try:
            with urllib.request.urlopen(
                self.telemetry_api_url, timeout=settings.MOBILE_DIST_TELEMETRY_API_TIMEOUT_S
            ) as resp:
                body = json.loads(resp.read())
            connected = True
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            connected = False
            body = None

        if connected and not self._was_connected:
            self._logger.info(log_line(
                "mobile", "TELEMETRY", "SOURCE_CONNECTED", f"url={self.telemetry_api_url}"
            ))
        elif not connected and self._was_connected:
            self._logger.warning(log_line(
                "mobile", "TELEMETRY", "SOURCE_LOST", f"url={self.telemetry_api_url}"
            ))
        self._was_connected = connected

        if not connected:
            return []

        # Refresh the flow-independent UL-KPM view from the session list
        # (each session carries the UE's imsi + latest radio KPM even with
        # no active flow). Rebuilt each cycle so a UE that stops reporting
        # sessions drops out. Also seed _imsi_by_ip from sessions so a src
        # can be resolved to its imsi even in a cycle where it has no flow.
        ul_kpm_by_ip: Dict[str, dict] = {}
        for sess in body.get("sessions", []):
            ip = sess.get("ip")
            if not ip:
                continue
            ul_kpm_by_ip[ip] = sess.get("kpm") or {}
            if sess.get("imsi"):
                self._imsi_by_ip[ip] = sess["imsi"]
        self._ul_kpm_by_ip = ul_kpm_by_ip

        events: List[TelemetryEvent] = []
        for row in body.get("flows", []):
            event = self._row_to_event(row)
            if event is not None:
                events.append(event)
        return events

    def latest_ul_thp_ul(self, src_ip: str) -> Optional[float]:
        """Latest flow-independent UL throughput (DRB.UEThpUl, kbps) this
        UE reported via its session KPM, or None if no KPM is available for
        it (bridge down, or the UE has no live session). Used by recovery
        detection to release a throttled UE once its UL is confirmed low,
        even though the throttle has already removed it from the per-flow
        telemetry."""
        kpm = self._ul_kpm_by_ip.get(src_ip)
        if not kpm:
            return None
        val = kpm.get("DRB.UEThpUl")
        return None if val is None else float(val)

    def _row_to_event(self, row: dict) -> Optional[TelemetryEvent]:
        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        imsi = row.get("imsi") or ""
        amf_ue_ngap_id = row.get("amf_ue_ngap_id") or 0
        if imsi:
            # Refreshed on every sighting -- apply_mitigation() reads
            # this later, potentially several cycles after the UE that
            # triggered a detection last appeared here.
            self._imsi_by_ip[src_ip] = imsi

        return TelemetryEvent(
            domain=self.domain_name,
            # ue_telemetry_api derives the real 22-bit gNB id from the
            # NR Cell Identity Open5GS reports for this exact NGAP UE.
            device_id=str(row.get("gnb_id") or ""),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=row.get("dst_port", 0),
            protocol=row.get("protocol", "IP"),
            pps=row.get("pps", 0.0),
            bps=row.get("bps", 0.0),
            imsi=imsi,
            amf_ue_ngap_id=amf_ue_ngap_id,
            kpm=row.get("kpm") or {},
        )

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # The attacking UE is action.src_ip (the real source this domain
        # reported it under in collect() above). This is the only place
        # that lookup can happen -- RCMitigator is never handed a raw,
        # unresolved action.
        imsi = self._imsi_by_ip.get(action.src_ip)
        if imsi is None:
            self._logger.warning(log_line(
                "mobile", "MITIGATION", "IMSI_UNRESOLVED",
                f"src_ip={action.src_ip} (no recent telemetry row resolved this UE's imsi)",
            ))
            return False

        return self.mitigator.apply(dataclasses.replace(action, imsi=imsi))
