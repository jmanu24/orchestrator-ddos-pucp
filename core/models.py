from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


# ---------------------------------------------------------------------------
# Stage 1 — Telemetry Collection
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """
    Normalized telemetry event produced by any domain adapter.
    Fed into the Multidomain Correlation layer.

    domain    : "enterprise" | "mobile" | "broadband" | "bgp" (displayed as "External Peering")
    device_id : switch DPID, BNG hostname, router ID, etc.
    protocol  : "TCP" | "UDP" | "ICMP" | "IP"
    pps       : packets per second
    bps       : bytes per second
    in_port   : physical switch port the traffic entered on, when known
                (only packet-in-derived events know this — flow-stats-
                derived ones leave it 0, since LearningSwitch's L3
                forwarding match doesn't carry in_port)
    flags     : optional protocol flags, e.g. {"SYN": True}
    imsi/amf_ue_ngap_id : subscriber identity for this event's src_ip,
                when the producing domain has one (mobile domain only,
                resolved from Open5GS's own AMF/SMF session state — see
                oran_bridge/ue_telemetry_api.py). Empty/None for every
                other domain, and for a mobile UE whose session hasn't
                been correlated yet.
    kpm       : latest identity-bound E2SM-KPM measurements for this UE.
                Empty for other domains or while the RIC source is stale.
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    pps: float
    bps: float
    in_port: int = 0
    flags: dict = field(default_factory=dict)
    imsi: str = ""
    amf_ue_ngap_id: int = 0
    kpm: dict = field(default_factory=dict)
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 2 — Multidomain Correlation
# ---------------------------------------------------------------------------

@dataclass
class CorrelatedEvent:
    """
    Output of the Multidomain Correlation layer.
    Groups TelemetryEvents from all domains that target the same destination.

    domains : list of domain names contributing (e.g. ["enterprise", "bgp"])
    events  : raw TelemetryEvent objects that were aggregated
    """
    dst_ip: str
    total_pps: float
    total_bps: float
    domains: List[str]
    events: List[TelemetryEvent]
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 3 — DDoS Detection Engine
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """
    Output of the DDoS Detection Engine.
    Produced when a CorrelatedEvent exceeds attack thresholds.

    attack_type : "SYN_FLOOD" | "UDP_FLOOD" | "ICMP_FLOOD" | "DDOS_DISTRIBUTED" | "MULTIDOMAIN_DISTRIBUTED_ATTACK"
    score       : raw metric ratio (observed / threshold)
    confidence  : 0.0–1.0, boosted when attack spans multiple domains
    sources     : distinct source IPs contributing — only populated for
                  DDOS_DISTRIBUTED/MULTIDOMAIN_DISTRIBUTED_ATTACK, where
                  src_ip is "*" (no single attacker)
    source_device_ids : src_ip -> that source's own device_id (e.g. real
                  gNB id for a mobile UE) — only populated alongside
                  `sources`. A mobile multi-source attack's contributing
                  UEs can each be attached to a *different* gNB, so
                  `device_id` above (one representative event's gNB) is
                  NOT a stand-in for every source's own gNB the way it is
                  for dst_port/protocol, which the attack
                  config genuinely does apply identically to the whole
                  group.
    source_domains : src_ip -> that source's own domain ("enterprise"|
                  "mobile"|"broadband") — only populated alongside
                  `sources`, same shape as source_device_ids. Lets
                  orchestration/controller.py's _build_actions() route
                  each contributing source through ITS OWN domain's real
                  mitigation mechanism instead of assuming every source
                  shares this DetectionResult's single representative
                  `domain` (correlation/correlator.py already aggregates
                  telemetry across domains toward one dst_ip, so a
                  distributed detection's sources can genuinely span
                  more than one domain -- see MULTIDOMAIN_DISTRIBUTED_
                  ATTACK).
    in_port     : ingress switch port of the representative event, when
                  known — lets mitigation scope a block to the exact
                  switch+port closest to the attacker instead of the
                  whole network
    pps/bps     : the representative event's measured rate at detection
                  time — carried through purely for observability
                  (audit records)
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    attack_type: str
    score: float
    confidence: float
    sources: List[str] = field(default_factory=list)
    source_device_ids: Dict[str, str] = field(default_factory=dict)
    source_domains: Dict[str, str] = field(default_factory=dict)
    in_port: int = 0
    pps: float = 0.0
    bps: float = 0.0
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 5 — Orchestration and Control
# ---------------------------------------------------------------------------

@dataclass
class MitigationAction:
    """
    Command issued by the Orchestration layer to a domain's mitigation backend.

    action   : "block" | "rate_limit" | "bgp_flowspec_discard"
    duration : how long the rule should stay active (seconds)
    dst_ip/dst_port/protocol : L4 5-tuple fields the mitigation backend
                               should match on (block by exact flow, not
                               just by source IP)
    sources     : when src_ip == "*" (distributed attack), the distinct
                  source IPs seen — used to clean up the per-source
                  forwarding rules that were letting them through
    attack_type : the DetectionResult.attack_type that triggered this
                  action — carried through purely for descriptive logging
    in_port     : ingress switch port closest to the attacker, when known
                  (0 if unknown, e.g. distributed attacks or flow-stats-
                  only visibility) — lets OpenFlowMitigator scope the
                  drop rule to a single switch+port instead of the whole
                  network
    pps/bps     : the triggering detection's measured rate — carried
                  through purely for observability (audit records)
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    action: str
    duration: int = 60
    sources: List[str] = field(default_factory=list)
    attack_type: str = ""
    in_port: int = 0
    pps: float = 0.0
    bps: float = 0.0
