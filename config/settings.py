import os

# Temporary lab measurement mode; normal detection is the default.
LAB_CALIBRATION_MODE = os.getenv("LAB_CALIBRATION_MODE", "false").lower() == "true"

# Pipeline cadence (controller/ryu_controller_2.py's _monitor loop): how
# often the full collect -> correlate -> detect -> decide -> mitigate
# pipeline runs. Lowered from 5s to get sub-second detection latency for
# the mobile-domain UE-throttle tests.
# NOTE: still >= MIN_FLOW_RATE_DT (below) so openflow's own flow-stats
# rate sampling keeps trusting its samples if/when that domain is
# exercised with real switches again.
COLLECT_INTERVAL = 0.5

SYN_THRESHOLD = 10
UDP_THRESHOLD = 200
ICMP_THRESHOLD = 150

DECISION_THRESHOLD = 1.5

# Where OrchestrationController publishes its currently-enforced blocks
# (JSON list, rewritten atomically on every change). Read from outside the
# controller process -- analysis/run_vm_lab_trials.py's mitigation_withdrawn
# probe. Empty string disables publishing.
ACTIVE_BLOCKS_STATE_PATH = "/run/ddos-controller/active_blocks.json"

# Flow priority used for mitigation drop rules (OpenFlowMitigator). Shared
# with FlowCollector so it can exclude these from polled flow stats — a
# drop rule still counts matched (dropped) packets, and if that volume got
# fed back into telemetry, the mitigation's own counters would look like a
# fresh attack and trigger a second, redundant block.
MITIGATION_DROP_PRIORITY = 100

# Priority of LearningSwitch's L3 (ipv4_src/ipv4_dst) forwarding rules, and
# of their "SYN twin": a second rule per validated pair, one priority higher,
# with the same output action but matching only BARE SYN packets (SYN set,
# ACK clear). A TCP SYN flood from a single source is otherwise invisible: the
# first packet is cached into the L3 rule and everything after it only moves
# that rule's counters, which carry no L4 information at all -- the rule
# can't say how much of its volume is SYNs. The twin's counters are exactly
# that number (forwarding/syn_twin.py). Distributed/spoofed floods don't need
# it: every spoofed source is a new pair, so each packet already reaches the
# controller (DDoSCollector tags it TCP_SYN).
FORWARDING_PRIORITY = 10
SYN_TWIN_PRIORITY = FORWARDING_PRIORITY + 1
SYN_TWIN_ENABLED = True

# Minimum elapsed time (seconds) between two samples of the same flow
# before FlowCollector trusts the resulting rate. Two OFPFlowStatsReply
# messages can land back-to-back (e.g. two switches replying close
# together, or the controller catching up after being busy) with a near-
# zero dt — dividing a normal packet_delta by that tiny dt produces a
# physically impossible rate (seen once: ~470M pps). Below this floor the
# sample is skipped rather than trusted.
# Must stay well BELOW COLLECT_INTERVAL (above), not just below it --
# flow-stats requests go out once per COLLECT_INTERVAL (_monitor's loop),
# so normal hub.sleep/processing jitter routinely makes the real dt
# between two polls land slightly under COLLECT_INTERVAL. When this was
# 0.5 and COLLECT_INTERVAL got lowered to 0.5 too (for mobile-domain
# sub-second latency), that jitter alone made FlowCollector skip a large
# fraction of openflow's flow-stats samples every cycle -- starving
# SYN_FLOOD's volumetric (flow-stats-based) detection.
MIN_FLOW_RATE_DT = 0.1

# Forced lifetime of a *validated* L3 forwarding rule (LearningSwitch),
# regardless of how continuously it's being used. Without a hard_timeout,
# a rule under continuous traffic never expires (idle_timeout keeps
# resetting), so it never triggers a fresh packet-in either — meaning
# OpenFlowAdapter's per-(src,dst) protocol/port metadata (_flow_meta),
# learned only from packet-in, can go stale for as long as the rule lives.
# E.g. a ping between two hosts caches an "ICMP" tag; if those same two
# hosts start a UDP flood minutes later, it silently reuses the cached
# rule and never refreshes that tag. This timeout forces periodic
# re-classification — matches telemetry/openflow_adapter.py's
# _FLOW_META_TTL so a rule never outlives the metadata it depends on.
VALIDATED_FLOW_HARD_TIMEOUT = 30

# Distributed / spoofed-source attack detection (IP flow entropy).
# A destination under attack from many distinct, individually-low-volume
# sources looks like an even (high-entropy) distribution of traffic across
# source IPs — the classic signature of a spoofed-source volumetric flood.
DIST_MIN_SOURCES = 5          # need at least this many distinct sources
DIST_ENTROPY_THRESHOLD = 0.7  # normalized Shannon entropy (0-1) of src distribution
DIST_PPS_THRESHOLD = 300      # aggregate pps across all sources toward one dst

# Minimum conntrack pps a mobile flow must carry to be considered the
# "carrier" of a UE's KPM-flagged attack (DDoSDetectionEngine.
# _mobile_kpm_signal): conntrack only identifies WHICH flow the UE is
# hammering, so an incidental trickle on another protocol isn't flagged.
MOBILE_KPM_MIN_CARRIER_PPS = 8.0

# Mobile (O-RAN) attack signal: the RAN's own UL E2SM-KPM, NOT conntrack.
# conntrack at the UPF only identifies WHICH flow a UE is hammering
# (dst_ip/protocol/port + imsi); whether it's an attack is decided from
# the radio layer -- an attacking UE saturates its uplink PRBs and pushes
# far more UL throughput than any legitimate app. A UE is flagged only
# when BOTH cross their threshold (AND), so a lone high-throughput burst
# or a momentary PRB spike alone doesn't trip it. Confirmed on a real
# UDP-flood run: idle UE reads PrbUsedUl~0/UEThpUl~0, a light ping
# ~1/28kbps, a flood PrbUsedUl=50 (saturated) / UEThpUl~6700kbps.
MOBILE_KPM_PRB_UL_THRESHOLD = 45          # RRU.PrbUsedUl (of ~50 max) -- near-saturation
MOBILE_KPM_THPUL_KBPS_THRESHOLD = 500     # DRB.UEThpUl kbps -- well above normal UL app rates

# Hysteresis for the mobile mitigation closed loop (avoids the throttle/
# release oscillation a single threshold causes). ACTIVATION: a UE must
# stay above the KPM thresholds above for this many CONSECUTIVE KPM
# reports before it is flagged/penalized -- filters a one-cycle PRB/thp
# spike. RECOVERY (the lower band edge): the penalty is only lifted once
# the UE's UL throughput stays below the recovery threshold (well under
# the activation one) -- the gap between the two is the hysteresis band.
# In this lab, exit is additionally gated by presence (the UE stopping
# telemetry toward the target -- see orchestration/controller.py's
# check_mobile_unblocks), which is stricter than the recovery threshold.
MOBILE_KPM_ACTIVATION_CYCLES = 3          # consecutive over-threshold reports before throttling
MOBILE_KPM_THPUL_RECOVERY_KBPS = 200      # UEThpUl kbps below which recovery counting starts

# Activation hysteresis for the enterprise (OpenFlow) domain: a detection
# toward (dst_ip, protocol) is only reported once it has been classified in
# at least ENTERPRISE_ACTIVATION_MIN_HITS pipeline cycles within the last
# ENTERPRISE_ACTIVATION_WINDOW_S seconds, so a one-cycle spike never
# triggers a block (the release half already exists: check_unblocks()).
# "k of a window", not "k consecutive": OpenFlow's provisional forwarding
# rule is torn down and reinstalled every ~2s, and the resulting negative
# counter delta makes FlowCollector skip that one sample, so a real flood
# has periodic single-cycle gaps that would reset a strict-consecutive
# counter forever. Time-based rather than cycle-based so it is unaffected
# by gaps when the pipeline isn't running (baseline/calibration). At
# COLLECT_INTERVAL=0.5s the defaults (3 hits in 3s) add ~1s to Td. Only
# detections whose contributing sources are all enterprise are delayed --
# mobile has its own KPM streak above, broadband has none yet, and
# anything involving more than one domain is reported immediately.
# MIN_HITS <= 1 disables it.
ENTERPRISE_ACTIVATION_MIN_HITS = 3
ENTERPRISE_ACTIVATION_WINDOW_S = 3.0

# Same activation hysteresis for the bgp (External Peering) domain, with
# parameters sized for ITS cadence: a detection can only be produced on a
# cycle that actually carries bgp events, and those arrive in bursts, one
# per nfcapd rotation (-t 2, deploy/vm-lab/ansible/roles/orchestrator) --
# most 0.5s cycles carry none. So "hits" here are bursts, not cycles: 2
# hits in 6s means the flood showed up in two separate capture files (>=
# ~2s apart) within three rotations, tolerating one empty or sub-threshold
# file in between. A single-burst spike never triggers a FlowSpec
# announce. Adds roughly one rotation (~2s) to Td. If nfcapd's rotation
# interval is changed, scale both values with it. MIN_HITS <= 1 disables it.
PEERING_ACTIVATION_MIN_HITS = 2
PEERING_ACTIVATION_WINDOW_S = 6.0

# Activation hysteresis for SYN floods in the mobile domain only. Mobile
# floods flagged by the KPM criterion keep their own streak
# (MOBILE_KPM_ACTIVATION_CYCLES above); a SYN flood is decided from the
# core-side connection-attempt rate instead (detection/engine.py's _classify),
# which has no streak of its own, so it gets the same "k hits in a window" as
# enterprise. Rows arrive every cycle, so 3 hits in 3s adds ~1.5s to Td.
# MIN_HITS <= 1 disables it.
MOBILE_SYN_ACTIVATION_MIN_HITS = 3
MOBILE_SYN_ACTIVATION_WINDOW_S = 3.0

# Domains whose mitigation is inherently per-source (one quarantine action
# per attacking UE/session, not one destination-wide network lever the way
# an OpenFlow drop rule is) --
# OrchestrationController's per-UE/per-session block/unblock branches
# (_build_actions, dispatch(), check_mobile_unblocks) key off this
# tuple instead of a hardcoded "mobile" string, so BroadbandAdapter's
# per-session accel-ppp sessions reuse the exact same machinery
# MobileNetworkAdapter's per-UE quarantine already validated. "bgp" joined
# this set for the same reason: BGP FlowSpec is a per-source discard route
# (one exact 5-tuple match, not a destination-wide network lever either),
# so it reuses this same per-source block/unblock machinery -- see
# docs/peering-plan.md §6 for why a hand-rolled bgp-specific tracking
# dict/check function turned out to be unnecessary.
PER_SOURCE_MITIGATION_DOMAINS = ("mobile", "broadband", "bgp")

# Domains whose block is a complete cutoff, not a throttle --
# BroadbandAdapter's session-stop kills the accel-ppp session entirely,
# so collect() produces ZERO TelemetryEvents for it until session-start.
# Confirmed on a real run: feeding that into check_mobile_unblocks's
# presence-based signal misread "no telemetry because we just blocked it"
# as "the attacker stopped", unblocking within UNBLOCK_CONFIRM_CYCLES
# regardless of whether the attack was still running -- a fast, repeating
# BLOCK/UNBLOCK/re-detect oscillation instead of one stable block for the
# duration of the attack. Domains here use a fixed wall-clock hold
# (MitigationAction.duration) instead. "bgp" is NOT in this set: its
# telemetry is captured before the block takes effect, so it releases on
# offered-load hysteresis (PEERING_RELEASE_QUIET_S below).
PRESENCE_BLIND_DOMAINS = ("broadband",)

# --- Broadband hysteresis ----------------------------------------------
# Activation: telemetry is one conntrack sample per flow every ~0.5s
# (simulation/bng_flow_api.py), and each sample counts once, so a detection
# must be seen in this many samples (window spans them with slack) before it
# is acted on.
BROADBAND_ACTIVATION_MIN_HITS = 2
BROADBAND_ACTIVATION_WINDOW_S = 4.0

# Release: a blocked subscriber's session is gone, so its flow telemetry goes
# silent; the offered load is instead the traffic its MAC still sends into
# bng's access port, counted per MAC and protocol by the netdev-ingress
# nft table roles/bng installs (BNG_DIST_OFFERED_NFT_*). The block is
# released once that rate has stayed below UNBLOCK_RATIO x the threshold
# that triggered it for BROADBAND_RELEASE_QUIET_S. If the counters can't be
# read the domain falls back to the block's fixed wall-clock duration.
BROADBAND_RELEASE_QUIET_S = 10.0
BROADBAND_OFFERED_POLL_S = 1.0
BROADBAND_OFFERED_MAX_AGE_S = 5.0
BNG_DIST_OFFERED_NFT_TABLE = "ddos_bb"
BNG_DIST_OFFERED_NFT_CHAIN = "offered"

# --- BGP Peering domain (see docs/peering-plan.md) --------------------
# Release hysteresis for FlowSpec blocks. A block is NOT held for a fixed
# wall-clock time: softflowd captures on `br`'s external interface BEFORE
# the FlowSpec/nftables rule drops the packet, so this domain's telemetry
# keeps showing the attacker's OFFERED load even while the block is fully
# effective. The block is released once that offered load (toward the
# blocked destination, same protocol/port; from the blocked source only,
# for a per-source block) has stayed below UNBLOCK_RATIO x the threshold
# that triggered it for PEERING_RELEASE_QUIET_S seconds
# (orchestration/controller.py's _bgp_offered_load_present). A fixed hold
# released a still-running attack as soon as it expired, which was
# re-detected and re-blocked (bounce); this releases only once the attack
# has actually stopped.
#
# Seconds, not pipeline cycles: nfcapd rotates every 2s and softflowd
# expires flows after ~1s (deploy/vm-lab/ansible/roles/br), so this
# domain's events arrive in bursts -- most 0.5s cycles carry none. The
# window must span several bursts (>= 3 rotations) so a gap between
# files is never mistaken for the end of the attack. Tradeoff: Tr is now
# "attack end + this window" instead of a fixed time from the block.
PEERING_RELEASE_QUIET_S = 8.0

# Directory nfcapd rotates its binary NetFlow/IPFIX capture files into,
# fed by softflowd sniffing r1's external interface. Read via `nfdump`,
# never parsed as raw wire format (collectors/peering_flow_collector.py).
PEERING_NFCAPD_DIR = "/var/cache/nfcapd/r1"
PEERING_NFDUMP_BIN = "nfdump"

# Named pipe exabgp's `api` process section reads announce/withdraw
# commands from (mitigation/peering_backend.py). exabgp itself holds the
# actual BGP session to r1's `flow` instance (github.com/hack3ric/flow)
# -- not FRR, whose own FlowSpec-to-dataplane bridge never installs the
# rule for real (see docs/peering-plan.md §2.1).
PEERING_EXABGP_FIFO = "/run/exabgp/exabgp.in"

# softflowd captures BOTH directions of traffic crossing the sniffed
# interface on `br`, so telemetry/bgp_adapter.py must not treat the
# victim stand-in's own outbound traffic (PEERING_CENTRAL_SERVER_IP) or
# br's own (PEERING_DIST_BR_PEERING_IP below) as an inbound attack --
# confirmed on the lab: a UDP flood produced a SECOND, spurious
# ATTACK_DETECTED ICMP_FLOOD with the victim misattributed as the source
# (the kernel's automatic ICMP "port unreachable" backscatter to the
# flood hitting a closed port), and a BGP_FLOWSPEC_DISCARD issued against
# the victim's own legitimate replies. Real FlowSpec is meant to stop
# traffic reaching a victim FROM an external peer, never to discard the
# router's own outbound traffic.
# A DENYLIST, not an allowlist of the one known external peer: a DDoS
# scenario sends spoofed (--rand-source) traffic with essentially none of
# it equal to the external peer's own address (peer-router, 10.30.0.2), and that must still pass
# through as legitimate external attack telemetry.
# Must match the dummy address deploy/vm-lab/ansible/roles/br's
# central-server-addr.service adds to br, and bird.conf.j2's import filter.
PEERING_CENTRAL_SERVER_IP = "10.99.0.1"

# --- BGP Peering domain: distributed VM lab (deploy/vm-lab) -----------
# `flow`/softflowd/nfcapd run as persistent systemd services on the `br`
# VM (deploy/vm-lab/ansible/roles/br), and `exabgp` as one on the host
# that runs this controller (deploy/vm-lab/ansible/roles/orchestrator).

# Detection mode -- the axis analysis/run_vm_lab_trials.py's own --mode
# does NOT control (that flag only picks the ATTACK scenario: one
# domain's source vs. one-per-domain MULTIDOMAIN_FLOOD). This is
# orthogonal: whether MultidomainCorrelator (correlation/correlator.py)
# merges telemetry across domains before detection/engine.py sees it.
#   true  (default, unchanged prior behavior) -- "multidomain detection":
#         events bucketed by dst_ip alone, so traffic toward the shared
#         victim from different domains lands in the SAME CorrelatedEvent
#         -- this is what lets detection/engine.py raise
#         MULTIDOMAIN_DISTRIBUTED_ATTACK and what the coordination this
#         thesis is actually testing depends on.
#   false -- "isolated detection": bucketed by (domain, dst_ip) instead,
#         so a CorrelatedEvent can never span more than one domain's
#         events -- each domain's FlowStatsIDS instance effectively
#         analyzes only its own telemetry, with no cross-domain boost or
#         coordinated reaction, the A/B baseline the thesis needs to
#         demonstrate correlation's actual benefit (not just that an
#         attack of either shape gets detected).
# Restarting ryu-manager picks up a changed value (see Lab.set_detection_
# mode in analysis/run_vm_lab_trials.py) -- this is a process-start
# setting, not hot-reloaded.
DETECTION_CROSS_DOMAIN_CORRELATION = os.environ.get(
    "DETECTION_CROSS_DOMAIN_CORRELATION", "true"
).lower() in ("1", "true", "yes")

# br's real address on VLAN-MGMT (deploy/vm-lab/topology.yaml) -- what
# `flow` binds its exabgp-facing listener to, and what this controller
# SSHes to. Deliberately br's MGMT address, NOT its PEERING one: this
# controller (orchestrator) has no interface on the PEERING VLAN at all
# (only br and peer-router do -- see topology.yaml), so br's PEERING
# address is simply unreachable from here.
PEERING_DIST_BR_IP = "10.10.0.3"

# br's real address on the PEERING VLAN -- NOT what flow binds to (see
# PEERING_DIST_BR_IP above), but the address actually carried on
# PEERING_DIST_BR_EXTERNAL_IFACE, the interface softflowd sniffs. So
# THIS is the one excluded from attack telemetry: br's own traffic on
# the sniffed link, not an external attacker's.
PEERING_DIST_BR_PEERING_IP = "10.30.0.1"

# br's real PEERING-facing NIC -- what softflowd sniffs. NOT guaranteed to be
# `ens192` on a different ESXi host/rebuild (see deploy/vm-lab's control-node interface-naming
# notes) -- confirm with `ip link show` on the actual VM before trusting
# this if the lab was ever rebuilt.
PEERING_DIST_BR_EXTERNAL_IFACE = "ens192"

# Non-default TCP port for the flow<->exabgp control channel (flow's own
# `-b`/exabgp's `connect`, see deploy/vm-lab/ansible/roles/br
# and roles/orchestrator). NOT 179: br also runs FRR's bgpd for the real
# eBGP session with peer-router (deploy/vm-lab/ansible/roles/br), which
# binds the standard BGP port on ALL of br's addresses by default (no
# simple per-address scoping available in FRR for the main listener) --
# flow trying to ALSO bind :179, even on a different specific address,
# fails with "Address already in use". Arbitrary otherwise; just needs
# flow's bind port and exabgp's connect port to agree.
PEERING_DIST_FLOW_PORT = 1790

# SSH target for the `br` VM -- there is no local process
# handle for flow/softflowd/nfcapd (they're systemd services on a
# different machine), so PeeringLifecycle.start()/stop() only verifies
# they're active via SSH rather than spawning/killing them, and
# collectors/peering_flow_collector.py lists/decodes nfcapd's capture
# files via SSH too (nfcapd writes them to br's own disk, not this
# host's). Must be able to SSH in non-interactively (key-based auth) --
# see deploy/vm-lab/README.md.
PEERING_DIST_BR_SSH_USER = "labadmin"
PEERING_DIST_BR_SSH_HOST = PEERING_DIST_BR_IP

# ---------------------------------------------------------------------
# Broadband domain -- distributed VM lab (see telemetry/broadband_adapter.py
# and simulation/bng_subscriber_agent.py's module docstrings for the full
# picture): `bng` runs accel-ppp (a real open-source BRAS/BNG) fronted by
# FreeRADIUS -- real per-session telemetry comes from FreeRADIUS's own
# accounting records there. `suscriptor` runs simulation/
# bng_subscriber_agent.py as a persistent systemd service, driven over
# SSH by a FIFO protocol (baseline/attack <scenario>/stop/stop_all).
# ---------------------------------------------------------------------
# suscriptor's real MGMT address (deploy/vm-lab/topology.yaml).
BNG_DIST_SUSCRIPTOR_IP = "10.10.0.9"
BNG_DIST_SUSCRIPTOR_SSH_USER = "labadmin"
BNG_DIST_SUSCRIPTOR_SSH_HOST = BNG_DIST_SUSCRIPTOR_IP

# bng's own real MGMT address (topology.yaml) -- Ubuntu template now
# (was Alpine, back when this VM only ran dnsmasq), so labadmin+sudo
# like every other Ubuntu VM in this lab, not root.
BNG_DIST_BNG_IP = "10.10.0.2"
BNG_DIST_BNG_SSH_USER = "labadmin"
BNG_DIST_BNG_SSH_HOST = BNG_DIST_BNG_IP

# victim's real VLAN_BACKBONE-facing address (shared target VM every
# domain's test scenario uses) -- simulation/bng_subscriber_agent.py's
# own target-ip. NOT victim's MGMT address anymore -- moved on explicit
# direction (docs/vlan-backbone.md): subscriber attack traffic now
# reaches victim by MASQUERADE out bng's own dedicated backbone NIC,
# through pe's OVS bridge (br-ent, OpenFlow-monitored by ryu-manager),
# landing on victim's ENT_DC interface -- not by plain L3 forwarding
# through bng straight onto victim's OOB management interface the way
# it used to. Confirmed on a real run: this is victim_ent_dc_addr in
# deploy/vm-lab's own group_vars, generated from topology.yaml's ENT_DC
# network, same address every other domain's attack traffic now
# converges on too (see docs/vlan-backbone.md's own diagram).
BNG_DIST_TARGET_IP = "10.55.0.100"

# suscriptor's control FIFO (simulation/bng_subscriber_agent.py) --
# same path/protocol simulation/bng_agent.py used.
BNG_DIST_FIFO_PATH = "/run/bng-agent/cmd"

# bng's conntrack telemetry sidecar (simulation/bng_flow_api.py, a systemd
# service on bng via roles/bng). telemetry/broadband_adapter.py's collect()
# is one plain HTTP GET per cycle: every subscriber flow with its real
# destination/protocol/port and rate, plus IP -> MAC/session. RADIUS
# accounting is NOT a telemetry source (volume per session, no L4).
# Must match the sidecar's BNG_FLOW_API_PORT.
BNG_DIST_FLOW_API_PORT = 8769
BNG_DIST_FLOW_API_URL = f"http://{BNG_DIST_BNG_IP}:{BNG_DIST_FLOW_API_PORT}/telemetry"
# A slow/unreachable bng must not stall the pipeline cycle (COLLECT_INTERVAL).
BNG_DIST_FLOW_API_TIMEOUT_S = 2

# suscriptor's own state endpoint (simulation/bng_subscriber_agent.py,
# GET /active_scenario). No longer read by the adapter; kept because the
# agent binds this port.
BNG_DIST_SUSCRIPTOR_HTTP_PORT = 8765

# accel-ppp's own CLI control port (roles/bng's accel-ppp.conf.j2 [cli]
# tcp=127.0.0.1:2000) -- used to resolve src_ip -> username/MAC for
# apply_mitigation() (`accel-cmd -p <port> show sessions`) and to
# terminate a session (`accel-cmd -p <port> terminate username <name>`).
# Reached over SSH to `bng` itself, then locally against loopback there
# (no route from orchestrator to bng's loopback, same as every other
# "control socket only exists on that VM" case in this project).
BNG_DIST_ACCEL_CMD_PORT = 2000

# Directory of per-MAC reject markers on `bng`. apply_mitigation()'s
# persistent block creates an (empty) file named after the subscriber's MAC
# here, and removes it on unblock; roles/bng's authorize{} rule (the
# mac_blocked exec module) answers Access-Reject to any Calling-Station-Id
# that has one, so a blocked subscriber's re-DHCP (accel-ppp retries this
# on its own -- session-stop/terminate alone gets silently undone) keeps
# failing auth until unblocked. Immediate, with no FreeRADIUS reload or
# restart: neither HUP nor radmin `hup files` re-reads the `users` data
# file, and a restart per block trips systemd's StartLimit (5 per 10s).
# Must match roles/bng's bng_radius_blocked_dir.
BNG_DIST_FREERADIUS_BLOCKED_DIR = "/var/lib/ddos-radius-blocked"

# ---------------------------------------------------------------------
# Mobile domain -- real srsRAN Project + Open5GS VM lab pipeline.
#
# Neither Open5GS nor FlexRIC expose a live query API for the one thing
# this domain actually needs (which UE, identified by subscriber, is
# sending how much traffic to which destination) -- that state only
# ever exists in each NF's own process memory, surfaced only via
# Open5GS's own AMF/SMF docker logs (identity: amf_ue_ngap_id -> imsi ->
# ip) and the kernel's own conntrack table on core5g (volumetric flow
# data: all UE uplink traffic is decapsulated onto core5g's single
# ogstun interface). Rather than have THIS process (orchestrator, the
# Ryu controller) tail either of those directly, oran_bridge/
# ue_telemetry_api.py runs as its own persistent local service ON
# core5g, joins the two there, and exposes one plain read-only JSON API
# -- mobile_adapter.py's collect() is then a single HTTP GET per cycle,
# the exact same shape as telemetry/broadband_adapter.py's own
# _read_active_scenario() call to suscriptor's /active_scenario.
# ---------------------------------------------------------------------
MOBILE_DIST_CORE5G_IP = "10.10.0.5"
MOBILE_DIST_TELEMETRY_API_PORT = 8766
MOBILE_DIST_TELEMETRY_API_URL = (
    f"http://{MOBILE_DIST_CORE5G_IP}:{MOBILE_DIST_TELEMETRY_API_PORT}/telemetry"
)
# Same posture as broadband_adapter.py's own SSH timeout for its HTTP
# call to suscriptor -- a slow/unreachable core5g shouldn't stall the
# whole pipeline cycle (COLLECT_INTERVAL, nominally 0.5s).
MOBILE_DIST_TELEMETRY_API_TIMEOUT_S = 2

# E2SM-RC mitigation actuator (oran_bridge/rc_actuator_xapp.py, running in
# the oran-sc-ric python_xapp_runner on the RIC). apply_mitigation() POSTs
# each block/unblock command here so it becomes a real RIC Control Request;
# empty string disables the live push (the JSONL queue is still written, so
# the simulator/audit path is unaffected). Kept short like the telemetry
# timeout so an unreachable RIC never stalls the pipeline cycle.
MOBILE_DIST_RIC_IP = "10.10.0.4"
MOBILE_RC_ACTUATOR_PORT = 8768
MOBILE_RC_ACTUATOR_URL = (
    f"http://{MOBILE_DIST_RIC_IP}:{MOBILE_RC_ACTUATOR_PORT}/rc"
)
MOBILE_RC_ACTUATOR_TIMEOUT_S = 2
