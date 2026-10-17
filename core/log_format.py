"""
core/log_format.py — O-RAN multidomain DDoS proposal.

Standardizes every controller log message to one shape:

    [DOMAIN] MODULE: ACTION info

Timestamp and level (INFO/WARNING/ERROR) are already supplied by
logging.basicConfig's own format string (see controller/ryu_controller_2.py),
so a full line reads e.g.:

    2026-06-26 01:25:48 WARNING FlowStatsIDS [enterprise] MITIGATION: BLOCK SYN_FLOOD source=10.0.4.10 destination=10.0.2.10:80/TCP

DOMAIN is the network domain a line concerns ("enterprise", "mobile", "broadband", "bgp" -- displayed elsewhere as "External Peering"),
or "controller" for domain-agnostic infrastructure events (startup,
topology). MODULE is the pipeline stage/subsystem that produced the
line (DETECTION, MITIGATION, TELEMETRY, FORWARDING, TOPOLOGY, STARTUP,
ORCHESTRATION). ACTION is a short, code-like verb (ATTACK_DETECTED,
BLOCK, UNBLOCK, THROTTLE, SOURCE_CONNECTED, ...) -- always upper snake
case, so it reads the same whether a human is scanning the terminal or
a script is grepping/parsing it.
"""


def log_line(domain: str, module: str, action: str, info: str = "") -> str:
    line = f"[{domain}] {module}: {action}"
    return f"{line} {info}" if info else line
