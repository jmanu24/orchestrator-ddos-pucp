"""
mitigation/mobile_mitigator.py — E2SM-RC actuation backend for the Mobile
Network domain.

Pure actuation: delivers an already-decided block/unblock action to the
Near-RT RIC as a real E2SM-RC Control Request (oran_bridge/
rc_actuator_xapp.py, Style 2 / Action 6, slice-level PRB quota on the DU
E2 node serving the attacking UE). This class never resolves identity --
action.imsi must already be populated by the caller. The only caller is
telemetry/mobile_adapter.py's MobileNetworkAdapter.apply_mitigation(),
which is the one place that can resolve a src_ip back to a subscriber
(MitigationAction only ever carries the IP DDoSDetectionEngine
classified, never the imsi itself, until the adapter resolves and hands
over a copy with imsi filled in -- see MitigationAction's own docstring
in core/models.py).

Two delivery paths, both fed the same command:
  - a live HTTP POST to the actuator's /rc endpoint
    (settings.MOBILE_RC_ACTUATOR_URL) -- best-effort, short timeout, so
    an unreachable RIC never stalls the pipeline cycle;
  - an append to a JSONL command queue (one line per command), which
    the offline simulator/analysis consumers tail and which doubles as
    an audit log.
The POST is skipped (queue-only) when MOBILE_RC_ACTUATOR_URL is empty,
so this stays usable in environments with no live RIC.
"""
import json
import logging
import urllib.error
import urllib.request
from typing import Optional

import config.settings as settings
from core.log_format import log_line
from core.models import MitigationAction
from mitigation.base import MitigationAdapter

DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"


class RCMitigator(MitigationAdapter):
    """E2SM-RC actuation for the Mobile domain -- see module docstring."""

    domain_name = "mobile"

    def __init__(
        self,
        rc_command_queue_path: str = DEFAULT_RC_COMMAND_QUEUE_PATH,
        rc_actuator_url: str = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.rc_command_queue_path = rc_command_queue_path
        # None -> take the configured default; pass "" explicitly to force
        # queue-only (no live RIC push).
        self.rc_actuator_url = (
            settings.MOBILE_RC_ACTUATOR_URL if rc_actuator_url is None
            else rc_actuator_url
        )
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        # Defensive only -- the adapter is expected to gate on this
        # itself (and log IMSI_UNRESOLVED there, since resolving src_ip
        # to an imsi is a telemetry/identity concern, not an actuation
        # one). A direct caller (e.g. a test) that skips the adapter and
        # passes an unresolved action just gets a quiet no-op.
        if not action.imsi:
            return False

        command = {
            "imsi": action.imsi,
            "action": action.action,
            "duration": action.duration,
            "attack_type": action.attack_type,
        }

        with open(self.rc_command_queue_path, "a") as f:
            f.write(json.dumps(command) + "\n")

        # Live delivery to the RIC's E2SM-RC actuator. Best-effort: a failed
        # or slow POST is logged but never fails the mitigation or stalls the
        # pipeline (the command is already durably queued above, and the
        # orchestrator's hysteresis will re-issue on the next cycle if the UE
        # keeps attacking). Skipped entirely when no actuator URL is set.
        if self.rc_actuator_url:
            self._push_to_actuator(command)

        # No print here -- OrchestrationController already reports this
        # action through the same MITIGATION dashboard/logger line every
        # other domain's actions go through (ryu_controller_2.py's
        # _run_pipeline), so a second, differently-formatted message here
        # would just be noise.
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _push_to_actuator(self, command: dict) -> None:
        data = json.dumps(command).encode()
        req = urllib.request.Request(
            self.rc_actuator_url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(
                req, timeout=settings.MOBILE_RC_ACTUATOR_TIMEOUT_S).close()
        except (urllib.error.URLError, OSError) as exc:
            self._logger.warning(log_line(
                "mobile", "MITIGATION", "RC_PUSH_FAILED",
                f"imsi={command.get('imsi')} action={command.get('action')} "
                f"url={self.rc_actuator_url} err={exc}",
            ))
