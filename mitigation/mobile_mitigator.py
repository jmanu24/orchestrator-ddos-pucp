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
from core.experiment_audit import emit as audit_emit
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
        #
        # A successful POST (no exception, i.e. the actuator xApp accepted
        # the HTTP request) is the closest thing this domain has to a
        # dataplane-installation confirmation distinct from "we queued a
        # command" -- it means the E2SM-RC Control Request genuinely
        # reached and was accepted by the actuator process, not merely
        # written to a JSONL file nothing may ever read. It does NOT
        # confirm the DU actually applied the PRB quota over the radio
        # interface (no E2 Control Acknowledge readback exists here) --
        # response_metrics.py's tI (HE3, tesis Tabla 3.6) should be read
        # accordingly for this domain. Queue-only mode (no actuator URL
        # configured) has no live backend to confirm against at all, so
        # no event is emitted and tI stays 'not_observable', same as today.
        if self.rc_actuator_url and self._push_to_actuator(command):
            audit_emit(
                self._logger, 'mitigation_installed',
                domain=self.domain_name,
                action=dict(
                    imsi=action.imsi, src_ip=action.src_ip, dst_ip=action.dst_ip,
                    dst_port=action.dst_port, protocol=action.protocol,
                ),
            )

        # No print here -- OrchestrationController already reports this
        # action through the same MITIGATION dashboard/logger line every
        # other domain's actions go through (ryu_controller_2.py's
        # _run_pipeline), so a second, differently-formatted message here
        # would just be noise.
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _push_to_actuator(self, command: dict) -> bool:
        data = json.dumps(command).encode()
        req = urllib.request.Request(
            self.rc_actuator_url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(
                req, timeout=settings.MOBILE_RC_ACTUATOR_TIMEOUT_S).close()
            return True
        except (urllib.error.URLError, OSError) as exc:
            self._logger.warning(log_line(
                "mobile", "MITIGATION", "RC_PUSH_FAILED",
                f"imsi={command.get('imsi')} action={command.get('action')} "
                f"url={self.rc_actuator_url} err={exc}",
            ))
            return False
