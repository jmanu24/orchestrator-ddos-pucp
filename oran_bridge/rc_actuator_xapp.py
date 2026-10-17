#!/usr/bin/env python3
"""O-RAN SC RIC E2SM-RC mitigation actuator xApp.

The missing half of the mobile-domain mitigation loop. The orchestrator's
telemetry/mobile_adapter.apply_mitigation() decides *what* to throttle
(it resolves the attacking UE's IMSI and writes/pushes a command); this
xApp is what actually *enforces* it on the RAN via a real E2SM-RC Control
Request, replacing the "not yet implemented" note in that adapter.

Runs inside the oran-sc-ric python_xapp_runner container, alongside
kpm_bridge_xapp.py. It exposes a tiny HTTP POST /rc endpoint that accepts
the same command shape apply_mitigation() emits:

    {"imsi": "001010123456780", "action": "block"|"unblock",
     "duration": 60, "attack_type": "UDP_FLOOD"}

and issues E2SM-RC Style 2 / Action 6 (control_slice_level_prb_quota) to
the DU E2 node serving that IMSI:

  * block   -> max_prb_ratio = THROTTLE_MAX_PRB (chokes the slice serving
               the UE, so its UL/DL collapses while the flood continues)
  * unblock -> max_prb_ratio = 100 (restores full PRB budget)

Topology facts this relies on (same as kpm_bridge_xapp.py): the RIC
registers each srsRAN DU as its own E2 node gnbd_<plmn>_<gnbid>_<du_id>,
and this lab runs exactly one UE per DU, so IMSI -> DU node is a static
map and the per-DU RRM-policy-ratio control targets exactly that one UE.

RMR note: rmr_send() must only be driven from the xApp's own thread, so
the HTTP handler just enqueues the command and start()'s loop drains the
queue and sends the control. RMR port 4560 receives RIC_CONTROL_ACK /
RIC_CONTROL_FAILURE (12041/12042 in routes.rtg); the bridge's 4561 (KPM
indications) is untouched.

Run (inside python_xapp_runner):
  python3 rc_actuator_xapp.py --api_port 8768
"""

import argparse
import json
import queue
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lib.xAppBase import xAppBase

# IMSI -> DU E2 node id. du1..du3 sit under gNB id 00019b (CU1), du4..du5
# under 000192 (CU2); the trailing _N is the gnb_du_id. Mirrors
# kpm_bridge_xapp.py's GNB_DU_ID_TO_IMSI (inverted) and topology.yaml.
IMSI_TO_E2_NODE = {
    "001010123456780": "gnbd_001_001_00019b_1",
    "001010123456790": "gnbd_001_001_00019b_2",
    "001010123456791": "gnbd_001_001_00019b_3",
    "001010123456792": "gnbd_001_001_000192_4",
    "001010123456793": "gnbd_001_001_000192_5",
}

# gNB-CU-UE-F1AP-ID that Style 2 Action 6's control header targets. With one
# UE per DU the CU assigns F1AP UE id 0 to that sole UE on each DU; override
# per-IMSI here only if a DU ever serves more than one UE.
IMSI_TO_UE_ID = {}
DEFAULT_UE_ID = 0

# E2SM-RC RAN function id (RC) as srsRAN advertises it.
RAN_FUNC_ID = 3

# PRB policy ratios. A blocked UE's slice is squeezed to THROTTLE_MAX_PRB%
# of PRBs (near-total choke for a DDoS source); unblock restores 100%.
THROTTLE_MIN_PRB = 0
THROTTLE_MAX_PRB = 1
RESTORE_MIN_PRB = 0
RESTORE_MAX_PRB = 100
DEDICATED_PRB = 100


class _State:
    """Last enforced action per IMSI, for /status and idempotent logging."""

    def __init__(self):
        self.lock = threading.Lock()
        # imsi -> {"action","e2_node","max_prb","attack_type","at"}
        self.enforced = {}

    def record(self, imsi, action, e2_node, max_prb, attack_type, src="?"):
        with self.lock:
            self.enforced[imsi] = {
                "action": action,
                "e2_node": e2_node,
                "max_prb": max_prb,
                "attack_type": attack_type,
                "requested_by": src,
                "at": time.time(),
            }

    def snapshot(self):
        with self.lock:
            return {"enforced": dict(self.enforced)}


state = _State()


def _make_handler(cmd_queue):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != "/status":
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(state.snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/rc":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                cmd = json.loads(raw or b"{}")
            except ValueError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"bad json"}')
                return

            imsi = str(cmd.get("imsi", ""))
            action = str(cmd.get("action", ""))
            if imsi not in IMSI_TO_E2_NODE or action not in ("block", "unblock"):
                self.send_response(422)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"error": "unknown imsi or action",
                     "imsi": imsi, "action": action}).encode())
                return

            # Stamp the requester so every enforced control is attributable:
            # the orchestrator's ryu-manager POSTs from 10.10.0.1, a manual
            # `docker exec ... curl localhost` from 127.0.0.1. Without this the
            # actuator log can't prove who asked for a block/unblock.
            cmd["_src"] = self.client_address[0] if self.client_address else "?"
            # Enqueue; the xApp thread performs the RMR send.
            cmd_queue.put(cmd)
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

    return Handler


class RcActuator(xAppBase):
    def __init__(self, config, http_server_port, rmr_port, api_port):
        super(RcActuator, self).__init__(config, http_server_port, rmr_port)
        self._api_port = api_port
        self._queue = queue.Queue()

    def _apply(self, cmd):
        imsi = str(cmd["imsi"])
        action = str(cmd["action"])
        e2_node = IMSI_TO_E2_NODE[imsi]
        ue_id = IMSI_TO_UE_ID.get(imsi, DEFAULT_UE_ID)
        attack_type = cmd.get("attack_type", "")

        if action == "block":
            min_prb, max_prb = THROTTLE_MIN_PRB, THROTTLE_MAX_PRB
        else:
            min_prb, max_prb = RESTORE_MIN_PRB, RESTORE_MAX_PRB

        ts = time.strftime("%H:%M:%S")
        src = cmd.get("_src", "?")
        print("{} RC {} imsi={} e2_node={} ue_id={} PRB[min={} max={}] attack={} from={}"
              .format(ts, action.upper(), imsi, e2_node, ue_id,
                      min_prb, max_prb, attack_type, src), flush=True)
        try:
            self.e2sm_rc.control_slice_level_prb_quota(
                e2_node, ue_id, min_prb, max_prb,
                dedicated_prb_ratio=DEDICATED_PRB, ack_request=1)
            state.record(imsi, action, e2_node, max_prb, attack_type, src)
        except Exception as exc:  # keep the loop alive on a bad control
            print("{} RC ERROR imsi={} e2_node={}: {}".format(
                ts, imsi, e2_node, exc), flush=True)

    @xAppBase.start_function
    def start(self):
        httpd = ThreadingHTTPServer(("0.0.0.0", self._api_port),
                                    _make_handler(self._queue))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print("rc_actuator: serving POST /rc on :{}".format(self._api_port),
              flush=True)

        while self.running:
            try:
                cmd = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._apply(cmd)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=str, default="")
    p.add_argument("--http_server_port", type=int, default=8092)
    p.add_argument("--rmr_port", type=int, default=4560)
    p.add_argument("--api_port", type=int, default=8768,
                   help="port to serve POST /rc (mitigation commands) on")
    p.add_argument("--ran_func_id", type=int, default=RAN_FUNC_ID)
    args = p.parse_args()

    xapp = RcActuator(args.config, args.http_server_port, args.rmr_port,
                      args.api_port)
    xapp.e2sm_rc.set_ran_func_id(args.ran_func_id)
    signal.signal(signal.SIGTERM, xapp.signal_handler)
    signal.signal(signal.SIGINT, xapp.signal_handler)
    xapp.start()
