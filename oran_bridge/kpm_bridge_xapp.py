#!/usr/bin/env python3
"""O-RAN SC RIC KPM bridge xApp.

Replaces the FlexRIC-based oran_bridge/kpm_telemetry_api.py after the RIC
migration (see docs). Runs inside the oran-sc-ric python_xapp_runner
container: it subscribes to every srsRAN DU E2 node for the UL radio KPM
that mobile detection needs, and re-exposes the latest per-UE sample over
a plain HTTP GET /kpm -- the exact same shape core5g's ue_telemetry_api
already polls, so nothing downstream changes except the join key (imsi,
not amf_ue_ngap_id -- see below).

Why this is so much simpler than the FlexRIC path: the O-RAN SC RIC
registers each srsRAN DU as its OWN E2 node, named gnbd_<plmn>_<gnbid>_<N>
where N is the DU's gnb_du_id. So the source node of every KPM indication
is known (xAppBase hands it to the callback as e2_agent_id), and since
this lab runs exactly one UE per DU, the DU node id identifies the UE
outright -- no ran_ue_id/f1ap correlation gymnastics, and no RIC crash on
subscribe/unsubscribe. gnb_du_id -> imsi is a static topology map (each DU
serves a fixed subscriber).

Run (inside python_xapp_runner):
  python3 kpm_bridge_xapp.py --du_nodes gnbd_001_001_00019b_1,... \
      --http_port 8767
"""

import argparse
import json
import re
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lib.xAppBase import xAppBase

# gnb_du_id (the _N suffix of the DU E2 node name) -> subscriber IMSI.
# Matches deploy/vm-lab/topology.yaml: du=1..du5=5 serve UE1..UE5.
GNB_DU_ID_TO_IMSI = {
    1: "001010123456780",
    2: "001010123456790",
    3: "001010123456791",
    4: "001010123456792",
    5: "001010123456793",
}

# UL radio KPM this bridge collects (srsRAN emits these at Report Style 1,
# E2-node level -- one UE per DU so node level == that UE). The mobile
# detector keys on RRU.PrbUsedUl + DRB.UEThpUl (see detection/engine.py).
METRICS = [
    "DRB.UEThpUl", "DRB.UEThpDl",
    "RRU.PrbUsedUl", "RRU.PrbTotUl", "RRU.PrbAvailUl",
    "DRB.RlcSduTransmittedVolumeUL", "DRB.RlcSduTransmittedVolumeDL",
    "DRB.RlcDelayUl", "DRB.AirIfDelayUl",
]

SAMPLE_TTL_S = 10.0

_DU_ID_RE = re.compile(r"_(\d+)$")


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        # imsi -> {"imsi","gnb_du_id","metrics","updated_at"}
        self.samples = {}
        self.node_count = 0

    def update(self, gnb_du_id, metrics):
        imsi = GNB_DU_ID_TO_IMSI.get(gnb_du_id)
        if imsi is None:
            return
        with self.lock:
            self.samples[imsi] = {
                "imsi": imsi,
                "gnb_du_id": gnb_du_id,
                "metrics": metrics,
                "updated_at": time.time(),
            }

    def snapshot(self):
        now = time.time()
        with self.lock:
            fresh = [s for s in self.samples.values()
                     if now - s["updated_at"] <= SAMPLE_TTL_S]
            return {
                "connected": True,
                "node_count": self.node_count,
                "samples": fresh,
            }


state = _State()


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != "/kpm":
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(state.snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


class KpmBridge(xAppBase):
    def __init__(self, config, http_server_port, rmr_port, du_nodes, api_port):
        super(KpmBridge, self).__init__(config, http_server_port, rmr_port)
        self._du_nodes = du_nodes
        self._api_port = api_port

    def _callback(self, e2_agent_id, subscription_id, indication_hdr,
                  indication_msg):
        # oran-sc-ric invokes the indication callback with exactly
        # (agent, sub, hdr, msg); the report style / ue_id are not passed
        # for Style 1, so we must not declare them as required args.
        m = _DU_ID_RE.search(e2_agent_id)
        if not m:
            return
        gnb_du_id = int(m.group(1))
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)
        metrics = {}
        for name, value in meas_data.get("measData", {}).items():
            # style-1 values are single-element lists; keep the scalar.
            if isinstance(value, list) and value:
                v = value[0]
            else:
                v = value
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            metrics[name] = v
        if metrics:
            state.update(gnb_du_id, metrics)

    @xAppBase.start_function
    def start(self):
        # Serve /kpm on our own HTTP server (xAppBase's own server is for
        # RIC REST callbacks).
        httpd = ThreadingHTTPServer(("0.0.0.0", self._api_port), _make_handler())
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        report_period = 1000
        granul_period = 1000
        state.node_count = len(self._du_nodes)
        for node in self._du_nodes:
            self.e2sm_kpm.subscribe_report_service_style_1(
                node, report_period, METRICS, granul_period, self._callback)

        while self.running:
            time.sleep(1)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=str, default="")
    p.add_argument("--http_server_port", type=int, default=8091)
    p.add_argument("--rmr_port", type=int, default=4561)
    p.add_argument("--du_nodes", type=str, required=True,
                   help="comma-separated DU E2 node ids (gnbd_...)")
    p.add_argument("--api_port", type=int, default=8767,
                   help="port to serve GET /kpm on")
    args = p.parse_args()

    xapp = KpmBridge(args.config, args.http_server_port, args.rmr_port,
                     [n for n in args.du_nodes.split(",") if n], args.api_port)
    signal.signal(signal.SIGTERM, xapp.signal_handler)
    signal.signal(signal.SIGINT, xapp.signal_handler)
    xapp.start()
