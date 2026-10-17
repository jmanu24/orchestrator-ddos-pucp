"""
collectors/peering_flow_collector.py — ingress flow telemetry for the BGP
Peering domain.

softflowd (on `br`, sniffing the real external-facing interface) exports
NetFlow v9/IPFIX directly to nfcapd, which writes rotated binary capture
files to PEERING_NFCAPD_DIR (see config/settings.py). This collector
never speaks the wire protocol itself -- it shells out to `nfdump`
(same suite as nfcapd) to decode each new capture file into per-flow CSV
records, the same "read via the vendor's own tool" pattern the rest of
this project uses instead of reimplementing
IPFIX/NetFlow decoding here.

See docs/peering-plan.md for the FlowSpec-dataplane-support spike --
this telemetry path does NOT depend on it and works independently of
whether mitigation/peering_backend.py's announcements actually get
installed by r1's FRR.

nfcapd ALWAYS runs on the same host as this collector (wherever the
controller runs -- `orchestrator` in the VM lab) -- softflowd is configured to export its
NetFlow stream THERE directly (settings.orchestrator_addr in
deploy/vm-lab/ansible/roles/br's softflowd-peering.service.j2, instead
of the 127.0.0.1 it used to point at when nfcapd ran alongside it on
`br`). That earlier remote-nfcapd-plus-SSH design was an artifact kept
past its usefulness: NetFlow export is UDP fire-and-
forget and already meant to be pointed at wherever the collector lives,
so redirecting the export is strictly simpler than polling a remote
host's disk over SSH for files this collector never needed to be
remote from in the first place. Confirmed on a real run: the SSH round
trip this replaced was the dominant cost of this domain's real pipeline
cycle time (~0.5s per call, at least once per COLLECT_INTERVAL), which
directly inflated how long UNBLOCK_CONFIRM_CYCLES took in wall-clock
time before a FlowSpec route got withdrawn.
"""
import csv
import io
import logging
import os
import subprocess
from typing import Dict, List, Optional

from eventlet import tpool

import config.settings as settings

_PROTO_NAMES = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}


def _proto_name(raw_proto: str, raw_flags: str = "") -> str:
    """
    A bare SYN (SYN set, ACK not set -- a flood/half-open connection
    attempt, as opposed to a normal established-connection packet) needs
    its own "TCP_SYN" tag, not generic "TCP": detection/engine.py's
    _PROTOCOL_CHECKS filters on protocol == "TCP_SYN" specifically for
    its SYN_FLOOD threshold, the same distinction
    telemetry/openflow_adapter.py's own packet-in path already makes
    (is_bare_syn = SYN set and not ACK set). Without this, a real SYN
    flood observed by this domain's own telemetry (confirmed via
    softflowd/nfcapd capturing it) would never classify as SYN_FLOOD --
    it would just be generic "TCP", invisible to that check, and (since
    this domain's own destination is rarely shared with another domain's
    telemetry, so there's usually no second source to fall back to)
    invisible to the distributed-flood fallback too.

    nfdump's `flg` column is a fixed-width 8-character string, one
    column per flag in order CWR,ECE,URG,ACK,PSH,RST,SYN,FIN ('.' where
    unset) -- confirmed against real captures on the VM: "......S." for
    a bare SYN, "...A.R.." for its ACK+RST reply.
    """
    raw_proto = (raw_proto or "").strip().upper()
    if raw_proto == "TCP":
        flags = (raw_flags or "").strip()
        if len(flags) == 8 and flags[6] == "S" and flags[3] != "A":
            return "TCP_SYN"
        return "TCP"
    return _PROTO_NAMES.get(raw_proto, raw_proto or "IP")


class PeeringFlowCollector:
    """
    Polls PEERING_NFCAPD_DIR for capture files not yet processed, decodes
    each with `nfdump -o csv`, and returns new per-flow records since the
    last call.

    nfcapd never writes a file under its permanent nfcapd.<timestamp>
    name directly -- it always writes to nfcapd.current.<pid> first, and
    only renames it to that permanent name once a rotation interval is
    fully closed (confirmed on the VM: an nfcapd killed with SIGKILL
    leaves an orphaned nfcapd.current.<pid> file behind forever, sitting
    right alongside normally-completed nfcapd.<timestamp> ones -- see
    docs/peering-plan.md §2.3). So a file is safe to read the moment it
    stops being named nfcapd.current.* -- no need to ALSO wait for a
    subsequent rotation to exist before trusting it, which earlier cost
    a full extra rotation interval of detection latency for nothing
    (that was this class's original design, based on the wrong
    assumption that the lexicographically-last nfcapd.* name was always
    the in-progress one).
    """

    def __init__(
        self,
        capture_dir: Optional[str] = None,
        nfdump_bin: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.capture_dir = capture_dir or settings.PEERING_NFCAPD_DIR
        self.nfdump_bin = nfdump_bin or settings.PEERING_NFDUMP_BIN
        self.logger = logger or logging.getLogger(__name__)
        # Seed with whatever's already on disk -- "tail -f" semantics, not
        # "read everything ever captured". Without this, a fresh controller
        # start replays hours-old capture files from an unrelated earlier
        # test session as if they were a live attack: confirmed on the VM,
        # where a stray nfcapd file from an earlier validate_peering.py run
        # fired a real (bogus) BGP_FLOWSPEC_DISCARD mitigation attempt the
        # moment ryu-manager booted, before the topology (and thus flow/
        # exabgp) even existed to receive it.
        #
        # None (not an empty set) when this initial listing fails --
        # confirmed on a real run: the capture dir can genuinely not
        # exist yet this early (nfcapd hasn't created it right at
        # controller startup), and treating that failure as "the
        # directory is empty" silently adopted an EMPTY baseline, so the
        # very next successful poll() saw every real (days-old, fully
        # legitimate) capture file as "new" and replayed the entire
        # backlog through nfdump -- observed taking ~6.5 hours, during
        # which every domain's own telemetry was starved behind it (see
        # poll()'s own comment for the rest of that story). poll()
        # checks for this sentinel and defers establishing the real
        # baseline to its own first successful listing instead.
        existing = self._existing_files()
        self._processed_files = set(existing) if existing is not None else None

    @staticmethod
    def _is_complete(fname: str) -> bool:
        return fname.startswith("nfcapd.") and not fname.startswith("nfcapd.current.")

    def _list_capture_dir(self) -> Optional[List[str]]:
        """Filenames only, complete or not -- caller filters with
        _is_complete(). Returns None (NOT []) on failure -- callers must
        not treat "directory doesn't exist yet" the same as "directory
        is genuinely empty", see __init__'s own comment on why that
        distinction matters."""
        try:
            return os.listdir(self.capture_dir)
        except OSError:
            return None

    def _existing_files(self) -> Optional[List[str]]:
        entries = self._list_capture_dir()
        if entries is None:
            return None
        return [f for f in entries if self._is_complete(f)]

    def poll(self) -> List[Dict]:
        """Return flow records from every unread, fully-written capture file."""
        if not self.capture_dir or not os.path.isdir(self.capture_dir):
            return []

        entries = self._list_capture_dir()
        if entries is None:
            return []  # capture dir not readable this tick -- try again next time
        files = sorted(f for f in entries if self._is_complete(f))

        if self._processed_files is None:
            # __init__'s own seeding attempt failed (see its comment) --
            # this is the first listing that's actually succeeded, so
            # treat everything currently on disk as the baseline instead
            # of "new" (it predates this collector even being able to
            # see it) rather than replaying a potentially large,
            # unrelated backlog through nfdump.
            self._processed_files = set(files)
            return []

        if not files:
            return []

        new_files = [f for f in files if f not in self._processed_files]

        records: List[Dict] = []
        for fname in new_files:
            records.extend(self._decode_file(fname))
            self._processed_files.add(fname)

        # nfcapd itself deletes files past its retention window, so this
        # set only needs to outlive that window, not grow forever.
        if len(self._processed_files) > 10000:
            self._processed_files = set(new_files[-1000:])

        return records

    def _decode_file(self, fname: str) -> List[Dict]:
        """fname is just the basename (see poll()) -- joined against
        self.capture_dir here.

        tpool.execute() wraps _run_and_parse() -- the WHOLE thing,
        subprocess.run() AND _parse_csv(), not just the subprocess call.
        Confirmed on a real run (py-spy dump against a live ryu-manager,
        caught mid-stall): with only the subprocess call wrapped, csv.
        DictReader's own row-by-row iteration inside _parse_csv() still
        ran directly in the MAIN greenthread's call stack after
        tpool.execute() returned -- pure CPU-bound Python bytecode that
        doesn't yield back to eventlet's hub at all while it runs, found
        active in the main thread in ~25% of one-second py-spy samples
        taken during a live test. That's long enough for Ryu's own
        OpenFlow echo-reply handling (a separate greenthread, but one
        that still needs the hub to actually run it) to miss `pe`'s
        inactivity-probe deadline and disconnect -- confirmed the
        dominant cause of this domain's Td/Tr variance (some runs ~2s,
        others 80-90s+, entirely explained by whether a poll cycle
        happened to catch a backlog of several unprocessed capture
        files at once, per this method's own timeout comment below).
        Passing self._parse_csv as part of the SAME tpool call keeps
        both the process wait AND the parsing off the main thread --
        only the final list of dicts crosses back."""
        path = f"{self.capture_dir.rstrip('/')}/{fname}"
        try:
            return tpool.execute(self._run_and_parse, path)
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.warning("nfdump failed on %s: %s", path, exc)
            return []

    def _run_and_parse(self, path: str) -> List[Dict]:
        """Runs entirely inside a tpool worker thread -- see
        _decode_file()'s own comment for why both halves need to.

        Do not aggregate here. nfdump 1.7 clears the `flg` column when
        `-A srcip,dstip,proto,dstport` is used (observed `......S.` in the
        raw record and `........` after aggregation). That silently turns a
        bare SYN into generic TCP and prevents SYN_FLOOD classification.
        The statistical runner uses hping3 --keep so TCP and UDP each stay
        in one 5-tuple and remain cheap to decode without losing flags."""
        result = subprocess.run(
            [self.nfdump_bin, "-r", path, "-o", "csv"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        return self._parse_csv(result.stdout)

    @staticmethod
    def _parse_csv(output: str) -> List[Dict]:
        """
        nfdump's `-o csv` output includes its own header row -- csv.DictReader
        picks up field names from it directly rather than this module
        hardcoding a column order that varies across nfdump versions.
        Short field names used below (sa/da/dp/pr/td/ipkt/ibyt/flg) match
        nfdump 1.7.x's csv output; verify against `nfdump -o csv -c 1`
        on the deployed version if this ever stops parsing.
        """
        records = []
        for row in csv.DictReader(io.StringIO(output)):
            try:
                src_ip = row["sa"]
                dst_ip = row["da"]
                if not src_ip or not dst_ip:
                    continue
                duration_s = max(float(row["td"]), 0.001)
                packets = int(row["ipkt"])
                byte_count = int(row["ibyt"])
                records.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": int(row.get("dp") or 0),
                    "protocol": _proto_name(row.get("pr", ""), row.get("flg", "")),
                    "pps": packets / duration_s,
                    "bps": byte_count / duration_s,
                })
            except (KeyError, ValueError, TypeError):
                # TypeError specifically: nfdump's CSV output appends a
                # trailing "Summary" section (a different, shorter
                # column set) after the per-flow rows. DictReader maps
                # its short rows onto our original flow header by
                # position, so columns past the summary's own width
                # (e.g. ipkt) land as None via restval -- int(None)
                # raises TypeError, not caught by the other two. Only
                # surfaced once a capture file had real flow data ahead
                # of that trailing block to reach this far.
                continue
        return records
