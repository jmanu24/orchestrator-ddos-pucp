"""BroadbandAdapter blocks a subscriber at the AAA layer with a per-MAC
marker file on `bng` (FreeRADIUS answers Access-Reject to any MAC that has
one). No FreeRADIUS reload/restart is involved. Needs eventlet (run with the
venv)."""

import subprocess
import unittest
from unittest import mock

import config.settings as settings
from core.models import MitigationAction
from telemetry import broadband_adapter
from telemetry.broadband_adapter import BroadbandAdapter

DIR = "/var/lib/ddos-radius-blocked"
MAC = "02:00:00:00:00:07"


def _result(rc=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr=stderr)


class MarkerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.rc = 0

        def fake_ssh(user, host, args, timeout=10, input_text=None):
            self.calls.append((host, list(args)))
            return _result(self.rc, "boom" if self.rc else "")

        p = mock.patch.object(broadband_adapter, "_ssh", fake_ssh)
        p.start()
        self.addCleanup(p.stop)
        self.adapter = BroadbandAdapter()
        self.calls.clear()  # drop the clear-on-init call

    def test_default_directory_matches_the_role(self):
        self.assertEqual(settings.BNG_DIST_FREERADIUS_BLOCKED_DIR, DIR)

    def test_construction_clears_leftover_markers(self):
        self.calls.clear()
        BroadbandAdapter()
        self.assertEqual(len(self.calls), 1)
        host, argv = self.calls[0]
        self.assertEqual(host, settings.BNG_DIST_BNG_SSH_HOST)
        self.assertEqual(argv[:4], ["sudo", "-n", "find", DIR])
        self.assertIn("-delete", argv)
        self.assertIn("??:??:??:??:??:??", argv)  # only MAC-named files

    def test_block_creates_the_marker(self):
        self.assertTrue(self.adapter._set_mac_rejected(MAC, True))
        self.assertEqual(self.calls, [(settings.BNG_DIST_BNG_SSH_HOST,
                                       ["sudo", "-n", "touch", f"{DIR}/{MAC}"])])

    def test_unblock_removes_the_marker(self):
        self.assertTrue(self.adapter._set_mac_rejected(MAC, False))
        self.assertEqual(self.calls[0][1], ["sudo", "-n", "rm", "-f", f"{DIR}/{MAC}"])

    def test_mac_is_normalized_to_lowercase(self):
        self.adapter._set_mac_rejected("02:AB:CD:00:00:07", True)
        self.assertEqual(self.calls[0][1][-1], f"{DIR}/02:ab:cd:00:00:07")

    def test_malformed_macs_never_reach_the_remote_command(self):
        for bad in ("", None, "02:00:00:00:00", "02:00:00:00:00:07;rm -rf /", "../../etc/passwd",
                    "02:00:00:00:00:0g", " 02:00:00:00:00:07 x"):
            self.assertFalse(self.adapter._set_mac_rejected(bad, True), bad)
        self.assertEqual(self.calls, [])

    def test_ssh_failure_is_reported_not_raised(self):
        self.rc = 1
        self.assertFalse(self.adapter._set_mac_rejected(MAC, True))

        def boom(*a, **k):
            raise subprocess.TimeoutExpired("ssh", 10)
        with mock.patch.object(broadband_adapter, "_ssh", boom):
            self.assertFalse(self.adapter._set_mac_rejected(MAC, True))

    def test_block_terminates_the_session_then_marks_the_mac(self):
        self.adapter._mac_by_ip["10.20.0.41"] = MAC
        action = MitigationAction(domain="broadband", device_id="bng", src_ip="10.20.0.41",
                                  dst_ip="10.55.0.100", dst_port=80, protocol="TCP",
                                  action="block", attack_type="UDP_FLOOD")
        self.assertTrue(self.adapter.apply_mitigation(action))
        argvs = [c[1] for c in self.calls]
        self.assertEqual(argvs[0][:2], ["accel-cmd", "-p"])
        self.assertIn("terminate", argvs[0])
        self.assertEqual(argvs[1], ["sudo", "-n", "touch", f"{DIR}/{MAC}"])
        self.assertFalse(any("restart" in a or "reload" in a for argv in argvs for a in argv))

    def test_unblock_removes_the_marker_and_kicks_the_subscriber(self):
        self.adapter._mac_by_ip["10.20.0.41"] = MAC
        action = MitigationAction(domain="broadband", device_id="bng", src_ip="10.20.0.41",
                                  dst_ip="10.55.0.100", dst_port=80, protocol="TCP",
                                  action="unblock", attack_type="UDP_FLOOD")
        self.adapter.apply_mitigation(action)
        argvs = [c[1] for c in self.calls]
        self.assertIn(["sudo", "-n", "rm", "-f", f"{DIR}/{MAC}"], argvs)
        self.assertTrue(any("kick 10.20.0.41" in " ".join(a) for a in argvs))
        self.assertFalse(any("restart" in a or "reload" in a for argv in argvs for a in argv))


if __name__ == "__main__":
    unittest.main()
