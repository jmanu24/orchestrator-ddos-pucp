"""_build_actions() relabels a single-domain detection MULTIDOMAIN_
DISTRIBUTED_ATTACK when another domain already has an active mitigation
against the same dst_ip (see _active_domains_for) -- but only when
DETECTION_CROSS_DOMAIN_CORRELATION is enabled. _active_blocks/
_active_mobile_blocks are process-wide state regardless of correlation
mode, so without the guard, isolated-mode (I) detections -- which are
never supposed to even know another domain exists -- could still pick up
a MULTIDOMAIN label purely from two domains' blocks overlapping in time.
The underlying mitigation action is identical either way (_action_for
maps DDOS_DISTRIBUTED and MULTIDOMAIN_DISTRIBUTED_ATTACK to the same
"block"): only the label (and its back-fill onto other active blocks) is
at stake here."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import DetectionResult
from orchestration.controller import OrchestrationController

DST = "10.55.0.100"


class FakeAdapter:
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.actions = []

    def collect(self):
        return []

    def is_connected(self):
        return True

    def apply_mitigation(self, action):
        self.actions.append(action)
        return True


def _detection(domain, src_ip, attack_type="SYN_FLOOD", protocol="TCP", dst_port=443):
    return DetectionResult(domain=domain, device_id="dev", src_ip=src_ip, dst_ip=DST,
                           dst_port=dst_port, protocol=protocol, attack_type=attack_type,
                           score=2.0, confidence=1.0)


class RelabelGuardTests(unittest.TestCase):
    def setUp(self):
        self.mobile = FakeAdapter("mobile")
        self.broadband = FakeAdapter("broadband")
        self.controller = OrchestrationController(adapters=[self.mobile, self.broadband])

    def _give_mobile_an_active_block(self):
        actions = self.controller.process([_detection("mobile", "10.45.1.7")])
        self.assertEqual(len(actions), 1)  # sanity: the setup step itself worked

    def test_relabeled_to_multidomain_when_correlation_is_enabled(self):
        with mock.patch.object(settings, "DETECTION_CROSS_DOMAIN_CORRELATION", True):
            self._give_mobile_an_active_block()
            actions = self.controller.process([_detection("broadband", "10.20.0.201")])
        self.assertEqual([a.attack_type for a in actions], ["MULTIDOMAIN_DISTRIBUTED_ATTACK"])

    def test_not_relabeled_when_correlation_is_disabled(self):
        with mock.patch.object(settings, "DETECTION_CROSS_DOMAIN_CORRELATION", False):
            self._give_mobile_an_active_block()
            actions = self.controller.process([_detection("broadband", "10.20.0.201")])
        self.assertEqual([a.attack_type for a in actions], ["SYN_FLOOD"])

    def test_the_action_itself_is_unaffected_by_the_label(self):
        # Same mitigation either way -- only the label (and the decision
        # whether to relabel it at all) is gated, never the action string.
        with mock.patch.object(settings, "DETECTION_CROSS_DOMAIN_CORRELATION", True):
            self._give_mobile_an_active_block()
            multidomain_actions = self.controller.process([_detection("broadband", "10.20.0.201")])

        controller2 = OrchestrationController(adapters=[FakeAdapter("mobile"), FakeAdapter("broadband")])
        with mock.patch.object(settings, "DETECTION_CROSS_DOMAIN_CORRELATION", False):
            controller2.process([_detection("mobile", "10.45.1.7")])
            isolated_actions = controller2.process([_detection("broadband", "10.20.0.202")])

        self.assertEqual(multidomain_actions[0].action, isolated_actions[0].action)


if __name__ == "__main__":
    unittest.main()
