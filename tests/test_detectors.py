import unittest

from bsa.config import Settings
from bsa.core.detectors import (
    PathVerificationDetector,
    ProcessHierarchyDetector,
    ProcessSpoofingDetector,
    ResourceBehaviorDetector,
)
from bsa.core.hash_cache import ExecutableHashCache
from bsa.core.detectors import ReputationMatcher
from bsa.core.models import ProcessSnapshot, ReputationRule
from bsa.core.path_utils import executable_is_in_directory, path_is_within


def process(**overrides):
    values = dict(
        pid=123, parent_pid=10, process_name="sample.exe",
        executable_path=r"C:\Program Files\Sample\sample.exe", parent_name="explorer.exe",
        username="tester", state="running", create_time=1000.0,
        cpu_percent=1.0, memory_bytes=1024 * 1024, memory_percent=1.0,
        thread_count=3, priority_value=32, io_read_bytes=10, io_write_bytes=20,
    )
    values.update(overrides)
    return ProcessSnapshot(**values)


class DetectorTests(unittest.TestCase):
    def test_path_prefix_does_not_match_similarly_named_directory(self):
        self.assertTrue(path_is_within(r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32"))
        self.assertFalse(path_is_within(r"C:\Windows\System32evil\svchost.exe", r"C:\Windows\System32"))

    def test_spoofing_detects_system_name_outside_expected_directory(self):
        detector = ProcessSpoofingDetector(r"C:\Windows")
        candidate = process(process_name="svchost.exe", executable_path=r"C:\Users\Public\svchost.exe")
        finding = detector.evaluate(candidate, {"rules_by_name": {}})
        self.assertIsNotNone(finding)
        self.assertEqual(finding.check_type, "PROCESS_SPOOFING")
        self.assertGreaterEqual(finding.risk_score, 95)

    def test_spoofing_does_not_flag_expected_direct_directory(self):
        detector = ProcessSpoofingDetector(r"C:\Windows")
        candidate = process(process_name="svchost.exe", executable_path=r"C:\Windows\System32\svchost.exe")
        self.assertIsNone(detector.evaluate(candidate, {"rules_by_name": {}}))

    def test_spoofing_requires_direct_parent_folder(self):
        self.assertFalse(executable_is_in_directory(r"C:\Windows\System32\sub\svchost.exe", r"C:\Windows\System32"))

    def test_generic_path_verification(self):
        detector = PathVerificationDetector()
        rule = ReputationRule(1, "sample.exe", r"C:\Program Files\Sample", None, "TRUSTED", "known app")
        candidate = process(executable_path=r"C:\Users\Public\sample.exe")
        finding = detector.evaluate(candidate, {"rules_by_name": {"sample.exe": [rule]}})
        self.assertIsNotNone(finding)
        self.assertEqual(finding.check_type, "PATH_VERIFICATION")

    def test_office_child_process_rule(self):
        detector = ProcessHierarchyDetector()
        candidate = process(process_name="powershell.exe", parent_name="WINWORD.EXE")
        finding = detector.evaluate(candidate, {"rules_by_name": {}})
        self.assertIsNotNone(finding)
        self.assertEqual(finding.check_type, "PROCESS_HIERARCHY")

    def test_resource_spike_rule(self):
        detector = ResourceBehaviorDetector(cpu_threshold=85, memory_threshold=35)
        candidate = process(cpu_percent=98.0, memory_percent=40.0)
        finding = detector.evaluate(candidate, {"rules_by_name": {}})
        self.assertIsNotNone(finding)
        self.assertEqual(finding.check_type, "RESOURCE_BEHAVIOR")


    def test_reputation_matches_configured_trusted_path(self):
        matcher = ReputationMatcher(ExecutableHashCache())
        rule = ReputationRule(1, "sample.exe", r"C:\Program Files\Sample", None, "TRUSTED", "known app")
        status, finding = matcher.classify(process(), [rule])
        self.assertEqual(status, "TRUSTED")
        self.assertIsNone(finding)

    def test_missing_path_is_unknown_not_automatically_malicious(self):
        matcher = ReputationMatcher(ExecutableHashCache())
        rule = ReputationRule(1, "sample.exe", r"C:\Program Files\Sample", None, "TRUSTED", "known app")
        status, finding = matcher.classify(process(executable_path=None), [rule])
        self.assertEqual(status, "UNKNOWN")
        self.assertIsNone(finding)

    def test_valid_wow64_system_binary_path(self):
        detector = ProcessSpoofingDetector(r"C:\Windows")
        candidate = process(process_name="svchost.exe", executable_path=r"C:\Windows\SysWOW64\svchost.exe")
        self.assertIsNone(detector.evaluate(candidate, {"rules_by_name": {}}))


if __name__ == "__main__":
    unittest.main()
