import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'securityd'))
import telemetry_health as h
import history


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.value = dict(schema=1,state='recording',boot_id='boot',interval_seconds=30,
                          updated_boottime=100,samples_written=3,consecutive_failures=0,last_success_boottime=99)

    def test_fresh_recording_is_not_security_attestation(self):
        result = h.interpret(self.value, 'boot', 110)
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(result['details']['fresh'])

    def test_old_other_boot_future_records_are_stale(self):
        for boot, now in [('other', 110), ('boot', 200), ('boot', 90)]:
            self.assertEqual(h.interpret(self.value, boot, now)['status'], 'attention')

    def test_stop_and_failure_need_attention(self):
        for state in ('degraded','stopped'):
            self.value['state'] = state
            self.assertEqual(h.interpret(self.value, 'boot', 110)['status'], 'attention')

    def test_invalid_fields_rejected(self):
        for key, value in [('interval_seconds',float('nan')),('samples_written',True),('last_success_boottime',101),('state','made-up')]:
            bad = dict(self.value, **{key:value})
            with self.assertRaises(ValueError):
                h.interpret(bad, 'boot', 110)

    def test_missing_and_unsafe_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'health.json'
            with patch.object(h, 'HEALTH', str(path)):
                self.assertEqual(h.configuration()['status'], 'unknown')
                path.write_text(json.dumps(self.value))
                path.chmod(0o644)
                self.assertEqual(h.configuration()['status'], 'unavailable')
                path.unlink()
                path.symlink_to('/dev/null')
                self.assertEqual(h.configuration()['status'], 'unavailable')

    def test_full_private_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'health.json'
            value = dict(self.value, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            path.write_text(json.dumps(value)); path.chmod(0o600)
            with patch.object(h, 'HEALTH', str(path)), patch.object(h.time, 'clock_gettime', return_value=110):
                self.assertEqual(h.configuration()['summary'], 'Telemetry recording reported')

    def test_history_ignores_sample_count_churn(self):
        one = dict(h.interpret(self.value, 'boot', 110), id='telemetry')
        two = copy.deepcopy(one)
        two['details']['samples_this_run'] += 1
        self.assertEqual(history.fingerprint(one), history.fingerprint(two))
        self.value['state'] = 'degraded'
        bad = dict(h.interpret(self.value, 'boot', 110), id='telemetry')
        self.assertNotEqual(history.fingerprint(one), history.fingerprint(bad))


if __name__ == '__main__':
    unittest.main()
