import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
from gate_record import validate
from unlock_dispatch import unlock

BOOT = '11111111-2222-3333-4444-555555555555'
POLICY = 'a'*64


class GateRecordTests(unittest.TestCase):
    def setUp(self):
        self.context = dict(boot_id=BOOT, policy_sha256=POLICY, mode='normal',
                            now=10., checker_ok=True)
        self.record = dict(schema_version=1, boot_id=BOOT, policy_sha256=POLICY,
                           mode='normal', sampled_boottime=9., checker_complete=True,
                           coverage_complete=True, decision=dict(allow_tpm_attempt=True,
                           manual_recovery_required=False, reason='Reviewed fixture'))

    def check(self, record=None, raw=None, **context):
        return validate(json.dumps(record or self.record).encode() if raw is None else raw,
                        **dict(self.context, **context))

    def test_current_exact_record(self):
        self.assertTrue(self.check()['allow_tpm_attempt'])

    def test_wrong_context(self):
        for context in (dict(boot_id=BOOT.replace('11111111', '22222222')),
                        dict(policy_sha256='b'*64), dict(mode='distress'),
                        dict(checker_ok=False), dict(checker_ok=1)):
            with self.subTest(context=context), self.assertRaises(ValueError):
                self.check(**context)

    def test_invalid_records_always_dispatch_manual(self):
        changes = [dict(sampled_boottime=v) for v in (-1, 0, 11, True, float('nan'), float('inf'))]
        changes += [dict(coverage_complete=False), dict(checker_complete=False),
                    dict(checker_complete=1), dict(schema_version=True), dict(extra=1)]
        for change in changes:
            record = dict(self.record, **change)
            calls = []
            result = unlock(lambda: self.check(record),
                            lambda: calls.append('tpm'), lambda: True)
            self.assertEqual(calls, [], change)
            self.assertEqual(result['method'], 'manual')

    def test_invalid_encoding_or_duplicate_fields(self):
        raw = json.dumps(self.record)
        for bad in (b'', b'\xff', b'[]', b'{}', b' '*8193, raw[:-1].encode(),
                    raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1').encode(),
                    raw.replace('"reason":', '"reason":"duplicate", "reason":').encode()):
            with self.subTest(raw=bad[:40]), self.assertRaises(ValueError):
                self.check(raw=bad)

    def test_distress_and_incomplete_coverage_can_only_deny(self):
        for mode in ('normal', 'distress'):
            r = copy.deepcopy(self.record)
            r.update(mode=mode, coverage_complete=False)
            r['decision'].update(allow_tpm_attempt=False, manual_recovery_required=True)
            self.assertFalse(self.check(r, mode=mode)['allow_tpm_attempt'])

    def test_strict_decision(self):
        for change in (dict(allow_tpm_attempt=1), dict(manual_recovery_required=True),
                       dict(reason=''), dict(reason='x'*257), dict(extra=True)):
            r = copy.deepcopy(self.record)
            r['decision'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(r)


if __name__ == '__main__':
    unittest.main()
