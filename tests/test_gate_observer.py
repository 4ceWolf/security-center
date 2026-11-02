import json
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
from gate_observer import build

class ObserverTests(unittest.TestCase):
    def build(self, policy=None, started=1, now=2):
        return build(json.dumps(policy or dict(schema_version=1, internal=[], trusted_external=[])).encode(),
                     '11111111-2222-3333-4444-555555555555', started, now,
                     dict(devices=[], errors=[], complete=True),
                     dict(pci=[], thunderbolt=[], errors=[], observation_complete=True))

    def test_never_upgrades_observations_to_permission(self):
        decision, summary = map(json.loads, self.build())
        self.assertFalse(decision['coverage_complete'])
        self.assertFalse(decision['decision']['allow_tpm_attempt'])
        self.assertTrue(decision['decision']['manual_recovery_required'])
        self.assertTrue(summary['observation_only'])

    def test_expired_or_invalid_scan_cannot_publish(self):
        for start, now in ((1,7), (3,2), (True,2), (1,float('nan'))):
            with self.subTest(start=start, now=now), self.assertRaises(ValueError):
                self.build(started=start, now=now)

    def test_policy_malformed(self):
        for policy in (dict(schema_version=True, internal=[], trusted_external=[]),
                       dict(schema_version=1, internal=[{}], trusted_external=[]),
                       dict(schema_version=1, internal=[], trusted_external=[], extra=True)):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                self.build(policy=policy)
