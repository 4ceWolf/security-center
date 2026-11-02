import json
import pathlib
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'securityd'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
import collector

class CollectorTests(unittest.TestCase):
    def test_tpm_secrets_never_exported(self):
        raw = {'keyslots': {'0': {}, '2': {}}, 'tokens': {'1': {
            'type': 'systemd-tpm2', 'keyslots': ['2'], 'tpm2-blob': 'TOP_SECRET',
            'tpm2-pcrs': [7], 'tpm2_pubkey_pcrs': [11],
            'tpm2_pubkey_ref': 'initrd', 'tpm2_srk': 'SECRET_SRK'}}}
        out = collector.extract_luks(raw)
        self.assertNotIn('SECRET', json.dumps(out))
        self.assertEqual(out['tokens'][0]['signed_pcrs'], [11])
        self.assertEqual(out['tokens'][0]['policy_reference'], 'initrd')
        self.assertFalse(out['manual_passphrase_tested'])

    def test_alternate_tpm_field_names(self):
        out = collector.extract_luks({'tokens': {'x': {'type': 'systemd-tpm2',
            'tpm2-hash-pcrs': [7], 'tpm2-pubkey-pcrs': [11],
            'tpm2-pubkey-ref': 'initrd'}}})
        self.assertEqual(out['tokens'][0]['direct_pcrs'], [7])
        self.assertFalse(out['manual_slot_0_present'])

    def test_module_failure_isolated(self):
        def broken(): raise TimeoutError('credential=DO_NOT_EXPOSE')
        result = collector.collect_one('test', 'Test', broken)
        self.assertEqual(result['status'], 'unavailable')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))
        with patch.dict(collector.COLLECTORS, {'broken': ('Broken', broken),
                 'ok': ('Healthy', lambda: collector.result('secure', 'OK'))}, clear=True), \
             patch.object(collector, 'timeline', side_effect=RuntimeError):
            data = collector.snapshot()
        self.assertEqual([m['status'] for m in data['modules']], ['unavailable', 'secure'])
        self.assertEqual(data['overall'], 'attention')
        self.assertEqual(data['event_status'], 'unavailable')

    def test_inactive_standard_service_does_not_override_actual_rules(self):
        actual = {'nftables': [{'chain': {'family': 'inet', 'table': 'custom', 'hook': 'input', 'policy': 'drop'}}]}
        with patch.object(collector, 'run', return_value=json.dumps(actual)):
            self.assertEqual(collector.firewall()['status'], 'secure')
        with patch.object(collector, 'run', return_value='{"nftables": []}'):
            self.assertEqual(collector.firewall()['status'], 'attention')

    def test_timeline_drops_arbitrary_message_text(self):
        entry = {'MESSAGE': 'Finished token=SECRET', 'UNIT': 'systemd-cryptsetup@root.service',
                 '__REALTIME_TIMESTAMP': '1000000', '_BOOT_ID': 'abc',
                 '__CURSOR': 'cursor-a', '_PID': '1', '_UID': '0', '_COMM': 'systemd'}
        with patch.object(collector, 'run', return_value=json.dumps(entry)):
            data = collector.timeline()
        self.assertEqual(len(data), 1)
        self.assertNotIn('SECRET', json.dumps(data))

if __name__ == '__main__': unittest.main()
