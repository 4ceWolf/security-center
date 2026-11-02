import copy
import json
import pathlib
import sys
import unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'initramfs'), str(ROOT/'policies')]
import boot_observation as record
import boot_observer
BOOT = '11111111-2222-3333-4444-555555555555'


class ObservationTests(unittest.TestCase):
    def data(self):
        return boot_observer.build(b'{"schema_version":1,"internal":[],"trusted_external":[]}',
            'a'*64, BOOT, 1, 2, {'devices': [], 'errors': []},
            {'pci': [], 'thunderbolt': [], 'errors': []})

    def test_history_remains_valid_later_same_boot(self):
        data = self.data()
        self.assertEqual(record.decode(json.dumps(data).encode(), BOOT, 36000), data)
        self.assertEqual(data['unlock_method'], 'unknown')
        self.assertFalse(data['coverage_complete'])

    def test_cannot_claim_enforcement_or_unlock(self):
        for key, value in [('attested', True), ('coverage_complete', True),
                           ('observation_only', 1), ('unlock_method', 'tpm'),
                           ('enforcement', 'enabled'), ('schema_version', True)]:
            data = self.data(); data[key] = value
            with self.assertRaises(ValueError): record.validate(data, BOOT, 3)

    def test_wrong_boot_future_and_nonfinite_times(self):
        for start, end, now in [(3, 2, 4), (1, 5, 4), (-1, 2, 4),
                                (1, 7, 8), (1, float('nan'), 3), (True, 2, 3)]:
            data = self.data(); data.update(started_boottime=start, finished_boottime=end)
            with self.assertRaises(ValueError): record.validate(data, BOOT, now)
        with self.assertRaises(ValueError): record.validate(self.data(), 'bad', 3)

    def test_duplicate_and_oversized_input(self):
        with self.assertRaises(ValueError):
            record.decode(b'{"boot_id":"a","boot_id":"b"}', BOOT, 3)
        with self.assertRaises(ValueError): record.decode(b' '*65537, BOOT, 3)

    def test_deep_json_and_huge_timestamp_rejected_as_value_error(self):
        with self.assertRaises(ValueError):
            record.decode(b'['*2000+b'0'+b']'*2000, BOOT, 3)
        data=self.data();data['started_boottime']=10**400
        with self.assertRaises(ValueError):
            record.decode(json.dumps(data).encode(), BOOT, 3)

    def test_bounded_fixed_diagnostics(self):
        for key, value in [('counts', {'usb': 257, 'pci': 0, 'thunderbolt': 0}),
                           ('errors', ['arbitrary sysfs secret']), ('errors', ['usb_scan_incomplete']*2),
                           ('limitations', [])]:
            data = self.data(); data[key] = value
            with self.assertRaises(ValueError): record.validate(data, BOOT, 3)

    def test_scanner_errors_are_codes_without_raw_content(self):
        data = boot_observer.build(b'{"schema_version":1,"internal":[],"trusted_external":[]}',
            'b'*64, BOOT, 1, 2, {'devices': [], 'errors': ['private input']},
            {'pci': [], 'thunderbolt': [], 'errors': ['other input']})
        self.assertEqual(data['errors'], ['usb_scan_incomplete', 'platform_scan_incomplete'])
        self.assertNotIn('private input', json.dumps(data))

    def test_postboot_main_refuses_before_inventory(self):
        with patch.object(pathlib.Path, 'is_file', return_value=False), patch.object(boot_observer, 'publish') as publish:
            with self.assertRaises(SystemExit): boot_observer.main()
            publish.assert_not_called()

    def test_invalid_policy_refuses_publication(self):
        with self.assertRaises(ValueError):
            boot_observer.build(b'{}', 'a'*64, BOOT, 1, 2,
                {'devices': [], 'errors': []}, {'pci': [], 'thunderbolt': [], 'errors': []})

if __name__ == '__main__': unittest.main()
