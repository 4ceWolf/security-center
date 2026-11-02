import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'securityd'))
import telemetry as t


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc, self.sys = self.root / 'proc', self.root / 'sys'
        self.write(self.proc / 'sys/kernel/random/boot_id', 'test-boot')
        self.write(self.proc / 'stat', 'cpu 100 0 100 800 0 0 0 0 100 0\ncpu0 100 0 100 800 0 0 0 0')
        self.write(self.proc / 'meminfo', 'MemTotal: 1000 kB\nMemAvailable: 600 kB\nSwapTotal: 100 kB\nSwapFree: 50 kB')
        self.write(self.proc / 'loadavg', '1 2 3 1/2 3')
        self.write(self.proc / 'net/dev', 'header\nheader\n eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0')
        self.write(self.sys / 'class/net/eth0/ifindex', '1')
        self.write(self.proc / 'diskstats', '8 0 sda 0 0 100 0 0 0 200 0 0 100 0')
        self.bat = self.sys / 'class/power_supply/BAT0'
        for field, value in {'type':'Battery', 'status':'Discharging', 'capacity':'60', 'power_now':'7000000', 'energy_full':'30000000', 'energy_full_design':'40000000'}.items():
            self.write(self.bat / field, value)
        self.write(self.sys / 'class/hwmon/hwmon0/name', 'coretemp')
        self.write(self.sys / 'class/hwmon/hwmon0/temp1_input', '45000')
        self.process(1, 100, 10)
        self.sampler = t.Sampler(self.proc, self.sys, interval=30)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def process(self, pid, ticks, start):
        fields = ['S'] + ['0'] * 21
        fields[11], fields[19], fields[21] = str(ticks), str(start), '10'
        self.write(self.proc / str(pid) / 'stat', f'{pid} (test with )) ' + ' '.join(fields))
        self.write(self.proc / str(pid) / 'cmdline', 'SECRET_ARGUMENT')
        self.write(self.proc / str(pid) / 'environ', 'SECRET_ENV')

    def sample(self, mono=100, boot_time=None):
        with patch.object(t.time, 'monotonic', return_value=mono), patch.object(t.time, 'clock_gettime', return_value=mono if boot_time is None else boot_time):
            return self.sampler.sample()

    def test_first_sample_has_gauges_but_no_rates_or_secrets(self):
        sample = self.sample()
        self.assertIsNone(sample['interval_seconds'])
        self.assertEqual(sample['metrics']['battery.BAT0.discharge_w'], 7)
        self.assertEqual(sample['metrics']['battery.BAT0.health_percent'], 75)
        self.assertEqual(sample['metrics']['memory.used_bytes'], 400 * 1024)
        self.assertEqual(sample['metrics']['sensor.hwmon0.coretemp.temp1_input_c'], 45)
        self.assertNotIn('SECRET', json.dumps(sample))
        self.assertEqual(sample['top_cpu'], [])

    def test_cpu_guest_not_double_counted_and_process_rate(self):
        self.sample()
        self.write(self.proc / 'stat', 'cpu 200 0 100 900 0 0 0 0 200 0')
        self.process(1, 100 + 30 * self.sampler.hz, 10)
        sample = self.sample(130)
        self.assertEqual(sample['metrics']['cpu.cpu.busy_percent'], 50)
        self.assertEqual(sample['top_cpu'][0]['cpu_percent_one_core'], 100)

    def test_pid_reuse_gets_no_cpu_rate(self):
        self.sample()
        self.process(1, 100000, 11)
        self.assertEqual(self.sample(130)['top_cpu'], [])

    def test_suspend_and_long_gap_suppress_rates(self):
        self.sample()
        self.assertIsNone(self.sample(130, 230)['interval_seconds'])
        self.assertIsNone(self.sample(330, 430)['interval_seconds'])

    def test_changed_boot_suppresses_rates(self):
        self.sample()
        self.write(self.proc / 'sys/kernel/random/boot_id', 'new-boot')
        self.assertIsNone(self.sample(130)['interval_seconds'])

    def test_counter_decrease_suppresses_network_rate(self):
        self.sample()
        self.write(self.proc / 'net/dev', 'h\nh\n eth0: 50 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0')
        self.assertNotIn('network.eth0.rx_bytes_s', self.sample(130)['metrics'])

    def test_network_identity_change_suppresses_rate(self):
        self.sample()
        self.write(self.sys / 'class/net/eth0/ifindex', '2')
        self.assertNotIn('network.eth0.rx_bytes_s', self.sample(130)['metrics'])

    def test_charge_power_is_not_discharge(self):
        self.write(self.bat / 'status', 'Charging')
        metrics = self.sample()['metrics']
        self.assertNotIn('battery.BAT0.discharge_w', metrics)
        self.assertEqual(metrics['battery.BAT0.charge_w'], 7)

    def test_current_voltage_fallback(self):
        (self.bat / 'power_now').unlink()
        self.write(self.bat / 'current_now', '1000000')
        self.write(self.bat / 'voltage_now', '8000000')
        self.assertEqual(self.sample()['metrics']['battery.BAT0.discharge_w'], 8)

    def test_missing_source_does_not_zero_fill(self):
        (self.proc / 'meminfo').unlink()
        sample = self.sample()
        self.assertNotIn('memory.used_bytes', sample['metrics'])
        self.assertIn('memory: unavailable or malformed', sample['issues'])

    def test_process_enumeration_is_bounded(self):
        self.process(2, 10, 20)
        with patch.object(t, 'MAX_PROCESSES', 1):
            sample = self.sample()
        self.assertEqual(sample['processes_observed'], 1)
        self.assertIn('processes: enumeration truncated', sample['issues'])

    def test_store_survives_reopen_and_keeps_means_peaks(self):
        path = self.root / 'private/data.sqlite'
        one = self.sample()
        one['timestamp'] = 100000
        two = copy.deepcopy(one)
        two['timestamp'] += 30
        two['metrics']['battery.BAT0.discharge_w'] = 9
        store = t.Store(path)
        store.append(one)
        store.append(two)
        store.close()
        store = t.Store(path)
        self.addCleanup(store.close)
        summary = json.loads(store.db.execute('SELECT payload FROM hourly').fetchone()[0])
        watts = summary['metrics']['battery.BAT0.discharge_w']
        self.assertEqual(watts, {'count':2, 'sum':16, 'min':7, 'max':9})
        self.assertEqual(summary['rate_samples'], 0)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertLessEqual(store.db.execute('PRAGMA max_page_count').fetchone()[0] * store.db.execute('PRAGMA page_size').fetchone()[0], 64 * 1024 * 1024)

    def test_retention_age_and_row_bounds_with_backward_clock(self):
        store = t.Store(self.root / 'private/data.sqlite')
        self.addCleanup(store.close)
        sample = self.sample()
        with patch.object(t, 'RAW_ROWS', 3), patch.object(t, 'HOUR_ROWS', 2):
            for stamp in (100000, 200000, 199000, 198000, 197000):
                sample['timestamp'] = stamp
                store.append(sample)
        self.assertLessEqual(store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 3)
        self.assertLessEqual(store.db.execute('SELECT count(*) FROM hourly').fetchone()[0], 2)
        self.assertEqual(store.db.execute('SELECT count(*) FROM samples WHERE timestamp=100000').fetchone()[0], 0)

    def test_private_directory_and_no_symlink(self):
        unsafe = self.root / 'unsafe'
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaises(ValueError):
            t.Store(unsafe / 'db')
        private = self.root / 'private'
        private.mkdir(mode=0o700)
        (private / 'db').symlink_to(self.root / 'other')
        with self.assertRaises(OSError):
            t.Store(private / 'db')

    def test_bad_sample_transaction_leaves_existing_data(self):
        store = t.Store(self.root / 'private/data.sqlite')
        self.addCleanup(store.close)
        sample = self.sample()
        store.append(sample)
        sample['metrics']['bad'] = float('nan')
        with self.assertRaises(ValueError):
            store.append(sample)
        self.assertEqual(store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 1)

    def test_database_full_preserves_previous_transaction(self):
        store = t.Store(self.root / 'private/data.sqlite')
        self.addCleanup(store.close)
        sample = self.sample()
        store.append(sample)
        pages = store.db.execute('PRAGMA page_count').fetchone()[0]
        store.db.execute('PRAGMA max_page_count=%d' % pages)
        sample['issues'] = ['x' * 60000]
        with self.assertRaises(sqlite3.OperationalError):
            store.append(sample)
        self.assertEqual(store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 1)
        self.assertEqual(store.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_hourly_mixed_boots_are_explicit(self):
        store = t.Store(self.root / 'private/data.sqlite')
        self.addCleanup(store.close)
        sample = self.sample()
        store.append(sample)
        sample['boot_id'] = 'second-boot'
        store.append(sample)
        summary = json.loads(store.db.execute('SELECT payload FROM hourly').fetchone()[0])
        self.assertTrue(summary['mixed_boots'])
        self.assertEqual(len(summary['boot_ids']), 2)


if __name__ == '__main__':
    unittest.main()
