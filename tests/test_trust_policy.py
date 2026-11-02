import copy
import json
import pathlib
import sys
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'policies'))
import trust_policy as trust
from device_gate import evaluate

class TrustPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'policies/normal-devices.candidate.json').read_text())
        self.device = copy.deepcopy(self.policy['trusted_external'][1])
        self.device['port'] = 'pci:0000:00:14.0/usb:2'
        self.inventory = {'usb_observation_complete': True, 'errors': [], 'devices': [self.device]}
        self.selected = trust.device_id(self.device)

    def test_add_exact_observed_identity_and_preserve_other_entries(self):
        proposal = trust.propose(self.policy, self.inventory, 'add', self.selected)
        result = trust.apply(self.policy, self.inventory, proposal)
        self.assertEqual(result['trusted_external'][:-1], self.policy['trusted_external'])
        self.assertEqual(result['trusted_external'][-1], self.device)
        self.assertNotEqual(trust.revision(result), proposal['base_revision'])
        inv = {'schema_version': 1, 'complete': True, 'transports_checked': ['usb','thunderbolt','pci-external'], 'devices': [self.device]}
        self.assertTrue(evaluate(inv, result)['allow_tpm_attempt'])
        self.assertFalse(evaluate(inv, result, 'distress')['allow_tpm_attempt'])

    def test_changed_port_interfaces_or_disconnect_reject_reviewed_add(self):
        proposal = trust.propose(self.policy, self.inventory, 'add', self.selected)
        for change in ('port', 'interfaces', 'disconnect'):
            inv = copy.deepcopy(self.inventory)
            if change == 'port': inv['devices'][0]['port'] += '.1'
            elif change == 'interfaces': inv['devices'][0]['interfaces'].append('03:01:01')
            else: inv['devices'] = []
            with self.assertRaises(ValueError): trust.apply(self.policy, inv, proposal)

    def test_stale_and_tampered_proposals_rejected(self):
        proposal = trust.propose(self.policy, self.inventory, 'add', self.selected)
        changed = copy.deepcopy(self.policy); changed['trusted_external'].pop(0)
        with self.assertRaises(ValueError): trust.apply(changed, self.inventory, proposal)
        for key, value in [('device', self.policy['trusted_external'][0]), ('base_revision', '0'*64), ('schema_version', True), ('extra', '')]:
            bad = copy.deepcopy(proposal); bad[key] = value
            with self.assertRaises(ValueError): trust.apply(self.policy, self.inventory, bad)

    def test_remove_disconnected_device_without_affecting_other_trust(self):
        selected = trust.device_id(self.policy['trusted_external'][1])
        proposal = trust.propose(self.policy, {}, 'remove', selected)
        result = trust.apply(self.policy, {}, proposal)
        self.assertEqual(result['trusted_external'], self.policy['trusted_external'][:1])
        with self.assertRaises(ValueError): trust.apply(result, {}, proposal)

    def test_ambiguous_or_partial_observations_cannot_add(self):
        for inv in ({}, {**self.inventory, 'errors':['unreadable']}, {**self.inventory, 'usb_observation_complete':False}, {**self.inventory, 'devices':[self.device,self.device]}):
            with self.assertRaises(ValueError): trust.propose(self.policy, inv, 'add', self.selected)

    def test_duplicate_conflict_wildcard_and_bounds_rejected(self):
        variants = []
        duplicate = copy.deepcopy(self.policy); duplicate['internal'] = duplicate['trusted_external'][:1]; variants.append(duplicate)
        for key, value in [('vendor','*'), ('interfaces',[]), ('port','*'), ('serial','bad\nserial')]:
            p = copy.deepcopy(self.policy); p['trusted_external'][0][key] = value; variants.append(p)
        p = copy.deepcopy(self.policy); p['trusted_external'] *= 129; variants.append(p)
        for p in variants:
            with self.assertRaises(ValueError): trust.validate(p)
        with self.assertRaises(ValueError): trust.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError): trust.decode(b' '* (trust.MAX_BYTES+1))

    def test_view_distinguishes_observation_from_live_policy_management(self):
        result = trust.view(self.policy, self.inventory)
        self.assertFalse(result['saved'][0]['connected'])
        self.assertEqual(result['activation']['preboot'], 'outside_scope')
        self.assertEqual(result['activation']['postboot'], 'not_managed_by_candidate_editor')
        self.assertIsNone(trust.view(self.policy, {})['saved'][0]['connected'])
        with self.assertRaises(ValueError): trust.propose(self.policy, self.inventory, 'add', trust.device_id(self.policy['trusted_external'][0]))

if __name__ == '__main__': unittest.main()
