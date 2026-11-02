import pathlib
import hashlib
import copy
import stat
import subprocess
import sys
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from effective_initrd import review, compare, review_with_directory_policy, semantic
from arch_initrd_manifest import inspect
from test_initrd_manifest import archive
D = stat.S_IFDIR | 0o755
F = stat.S_IFREG | 0o644
L = stat.S_IFLNK | 0o777


def image(early, main=()):
    return archive(early) + subprocess.check_output(
        ['/usr/bin/zstd', '-q', '--stdout'], input=archive(list(main)))


@unittest.skipUnless(pathlib.Path('/usr/bin/zstd').exists(), 'Host zstd required')
class EffectiveInitrdTests(unittest.TestCase):
    def transition_fixture(self):
        raw = image([('d', stat.S_IFDIR | 0o700, b'')], [('d', D, b'')])
        manifest = inspect(raw)
        policy = {'schema_version': 1, 'image_sha256': hashlib.sha256(raw).hexdigest(),
                  'transitions': [{'path': 'd', 'segment': 1,
                      'before': semantic(manifest['segments'][0]['files']['d']),
                      'after': semantic(manifest['segments'][1]['files']['d'])}]}
        return raw, policy

    def test_explicit_directory_transition_is_exact_and_retained(self):
        raw, policy = self.transition_fixture()
        with self.assertRaises(ValueError):
            review(raw)
        result = review_with_directory_policy(raw, policy)
        self.assertFalse(result['approved'])
        self.assertEqual(result['effective']['d']['mode'], D)
        self.assertEqual(result['reviewed_directory_transitions'], policy['transitions'])
        self.assertEqual(len(result['records']), 2)

    def test_policy_cannot_transfer_to_other_image_or_metadata(self):
        raw, policy = self.transition_fixture()
        for mutation in ('digest', 'path', 'segment', 'before', 'after', 'extra', 'missing', 'null'):
            changed = copy.deepcopy(policy)
            if mutation == 'digest': changed['image_sha256'] = '0' * 64
            elif mutation == 'path': changed['transitions'][0]['path'] = 'elsewhere'
            elif mutation == 'segment': changed['transitions'][0]['segment'] = 0
            elif mutation in ('before', 'after'): changed['transitions'][0][mutation]['uid'] = 1
            elif mutation == 'extra': changed['transitions'] *= 2
            elif mutation == 'missing': changed['transitions'] = []
            else: changed['transitions'].append(None)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                review_with_directory_policy(raw, changed)

    def test_policy_cannot_authorize_payload_or_other_mode_changes(self):
        for first, second in ((F, F | 0o111), (stat.S_IFDIR | 0o700, stat.S_IFDIR | 0o777)):
            raw = image([('d', first, b'')], [('d', second, b'')])
            manifest = inspect(raw)
            policy = {'schema_version': 1, 'image_sha256': hashlib.sha256(raw).hexdigest(),
                      'transitions': [{'path': 'd', 'segment': 1,
                          'before': semantic(manifest['segments'][0]['files']['d']),
                          'after': semantic(manifest['segments'][1]['files']['d'])}]}
            with self.assertRaises(ValueError):
                review_with_directory_policy(raw, policy)

    def test_root_cannot_be_replaced(self):
        for kind, payload in ((F, b'x'), (L, b'usr')):
            with self.assertRaises(ValueError):
                review(image([('.', kind, payload)]))

    def test_arch_alias_across_segments_and_order(self):
        raw = image([('lib', L, b'usr/lib'), ('usr', D, b''), ('usr/lib', D, b'')],
                    [('lib/libc.so', F, b'library')])
        data = review(raw)
        self.assertIn('usr/lib/libc.so', data['effective'])
        self.assertEqual(data['records'][-1]['effective_path'], 'usr/lib/libc.so')
        self.assertEqual(data['records'][-1]['segment'], 1)
        self.assertFalse(data['approved'])

    def test_alias_collision_cannot_overwrite_library(self):
        base = [('usr', D, b''), ('usr/lib', D, b''), ('usr/lib/a', F, b'original'),
                ('lib', L, b'usr/lib')]
        for entry in [('lib/a', F, b'changed'), ('lib/a', F | 0o111, b'original'),
                      ('usr/lib', L, b'elsewhere')]:
            with self.assertRaises(ValueError):
                review(image(base, [entry]))

    def test_identical_repeat_retains_provenance(self):
        data = review(image([('a', F, b'x')], [('a', F, b'x')]))
        self.assertEqual(len(data['records']), 2)
        self.assertTrue(data['records'][1]['repeated'])

    def test_parents_must_exist_before_use(self):
        for base in [[], [('a', F, b'x')], [('a', L, b'missing')]]:
            with self.assertRaises(ValueError):
                review(image(base, [('a/file', F, b'x')]))
        with self.assertRaises(ValueError):
            review(image([('a/file', F, b'x'), ('a', D, b'')]))

    def test_cycle_escape_and_expansion_refused(self):
        for entries in [[('a', L, b'a')], [('a', L, b'b'), ('b', L, b'a')],
                        [('a', L, b'../escape')], [('a', L, b'/../../escape')],
                        [('a', L, b'a/child')]]:
            with self.assertRaises(ValueError):
                review(image(entries))

    def test_absolute_links_are_image_rooted_and_dangling_allowed(self):
        data = review(image([('usr', D, b''), ('usr/lib', D, b''), ('lib', L, b'/usr/lib'),
                             ('dangling', L, b'/proc/mounts')], [('lib/x', F, b'x')]))
        self.assertIn('usr/lib/x', data['effective'])

    def test_dotdot_follows_symlink_before_parent(self):
        base = [('usr', D, b''), ('usr/lib', D, b''), ('alias', L, b'usr/lib'),
                ('route', L, b'alias/..')]
        data = review(image(base, [('route/x', F, b'x')]))
        self.assertIn('usr/x', data['effective'])
        self.assertNotIn('x', data['effective'])

    def test_complete_delta_includes_directory_mode_and_removed_files(self):
        before = image([('d', D, b''), ('d/a', F, b'old'), ('removed', F, b'x')])
        after = image([('d', stat.S_IFDIR | 0o700, b''), ('d/a', F, b'new'), ('added', F, b'x')])
        delta = compare(before, after)
        self.assertEqual(delta['added'], ['added'])
        self.assertEqual(delta['removed'], ['removed'])
        self.assertEqual([v['path'] for v in delta['changed']], ['d', 'd/a'])
        self.assertFalse(delta['approved'])
        self.assertTrue(compare(before, before)['byte_identical'])


if __name__ == '__main__':
    unittest.main()
