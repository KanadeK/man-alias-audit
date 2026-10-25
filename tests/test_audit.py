import bz2
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from man_alias_audit import AuditError, audit

BODY = b'.TH DEMO 1\n.SH NAME\ndemo \\- example\n.SH DESCRIPTION\nExpected terminal content.\n'


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'man'
        self.root.mkdir()
        (self.root / 'man1').mkdir()
        (self.root / 'man3').mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, content=BODY):
        if isinstance(content, str):
            content = content.encode('utf-8')
        compressors = {'.gz': lambda b: gzip.compress(b, mtime=0), '.bz2': bz2.compress, '.xz': lzma.compress}
        suffix = Path(path).suffix
        if suffix in compressors:
            content = compressors[suffix](content)
        (self.root / path).write_bytes(content)

    def link(self, name, target, directory=False):
        try:
            (self.root / name).symlink_to(target, target_is_directory=directory)
        except OSError:
            self.skipTest('symlink creation unavailable')

    def entry(self, report, path):
        return next(item for item in report['results'] if item['path'] == path)


class AuditTests(Fixture):
    def test_all_supported_compression_targets(self):
        for suffix in ['', '.gz', '.bz2', '.xz']:
            with self.subTest(suffix=suffix):
                self.put('man1/base.1' + suffix)
                self.put('man1/alias.1', '.so man1/base.1\n')
                report = audit(self.root)
                self.assertTrue(report['passed'], report)
                self.assertEqual(self.entry(report, 'man1/alias.1')['terminal'], 'man1/base.1' + suffix)
                (self.root / ('man1/base.1' + suffix)).unlink()

    def test_compressed_alias_chains(self):
        self.put('man1/base.1.gz')
        self.put('man1/middle.1.bz2', '.so man1/base.1\n')
        self.put('man3/start.3.xz', '.so man1/middle.1\n')
        result = self.entry(audit(self.root), 'man3/start.3.xz')
        self.assertEqual(result['chain'], ['man3/start.3.xz', 'man1/middle.1.bz2', 'man1/base.1.gz'])

    def test_missing_target_propagates(self):
        self.put('man1/a.1', '.so man1/b.1\n')
        self.put('man1/b.1', '.so man1/gone.1\n')
        report = audit(self.root)
        self.assertFalse(report['passed'])
        self.assertEqual(report['summary']['failed'], 2)
        self.assertEqual(self.entry(report, 'man1/a.1')['chain'], ['man1/a.1', 'man1/b.1'])

    def test_cycles_and_upstream_witness(self):
        self.put('man1/a.1', '.so man1/b.1\n')
        self.put('man1/b.1', '.so man1/a.1\n')
        self.put('man1/start.1', '.so man1/a.1\n')
        result = self.entry(audit(self.root), 'man1/start.1')
        self.assertEqual(result['code'], 'cycle')
        self.assertEqual(result['chain'], ['man1/start.1', 'man1/a.1', 'man1/b.1', 'man1/a.1'])

    def test_self_cycle(self):
        self.put('man1/a.1', '.so man1/a.1\n')
        self.assertEqual(self.entry(audit(self.root), 'man1/a.1')['chain'], ['man1/a.1', 'man1/a.1'])

    def test_ambiguous_compression_is_not_guessed(self):
        self.put('man1/base.1.gz')
        self.put('man1/base.1.xz')
        self.put('man1/alias.1', '.so man1/base.1\n')
        report = audit(self.root)
        self.assertEqual(self.entry(report, 'man1/alias.1')['code'], 'ambiguous-compression')
        self.assertEqual(report['findings'][0]['code'], 'competing-variants')

    def test_exact_target_precedes_fallback_but_duplicate_policy_fails(self):
        self.put('man1/base.1')
        self.put('man1/base.1.gz')
        self.put('man1/alias.1', '.so man1/base.1\n')
        report = audit(self.root)
        self.assertEqual(self.entry(report, 'man1/alias.1')['terminal'], 'man1/base.1')
        self.assertFalse(report['passed'])

    def test_explicit_compression_target_does_not_fallback(self):
        self.put('man1/base.1.xz')
        self.put('man1/alias.1', '.so man1/base.1.gz\n')
        self.assertEqual(self.entry(audit(self.root), 'man1/alias.1')['code'], 'missing-target')

    def test_symlink_has_no_compression_fallback(self):
        self.put('man1/base.1.gz')
        self.link('man1/link.1', 'base.1')
        self.assertEqual(self.entry(audit(self.root), 'man1/link.1')['code'], 'missing-target')

    def test_symlink_relative_parent_then_roff_root(self):
        self.put('man1/base.1.gz')
        self.put('man3/middle.3', '.so man1/base.1\n')
        self.link('man1/link.1', '../man3/middle.3')
        result = self.entry(audit(self.root), 'man1/link.1')
        self.assertEqual(result['terminal'], 'man1/base.1.gz')

    def test_symlink_cycle(self):
        self.link('man1/a.1', 'b.1')
        self.link('man1/b.1', 'a.1')
        self.assertEqual(self.entry(audit(self.root), 'man1/a.1')['code'], 'cycle')

    def test_symlink_escape_and_absolute_targets(self):
        self.link('man1/a.1', '../../outside.1')
        self.link('man1/b.1', str(Path(self.temp.name) / 'outside.1'))
        report = audit(self.root)
        self.assertEqual(report['summary']['failed'], 2)
        self.assertTrue(all(item['code'] == 'unsafe-target' for item in report['results']))

    def test_linked_section_directory_is_not_followed(self):
        other = Path(self.temp.name) / 'other'
        other.mkdir()
        (other / 'secret.7').write_bytes(BODY)
        self.link('man7', other, directory=True)
        report = audit(self.root)
        self.assertEqual(report['pages'], 0)
        self.assertEqual(report['findings'][0]['code'], 'linked-section-directory')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO unavailable on this platform')
    def test_fifo_is_not_opened(self):
        os.mkfifo(self.root / 'man1/pipe.1')
        self.assertEqual(self.entry(audit(self.root), 'man1/pipe.1')['code'], 'special-or-directory-page')

    def test_directory_page_is_not_opened(self):
        (self.root / 'man1/directory.1').mkdir()
        self.assertFalse(audit(self.root)['passed'])

    def test_comments_and_crlf(self):
        self.put('man1/base.1')
        self.put('man1/alias.1', '.\\" comment\r\n\r\n.so man1/base.1 \\" trailing comment\r\n')
        self.assertTrue(audit(self.root)['passed'])

    def test_unsupported_roff_is_unverified(self):
        for value in ['.TH TITLE 1\n.so man1/base.1', '.so "man1/base.1"', '.so \\*[dynamic]',
                      '.so', "'so man1/base.1", '. so man1/base.1', '.soman1/base.1',
                      '.if 1 .so man1/base.1']:
            with self.subTest(value=value):
                self.put('man1/a.1', value)
                self.assertEqual(self.entry(audit(self.root), 'man1/a.1')['status'], 'unverified')

    def test_unsupported_compression_propagates(self):
        self.put('man1/base.1.zst', b'not decoded')
        self.put('man1/alias.1', '.so man1/base.1')
        report = audit(self.root)
        self.assertEqual(report['summary']['unverified'], 2)

    def test_utf8_empty_and_corrupt_compression(self):
        for content in [b'\xff', b'', b'.\\" only a comment\n']:
            self.put('man1/a.1', content)
            self.assertFalse(audit(self.root)['passed'])
        (self.root / 'man1/a.1').unlink()
        for suffix in ['.gz', '.bz2', '.xz']:
            path = self.root / ('man1/a.1' + suffix)
            path.write_bytes(b'corrupt')
            self.assertFalse(audit(self.root)['passed'])
            path.unlink()

    def test_truncated_and_concatenated_streams(self):
        for suffix, encode in [('.gz', gzip.compress), ('.bz2', bz2.compress), ('.xz', lzma.compress)]:
            path = self.root / ('man1/a.1' + suffix)
            for content in [encode(BODY)[:-2], encode(BODY) + encode(BODY), encode(BODY) + b'x']:
                path.write_bytes(content)
                self.assertFalse(audit(self.root)['passed'])
            path.unlink()

    def test_bounds_for_plain_and_expanded_pages(self):
        for suffix in ['', '.gz', '.bz2', '.xz']:
            self.put('man1/a.1' + suffix, b'x' * 2000)
            with patch('man_alias_audit.core.MAX_FILE', 256):
                self.assertFalse(audit(self.root)['passed'])
            (self.root / ('man1/a.1' + suffix)).unlink()

    def test_hop_limit_is_unverified(self):
        self.put('man1/a.1', '.so man1/b.1')
        self.put('man1/b.1', '.so man1/c.1')
        self.put('man1/c.1')
        with patch('man_alias_audit.core.MAX_HOPS', 2):
            self.assertEqual(self.entry(audit(self.root), 'man1/a.1')['code'], 'hop-limit')

    def test_root_based_so_and_case_sensitive_keys(self):
        self.put('man1/base.1')
        for target in ['base.1', 'man1/BASE.1']:
            self.put('man1/alias.1', '.so ' + target)
            self.assertEqual(self.entry(audit(self.root), 'man1/alias.1')['code'], 'missing-target')

    def test_unsafe_and_nonexistent_intermediate_paths(self):
        self.put('man1/base.1')
        for target in ['../../outside.1', '/usr/share/man/man1/base.1', 'C:/base.1',
                       'missing/../man1/base.1', 'man1/base.1/', 'man1/base.1/.', 'man1/base.1/../base.1']:
            self.put('man1/alias.1', '.so ' + target)
            self.assertEqual(self.entry(audit(self.root), 'man1/alias.1')['code'], 'unsafe-target')
        self.put('man1/alias.1', '.so man3/../man1/base.1')
        self.assertTrue(audit(self.root)['passed'])

    def test_ignored_files_and_locale_are_visible(self):
        self.put('man1/base.1')
        self.put('man1/readme.txt', 'ignore')
        (self.root / 'fr').mkdir()
        report = audit(self.root)
        self.assertEqual(report['ignored'], ['fr', 'man1/readme.txt'])
        self.assertEqual(report['pages'], 1)

    def test_zero_and_letter_sections(self):
        for section in ['0p', 'n', 'l', '3pm']:
            (self.root / ('man' + section)).mkdir()
            self.put(f'man{section}/base.{section}')
            self.put(f'man{section}/alias.{section}', f'.so man{section}/base.{section}')
        report = audit(self.root)
        self.assertTrue(report['passed'])
        self.assertEqual(report['aliases'], 4)

    def test_empty_root_bad_root_and_enumeration_limit(self):
        with self.assertRaises(AuditError):
            audit(self.root)
        self.put('man1/a.1')
        with self.assertRaises(AuditError):
            audit(self.root / 'man1/a.1')
        with patch('man_alias_audit.core.MAX_PAGES', 1):
            with self.assertRaises(AuditError):
                audit(self.root)

    def test_deterministic_and_read_only(self):
        self.put('man1/base.1.gz')
        self.put('man1/a.1', '.so man1/base.1')
        files = list(self.root.glob('man*/*'))
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        one = audit(self.root)
        self.assertEqual(one, audit(self.root))
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files})

    def test_cli_json_and_exit_codes(self):
        env = os.environ.copy()
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        self.put('man1/base.1')
        command = [sys.executable, '-m', 'man_alias_audit', str(self.root), '--json']
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['passed'])
        self.put('man1/a.1', '.so man1/missing.1')
        self.assertEqual(subprocess.run(command, env=env, capture_output=True).returncode, 1)
        bad = subprocess.run(command[:3] + [str(self.root / 'no')], env=env, capture_output=True)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stdout, b'')


ZSOELIM = shutil.which('zsoelim')
for location in ['/usr/libexec/man-db/zsoelim', '/usr/lib/man-db/zsoelim']:
    if not ZSOELIM and Path(location).is_file():
        ZSOELIM = location


@unittest.skipUnless(ZSOELIM, 'native man-db zsoelim unavailable')
class NativeIntegration(Fixture):
    # Inherit fixture utilities, but run only the native fixture scenario.
    def test_native_zsoelim_matches_compressed_chain(self):
        self.put('man1/base.1.gz')
        self.put('man1/middle.1', '.so man1/base.1\n')
        self.put('man3/start.3', '.so man1/middle.1\n')
        native = subprocess.run([ZSOELIM, 'man3/start.3'], cwd=self.root,
                                capture_output=True, timeout=15)
        self.assertEqual(native.returncode, 0, native.stderr)
        self.assertIn(b'Expected terminal content.', native.stdout)
        self.assertEqual(self.entry(audit(self.root), 'man3/start.3')['terminal'], 'man1/base.1.gz')


if __name__ == '__main__':
    unittest.main()
