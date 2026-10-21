import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build_release.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ruri-public-rules-test-',dir=os.environ.get('RURI_RULE_TEST_TMP'))
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        shutil.copytree(ROOT/'rules',self.root/'rules')
        shutil.copy2(ROOT/'catalog.json',self.root/'catalog.json')
        shutil.copytree(ROOT/'notices',self.root/'notices')
        self.scope=patch.object(builder,'ROOT',self.root);self.scope.start();self.addCleanup(self.scope.stop)

    def build(self,version='test-1',sequence='1',extra=()):
        args=['builder','build','--output',str(self.root/'out'),'--sequence',sequence,'--version',version,
          '--revision','LOCAL_TEST_NOT_PUBLISHED','--issued-at','2026-10-21T00:00:00Z','--expires-at','2026-10-28T00:00:00Z',*map(str,extra)]
        with patch('sys.argv',args),contextlib.redirect_stdout(io.StringIO()): builder.main()
        return self.root/'out'/'releases'/version/'manifest.json'

    def test_exact_twelve_deterministic_and_no_unsigned_latest(self):
        manifest=self.build();first=manifest.read_bytes();self.build()
        self.assertEqual(manifest.read_bytes(),first)
        self.assertEqual(len(json.loads(first)['rules']),12)
        self.assertFalse((self.root/'out/latest.json').exists())

    def test_changed_content_cannot_overwrite_existing_release(self):
        manifest=self.build();first=manifest.read_bytes()
        path=self.root/'rules/libvio.json';rule=builder.read(path);rule['version']='99.0';path.write_bytes(builder.encoded(rule))
        with self.assertRaisesRegex(ValueError,'Immutable output'): self.build()
        self.assertEqual(manifest.read_bytes(),first)

    def test_sequence_and_source_version_advance(self):
        first=self.build()
        with self.assertRaisesRegex(ValueError,'sequence'): self.build('test-2','1',('--previous-manifest',first))
        path=self.root/'rules/libvio.json';rule=builder.read(path);rule['blockAds']=not rule.get('blockAds',False);path.write_bytes(builder.encoded(rule))
        with self.assertRaisesRegex(ValueError,'source version'):self.build('test-2','2',('--previous-manifest',first))
        rule['version']='99.0';path.write_bytes(builder.encoded(rule))
        self.build('test-2','2',('--previous-manifest',first))

    def test_fixed_bootstrap_defaults_do_not_follow_remote_default_changes(self):
        config=builder.read(self.root/'catalog.json')
        for entry in config['rules']:entry['defaultEnabled']=not entry['defaultEnabled']
        (self.root/'catalog.json').write_bytes(builder.encoded(config))
        output=self.root/'client'
        self.build(extra=('--client-assets',output))
        manifest=builder.read(output/'manifest.json')
        self.assertEqual([e['defaultEnabled'] for e in manifest['rules']],[True]*6+[False]*6)
        self.assertEqual(len(manifest['publisherManifestSha256']),64)

    def test_retirement_can_publish_without_silently_changing_bootstrap(self):
        config=builder.read(self.root/'catalog.json');config['rules']=[e for e in config['rules'] if e['id']!='native:moonci'];config['retired']=['native:moonci']
        (self.root/'rules/moonci.json').unlink()
        (self.root/'catalog.json').write_bytes(builder.encoded(config))
        manifest=builder.read(self.build())
        self.assertEqual(len(manifest['rules']),11);self.assertEqual(manifest['retired'],['native:moonci'])
        with self.assertRaisesRegex(ValueError,'previously validated twelve-source'):self.build(extra=('--client-assets',self.root/'client'))

    def test_duplicate_json_and_rule_path_scope_rejected(self):
        config=builder.read(self.root/'catalog.json');config['rules'][0]['file']='../outside.json'
        (self.root/'catalog.json').write_bytes(builder.encoded(config))
        with self.assertRaisesRegex(ValueError,'scope'):builder.load()
        (self.root/'bad.json').write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError,'Duplicate'):builder.read(self.root/'bad.json')

    def test_independent_release_carries_hash_bound_recipient_notices(self):
        manifest=builder.read(self.build())
        self.assertEqual(len(manifest['notices']),1)
        item=manifest['notices'][0]
        content=(self.root/'out'/item['path']).read_bytes()
        self.assertEqual(content,(ROOT/'notices/LICENSE.KazumiRules').read_bytes())
        self.assertEqual(builder.digest(content),item['sha256'])
        self.assertEqual(len(content),item['bytes'])
        # Simulated approved license input; never assigns the actual repository
        # a license or signs/publishes an artifact.
        (self.root/'LICENSE').write_text('TEST FIXTURE ONLY',encoding='utf-8')
        manifest=builder.read(self.build('test-2','2'))
        self.assertEqual([Path(n['path']).name for n in manifest['notices']],['LICENSE.KazumiRules','LICENSE'])

    def test_formal_publication_requires_owner_license_before_output_or_key_use(self):
        with patch.object(builder.subprocess,'run') as command:
            with self.assertRaisesRegex(ValueError,'owner-approved root LICENSE'):
                self.build(extra=('--key-file',self.root/'NOT_A_REAL_KEY'))
            command.assert_not_called()
        self.assertFalse((self.root/'out').exists())

    def test_first_publication_stages_only_explicit_ignored_distribution(self):
        # Reproduce the published branch inheriting main's ignored dist/.
        repo=self.root/'git-fixture';repo.mkdir()
        def git(*args):
            return subprocess.run(['git','-C',str(repo),*args],capture_output=True,check=False)
        self.assertEqual(git('init','--quiet').returncode,0)
        (repo/'.gitignore').write_text('dist/\n',encoding='utf-8')
        (repo/'dist').mkdir();(repo/'dist/rules.json').write_text('{}',encoding='utf-8')
        self.assertNotEqual(git('add','--','dist').returncode,0)
        self.assertEqual(git('add','-f','--','dist').returncode,0)
        self.assertEqual(git('diff','--cached','--name-only').stdout.decode().strip(),'dist/rules.json')
        workflow=(ROOT/'.github/workflows/publish.yml').read_text(encoding='utf-8')
        self.assertIn('git add -f -- dist',workflow)


if __name__=='__main__':unittest.main()
