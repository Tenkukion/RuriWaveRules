import base64
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('replacement',Path(__file__).parents[1]/'tools/replace_client_trust.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class TrustReplacementTests(unittest.TestCase):
    # Published RFC8032 public key; no publisher credentials.
    key=base64.b64encode(bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')).decode()
    original={'schema':1,'trustRevision':3,'baseUrl':'https://example.invalid/rules/','keys':{'retired':'old'}}

    def test_replaces_not_merges_old_keys(self):
        result=module.replacement(self.original,{'approved':self.key},4)
        self.assertEqual(result['keys'],{'approved':self.key})
        self.assertEqual(result['trustRevision'],4)
        self.assertEqual(self.original['keys'],{'retired':'old'})

    def test_revision_key_and_endpoint_fail_closed(self):
        for revision in (2,3,5):
            with self.assertRaises(ValueError): module.replacement(self.original,{'new':self.key},revision)
        for keys in ({},{'bad/id':self.key},{'new':'not a public key'}):
            with self.assertRaises(ValueError): module.replacement(self.original,keys,4)
        for url in ('http://example.invalid/','https://user@example.invalid/','https://example.invalid/a?x=1'):
            with self.assertRaises(ValueError): module.replacement(self.original,{'new':self.key},4,url)


if __name__=='__main__': unittest.main()
