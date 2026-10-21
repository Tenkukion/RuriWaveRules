"""Prepare public-key configuration for an independently accepted CLIENT release.

No network, private keys, key generation or direct installation into a running
client. Output is a new review artifact; the caller must explicitly replace the
client asset, run signature tests and the normal Candidate acceptance workflow.
"""
import argparse
import base64
import json
from pathlib import Path
import re


def replacement(current, keys, revision, base_url=None):
    from urllib.parse import urlsplit
    if current.get('schema') != 1 or type(current.get('trustRevision')) is not int:
        raise ValueError('Unsupported current trust configuration')
    if revision != current['trustRevision'] + 1:
        raise ValueError('Trust revision must advance exactly once')
    if not keys or len(keys) > 4:
        raise ValueError('Explicit replacement set requires 1..4 approved public keys')
    for key_id, key in keys.items():
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}', key_id):
            raise ValueError('Invalid key ID')
        if not isinstance(key, str) or len(base64.b64decode(key, validate=True)) != 32:
            raise ValueError('Expected raw Ed25519 public key, 32 bytes base64')
    url = current['baseUrl'] if base_url is None else base_url
    parsed = urlsplit(url)
    if url and (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or not parsed.path.endswith('/')):
        raise ValueError('Explicit HTTPS repository base required')
    return {'schema': 1, 'trustRevision': revision, 'baseUrl': url, 'keys': keys}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current', required=True, type=Path)
    parser.add_argument('--approved-public-keys', required=True, type=Path)
    parser.add_argument('--revision', required=True, type=int)
    parser.add_argument('--base-url')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    value = replacement(json.loads(args.current.read_text(encoding='utf-8')),
        json.loads(args.approved_public_keys.read_text(encoding='utf-8')),
        args.revision, args.base_url)
    # Never overwrite current trust or an earlier review artifact.
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        json.dump(value, out, ensure_ascii=False, separators=(',', ':'))
    print('PREPARED_PUBLIC_TRUST_REPLACEMENT_NOT_ACTIVATED')


if __name__ == '__main__':
    main()
