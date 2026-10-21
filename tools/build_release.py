"""Data-only NativeRule release builder. No private application imports.

Signing delegates to OpenSSL Ed25519 (RFC8032), never an in-house primitive.
Ordinary validation/build does not create keys, publish, or access the network.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TOP = {'schema','id','name','version','baseUrl','allowedOrigins','search','catalog',
       'headers','verificationSelector','resolver','blockAds'}
SEARCH = {'path','method','parameters','root','items','title','reference','format','acquisition'}
CATALOG = {'root','roads','episodes','title','reference','format','subject','delimited',
           'episodeGroups','nextDataKeys','acquisition'}
FIELD = {'selector','kind','attribute','template','httpUrl'}

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

def digest(value):
    return hashlib.sha256(value).hexdigest()

def read(path):
    # Duplicate JSON keys are invalid, including signed metadata.
    def pairs(items):
        result = {}
        for k,v in items:
            if k in result: raise ValueError('Duplicate JSON key')
            result[k] = v
        return result
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs)

def check(condition, message):
    if not condition: raise ValueError(message)

def validate_rule(rule):
    check(isinstance(rule, dict) and not set(rule)-TOP, 'Unknown native contract field')
    check(rule.get('schema') == 1, 'Unsupported native schema')
    check(re.fullmatch(r'native:[a-z0-9][a-z0-9.-]{0,95}',rule.get('id','')), 'Source identity')
    check(re.fullmatch(r'\d{1,9}(?:\.\d{1,9}){0,5}',rule.get('version','')), 'Source version')
    check(isinstance(rule.get('name'), str) and 0 < len(rule['name']) < 257, 'Source name')
    def origin(url):
        u=urlsplit(url)
        check(u.scheme in ('https','http') and u.hostname and not u.username and not u.password, 'HTTP URL')
        return f'{u.scheme}://{u.netloc}'
    origins=rule.get('allowedOrigins',[])
    check(isinstance(origins,list) and 0 < len(origins) <= 16 and len(set(origins))==len(origins), 'Origins')
    check(all(origin(o)==o.rstrip('/') and urlsplit(o).path in ('','/') and not urlsplit(o).query for o in origins), 'Origin scope')
    check(origin(rule['baseUrl']) in [o.rstrip('/') for o in origins], 'Base outside scope')
    check(rule.get('resolver','browser') in ('browser','embedded'), 'Resolver')
    check(type(rule.get('blockAds',False)) is bool, 'Ad policy')
    headers=rule.get('headers',{})
    check(isinstance(headers,dict) and len({k.lower() for k in headers})==len(headers), 'Headers')
    check(all(k.lower() in ('user-agent','accept','accept-language','referer') and isinstance(v,str) and '\r' not in v and '\n' not in v for k,v in headers.items()), 'Unsupported headers')
    for kind,allowed,required in [('search',SEARCH,('path','method','parameters','root','items','title','reference')),
                                  ('catalog',CATALOG,('root','roads','episodes','title','reference'))]:
        section=rule.get(kind)
        check(isinstance(section,dict) and not set(section)-allowed and all(k in section for k in required), 'Section contract')
        check(section.get('format','html') in ('html','json'), 'Document format')
        check(section.get('acquisition','http') in ('http','browser'), 'Acquisition')
        if section.get('acquisition')=='browser': check(section.get('format','html')=='html', 'Browser format')
        for key in ('title','reference','subject'):
            if key not in section: continue
            field=section[key]
            check(isinstance(field,dict) and not set(field)-FIELD and isinstance(field.get('selector'),str), 'Extraction contract')
            check(field.get('kind') in ('text','ownText','attribute','json'), 'Extraction kind')
            check((field['kind']=='attribute')==('attribute' in field), 'Attribute contract')
            check(type(field.get('httpUrl',False)) is bool, 'Extraction URL flag')
        if kind=='search':
            check(section['method'] in ('GET','POST') and isinstance(section['parameters'],dict), 'Search method')
            check('{query}' in section['parameters'].values(), 'Bounded query')
            check(all(isinstance(v,str) and (v=='{query}' or ('{' not in v and '}' not in v)) for v in section['parameters'].values()), 'Query template')
    check(len(encoded(rule)) <= 64*1024, 'Rule size')

def load():
    config=read(ROOT/'catalog.json')
    check(config['schema']==1 and config['namespace']=='ruriwave.official', 'Repository namespace')
    check(len(config['rules']) <= 256, 'Source limit')
    rules={}; entries=[]; names=set()
    for meta in config['rules']:
        path=(ROOT/meta['file']).resolve()
        check(path.is_relative_to((ROOT/'rules').resolve()) and path.suffix=='.json', 'Rule path scope')
        rule=read(path);validate_rule(rule)
        check(rule['id']==meta['id'] and rule['id'] not in rules and rule['name'].lower() not in names,'Duplicate identity/name')
        check(type(meta['defaultEnabled']) is bool and meta['ruleSchema']==1 and 0 <= meta['minimumEngine'] <= meta['maximumEngine'], 'Compatibility/default')
        text=encoded(rule).decode('utf-8');rules[rule['id']]=text;names.add(rule['name'].lower())
        entries.append({k:meta[k] for k in ('id','defaultEnabled','ruleSchema','minimumEngine','maximumEngine')} |
                       {'name':rule['name'],'version':rule['version'],'sha256':digest(text.encode('utf-8'))})
    bootstrap=config['bootstrapIds'];retired=config['retired']
    check(len(bootstrap)==12 and len(set(bootstrap))==12 and all(k in rules or k in retired for k in bootstrap), 'Fixed twelve bootstrap')
    check(len(set(retired))==len(retired) and not set(retired)&rules.keys(), 'Retired/distributed overlap')
    check(not ({p.name for p in (ROOT/'rules').glob('*.json')} - {Path(m['file']).name for m in config['rules']}), 'Unreferenced rule file')
    return config,rules,entries

def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists(): check(path.read_bytes()==data, 'Immutable output already exists: '+str(path))
    else: path.write_bytes(data)

def release_notices(formal):
    # Explicit allowlist only: never copy repository documentation, credentials
    # or arbitrary files into a public artifact. Root LICENSE is an owner choice.
    check(not formal or (ROOT/'LICENSE').is_file(),
          'Formal publication requires an owner-approved root LICENSE')
    names=['notices/LICENSE.KazumiRules']
    if (ROOT/'LICENSE').is_file(): names.append('LICENSE')
    result={}
    for name in names:
        path=ROOT/name
        check(path.is_file(), 'Required recipient notice missing: '+name)
        content=path.read_bytes()
        check(0 < len(content) <= 64*1024, 'Recipient notice size')
        content.decode('utf-8')
        result['notices/'+path.name]=content
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('command',choices=['validate','build'])
    ap.add_argument('--output',type=Path);ap.add_argument('--sequence',type=int);ap.add_argument('--version')
    ap.add_argument('--revision');ap.add_argument('--issued-at');ap.add_argument('--expires-at')
    ap.add_argument('--key-file',type=Path);ap.add_argument('--key-id');ap.add_argument('--expected-public-key');ap.add_argument('--client-assets',type=Path)
    ap.add_argument('--client-dart',type=Path);ap.add_argument('--previous-manifest',type=Path)
    args=ap.parse_args();config,rules,entries=load()
    if args.command=='validate': print('VALID_RULES',len(rules));return
    check(args.output is not None and args.sequence is not None and 0<=args.sequence<=0x7fffffff and args.version and args.revision,'Build identity required')
    check(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}',args.version), 'Release version')
    start=dt.datetime.fromisoformat(args.issued_at.replace('Z','+00:00'));end=dt.datetime.fromisoformat(args.expires_at.replace('Z','+00:00'))
    check(start.utcoffset()==dt.timedelta() and end.utcoffset()==dt.timedelta() and dt.timedelta() < end-start <= dt.timedelta(days=31), 'Manifest validity')
    notices=release_notices(bool(args.key_file))
    bundle=encoded(rules)
    check(len(bundle)<=4*1024*1024,'Client bundle limit')
    manifest={'schema':1,'namespace':config['namespace'],'sequence':args.sequence,'version':args.version,
              'gitRevision':args.revision,'issuedAt':args.issued_at,'expiresAt':args.expires_at,
              'bundlePath':f'releases/{args.version}/rules.json','bundleSha256':digest(bundle),'bundleBytes':len(bundle),
              'rules':entries,'retired':config['retired'],
              'notices':[{'path':f'releases/{args.version}/{name}','sha256':digest(content),'bytes':len(content)}
                         for name,content in notices.items()]}
    payload=encoded(manifest)
    if args.previous_manifest:
        previous=read(args.previous_manifest)
        check(previous['namespace']==config['namespace'] and previous['sequence']<args.sequence, 'Release sequence must advance')
        by_id={e['id']:e for e in previous['rules']}
        for entry in entries:
            old=by_id.get(entry['id'])
            if old:
                check(old['name']==entry['name'], 'Stable source name changed')
                version=lambda e: tuple(int(p) for p in e['version'].split('.'))
                # Padding makes 1 and 1.0 the same version, like the client.
                left=version(entry);right=version(old);size=max(len(left),len(right))
                left+=tuple(0 for _ in range(size-len(left)));right+=tuple(0 for _ in range(size-len(right)))
                check(left>=right and (entry['sha256']==old['sha256'] or left>right), 'Changed rule requires a higher source version')
    release=args.output/'releases'/args.version
    for name,content in notices.items(): write(release/name,content)
    write(release/'rules.json',bundle);write(release/'manifest.json',payload)
    if args.key_file:
        now=dt.datetime.now(dt.timezone.utc)
        check(start<=now+dt.timedelta(minutes=5) and end>now,'Formal manifest must be current when published')
        check(args.sequence>0 and re.fullmatch(r'[a-f0-9]{40}',args.revision) and args.key_id and args.expected_public_key, 'Formal signing requires real Git revision/sequence/approved key identity')
        expected=base64.b64decode(args.expected_public_key,validate=True)
        check(len(expected)==32,'Expected approved raw Ed25519 public key')
        # No key creation, no secret copied to output, stdout or subprocess logs.
        with tempfile.TemporaryDirectory(prefix='ruri-rule-sign-') as temporary:
            inp=Path(temporary)/'payload';sig=Path(temporary)/'signature';pub=Path(temporary)/'public.der';inp.write_bytes(payload)
            public=subprocess.run(['openssl','pkey','-in',str(args.key_file),'-pubout','-outform','DER'],capture_output=True)
            # OpenSSL emits RFC8410 SubjectPublicKeyInfo; check the Ed25519 OID
            # and the independently approved public bytes before signing.
            check(public.returncode==0 and public.stdout==bytes.fromhex('302a300506032b6570032100')+expected,'Signing key does not match approved Ed25519 publisher')
            pub.write_bytes(public.stdout)
            result=subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(args.key_file),'-in',str(inp),'-out',str(sig)],capture_output=True)
            check(result.returncode==0, 'OpenSSL signing failed')
            signature=sig.read_bytes();check(len(signature)==64,'Ed25519 signature required')
            verify=subprocess.run(['openssl','pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',str(pub),'-in',str(inp),'-sigfile',str(sig)],capture_output=True)
            check(verify.returncode==0,'Signature read-back verification failed')
        envelope=encoded({'algorithm':'Ed25519','keyId':args.key_id,'payload':base64.b64encode(payload).decode(), 'signature':base64.b64encode(signature).decode()})
        write(release/'manifest.signed.json',envelope)
        # A site deployment exposes the complete immutable tree and this entry
        # in one Pages artifact; no commit-triggered live update.
        latest=args.output/'latest.json';latest.write_bytes(envelope)
    if args.client_assets:
        check(all(k in rules for k in config['bootstrapIds']), 'A retired bootstrap member requires the previously validated twelve-source release snapshot; do not silently change the fixed bootstrap')
        selected={k:rules[k] for k in config['bootstrapIds']};client_bundle=encoded(selected)
        bootstrap=dict(manifest,publisherManifestSha256=digest(payload),bundlePath='rules.json',bundleSha256=digest(client_bundle),bundleBytes=len(client_bundle),rules=[dict(next(e for e in entries if e['id']==k), defaultEnabled=i<6) for i,k in enumerate(config['bootstrapIds'])])
        write(args.client_assets/'manifest.json',encoded(bootstrap));write(args.client_assets/'rules.json',client_bundle)
        write(args.client_assets/'bootstrap.json',encoded(config['bootstrapIds']))
    if args.client_dart:
        by_id={m['id']:m for m in config['rules']}
        files=[Path(by_id[k]['file']).stem for k in config['bootstrapIds']]
        data='// Generated by RuriWaveRules/tools/build_release.py. Do not edit.\nabstract final class BundledSourceData {\n'
        data+='  static const files = '+repr(files)+';\n'
        data+='  static const disabledIds = <String>{'+','.join(repr(k) for k in config['bootstrapIds'][6:])+'};\n}\n'
        write(args.client_dart,data.encode('utf-8'))
    print('BUILT',args.version,'SIGNED' if args.key_file else 'LOCAL_UNSIGNED_NOT_PUBLISHED')

if __name__=='__main__':main()
