#!/usr/bin/env python3
"""Read-only installation consistency check; no site access or package imports."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

RELEASE = '0.25.0-rc1'
MANIFEST = 'package-manifest.json'
MAX_BYTES = 16 * 1024 * 1024

def read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
        raise ValueError('Not an ordinary file or exceeds size limit')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('File changed while opening')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if len(raw) > MAX_BYTES or fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(final):
        raise ValueError('File changed during verification')
    return raw

def verify(directory):
    manifest = json.loads(read_regular(directory / MANIFEST))
    if not isinstance(manifest, dict) or manifest.get('format') != 'sentinel-package-1' or manifest.get('release') != RELEASE:
        raise ValueError('Manifest format/release does not match this verifier; upload the complete release')
    files = manifest.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 500:
        raise ValueError('Invalid manifest file list')
    if not {'verify-package.py', 'sentinel.py', 'sentinelctl.py', 'routine.py', 'rules.json'} <= files.keys():
        raise ValueError('Manifest is missing required program entries')
    for name, entry in files.items():
        if not re.fullmatch(r'(?:documentation/)?[A-Za-z0-9][A-Za-z0-9_.-]*\.(py|php|txt|json)', name):
            raise ValueError('Invalid manifest filename')
        if not isinstance(entry, dict) or type(entry.get('bytes')) is not int or not 0 <= entry['bytes'] <= MAX_BYTES or not re.fullmatch('[0-9a-f]{64}', str(entry.get('sha256', ''))):
            raise ValueError('Invalid manifest digest or size')
    issues, matched = [], 0
    for name, expected in sorted(files.items()):
        try:
            raw = read_regular(directory / name)
            if len(raw) == expected['bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256']:
                matched += 1
            else:
                issues.append({'file': name, 'status': 'mismatch', 'action': 'Upload this file again from the complete release; transfer without changing line endings.'})
        except FileNotFoundError:
            issues.append({'file': name, 'status': 'missing'})
        except (OSError, ValueError) as error:
            issues.append({'file': name, 'status': 'unreadable-or-unsafe', 'reason': type(error).__name__})
    extras = sorted(p.name for p in directory.iterdir() if p.suffix.lower() in ('.py', '.php', '.txt') and p.name not in files)
    extras += sorted('documentation/' + p.name for p in (directory / 'documentation').glob('*') if p.suffix.lower() == '.txt' and 'documentation/' + p.name not in files)
    return {'status': 'package-matches' if not issues else 'package-incomplete-or-modified',
            'expected_release': RELEASE, 'files_expected': len(files), 'files_matched': matched,
            'issues': issues, 'unlisted_program_or_text_entries': extras,
            'note': 'Only listed package bytes are checked. Extra entries are not verified or deleted. No website, profiles, reports or recovery stores are inspected. This local manifest is not a digital signature: an attacker able to replace the verifier and manifest can falsify results.'}

def main():
    try:
        result = verify(Path(__file__).resolve().parent)
        print(json.dumps(result, indent=2))
        return 0 if not result['issues'] else 1
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({'status': 'verification-unavailable', 'reason': str(error)}))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
