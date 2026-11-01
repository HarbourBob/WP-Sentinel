#!/usr/bin/env python3
"""Rebuild package-manifest.json. Run after changing any packaged file: python -B tools/build_manifest.py"""
import hashlib
import json
from pathlib import Path
import re

PACKAGE = Path(__file__).resolve().parent.parent
release = re.search(r"^VERSION = '([^']+)'", (PACKAGE / 'sentinel.py').read_text(encoding='utf-8'), re.M).group(1)
paths = [*PACKAGE.glob('*.py'), *PACKAGE.glob('*.php'), PACKAGE / 'rules.json', *(PACKAGE / 'documentation').glob('*.txt')]
files = {}
for path in sorted(paths, key=lambda p: p.relative_to(PACKAGE).as_posix()):
    data = path.read_bytes()
    files[path.relative_to(PACKAGE).as_posix()] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
manifest = {'format': 'sentinel-package-1', 'release': release, 'distribution': 'hosting', 'files': files}
(PACKAGE / 'package-manifest.json').write_bytes((json.dumps(manifest, indent=2) + '\n').encode())
print(f'{release}: {len(files)} files')
