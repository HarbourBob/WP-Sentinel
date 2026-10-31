#!/usr/bin/env python3
"""WordPress Sentinel: bounded, read-only triage. Python standard library only."""
import argparse
import datetime
import getpass
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import struct
import sys
import zlib
import zipfile
import stat
import importlib.util
import urllib.parse
import urllib.request
import urllib.error

VERSION = '0.21.0-rc1'
SEVERITIES = ('high', 'medium', 'review', 'info')
PHP_SUFFIXES = {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.php8', '.phar', '.pht', '.phtm', '.phps'}
SCRIPT_SUFFIXES = {'.js', '.html', '.htm', '.svg'}
TEXT_EXTENSIONS = PHP_SUFFIXES | SCRIPT_SUFFIXES | {'.inc', '.txt', '.css', '.ini', '.conf'}
ROOT_PHP_FILES = {'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php',
                  'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php',
                  'wp-trackback.php', 'xmlrpc.php'}
WP_CONTENT_PHP_FILES = {'index.php', 'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php',
                        'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php'}
STRING_TRICK = re.compile(r'''\\x[0-9a-fA-F]|\\[0-7]{2}|['"]\s*\.\s*['"]''')
COMMENT_ONLY_PHP = re.compile(rb'\s*<\?php(?:\s|//[^\n]*|\#[^\n]*|/\*.*?\*/)*(?:\?>\s*)?', re.S)
_rule_pack = None

def load_rules(path=None):
    """Read and compile the rule pack. Rules are data; nothing in the pack is executed."""
    global _rule_pack
    path = Path(path) if path else Path(__file__).resolve().with_name('rules.json')
    pack = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(pack, dict) or pack.get('format') != 'sentinel-rules-1' or not isinstance(pack.get('version'), str):
        raise ValueError('Unsupported rule pack format')
    macros = pack.get('macros', {})
    expand = lambda text: re.sub(r'\{([a-z]+)\}', lambda m: macros.get(m.group(1), m.group(0)), text)
    compiled = []
    seen = set()
    for rule in pack['file_rules']:
        if rule['id'] in seen or rule['severity'] not in SEVERITIES or not set(rule['applies_to']) <= {'php', 'js', 'htaccess'} or not rule['all']:
            raise ValueError('Invalid rule: ' + str(rule.get('id')))
        seen.add(rule['id'])
        flags = re.I | (re.M if 'm' in rule.get('flags', '') else 0)
        compiled.append(dict(rule, patterns=[re.compile(expand(item), flags) for item in rule['all']]))
    for rule in pack['database_rules']:
        if rule['severity'] not in SEVERITIES or not isinstance(rule['pattern'], str):
            raise ValueError('Invalid database rule: ' + str(rule.get('id')))
    _rule_pack = dict(version=pack['version'], file_rules=compiled, database_rules=pack['database_rules'])
    return _rule_pack

def normalize_php(text):
    """Undo simple string tricks so names hidden by them can be matched. Never evaluated."""
    def unescape(match):
        return chr(int(match.group(1), 16)) if match.group(1) else chr(int(match.group(2), 8) & 255)
    text = re.sub(r'\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})', unescape, text)
    return re.sub(r'''['"]\s*\.\s*['"]''', '', text)

def detect(text, kinds=('php', 'js', 'htaccess'), location=''):
    findings = []
    normalized = None
    lowered = text.lower()
    for rule in (_rule_pack or load_rules())['file_rules']:
        if not set(rule['applies_to']) & set(kinds):
            continue
        if location.startswith(tuple(rule.get('exclude_paths', ('\0',)))):
            continue
        if 'only_paths' in rule and not location.startswith(tuple(rule['only_paths'])):
            continue
        # A plain text check first: far quicker than running a pattern over a whole file.
        if 'literals' in rule and not any(item in lowered for item in rule['literals']):
            continue
        if rule.get('scope') == 'normalized':
            if len(text) > 5242880 or not STRING_TRICK.search(text) or rule['patterns'][0].search(text):
                continue
            if normalized is None:
                normalized = normalize_php(text)
            if rule['patterns'][0].search(normalized):
                findings.append(dict(rule=rule['id'], severity=rule['severity'], reason=rule['reason'], line=None))
            continue
        matches = [pattern.search(text) for pattern in rule['patterns']]
        if all(matches):
            findings.append(dict(rule=rule['id'], severity=rule['severity'], reason=rule['reason'], line=text.count('\n', 0, matches[0].start()) + 1))
    return findings

def path_findings(rel, name, suffix, data):
    """Checks that need only a file's location. These do not depend on its contents matching a rule."""
    results = []
    def add(rule, severity, reason):
        results.append(dict(rule=rule, severity=severity, reason=reason, line=None))
    executable_name = suffix in PHP_SUFFIXES or re.search(r'\.(?:php\d?|phtml|phar|pht)\.[a-z0-9]+$', name, re.I) is not None
    if '/' not in rel and suffix in PHP_SUFFIXES and name not in ROOT_PHP_FILES:
        add('unexpected-root-php', 'medium', 'PHP file in the site root that is not part of WordPress. A common place for backdoors; some hosts and tools add legitimate ones.')
    parent, _, _ = rel.rpartition('/')
    if parent == 'wp-content' and suffix in PHP_SUFFIXES and name not in WP_CONTENT_PHP_FILES:
        add('unexpected-wp-content-php', 'review', 'PHP file directly in wp-content that is not a known WordPress drop-in.')
    if re.search(r'\.(?:php\d?|phtml|phar|pht)\.[a-z0-9]+$', name, re.I) and suffix not in {'.pubkey', '.asc', '.sig', '.sha256', '.md5'}:
        add('double-extension', 'medium', 'File name contains a PHP extension before its final extension, which some servers will still run as PHP.')
    if name.startswith('.') and suffix in PHP_SUFFIXES:
        add('hidden-php-file', 'medium', 'PHP file with a hidden name.')
    if rel != 'wp-config.php' and name == 'wp-config.php':
        add('config-name-outside-root', 'medium', 'A wp-config.php outside the site root. It can be a copied secrets file or a payload using a trusted name.')
    if '/' in rel and (name == '.env' or name.startswith('.env.')):
        add('config-name-outside-root', 'medium' if suffix in PHP_SUFFIXES else 'review', 'An .env-style file below the site root. It can be a stray secrets file, or a payload using that name.')
    if rel.startswith('wp-content/uploads/') and executable_name:
        if len(data) <= 4096 and COMMENT_ONLY_PHP.fullmatch(data):
            add('placeholder-php', 'info', 'PHP file in uploads containing only comments, usually a directory-listing placeholder.')
        else:
            add('executable-in-uploads', 'high', 'Executable file type in uploads, whatever it contains. Uploads should hold media, not code. Some plugins do write PHP here; review it.')
    return results

def inside(path, root):
    return path == root or root in path.parents

def image_payload_ranges(data):
    """Return compressed payload spans only for bounded, structurally checked containers.

    This validates container framing, not image decoding or absence of malware.
    """
    ranges = []
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        pos = 8
        first = True
        while pos + 12 <= len(data):
            size = struct.unpack('>I', data[pos:pos + 4])[0]
            end = pos + size + 12
            if end > len(data):
                return []
            kind = data[pos + 4:pos + 8]
            if first and (kind != b'IHDR' or size != 13):
                return []
            first = False
            crc = struct.unpack('>I', data[end - 4:end])[0]
            if zlib.crc32(data[pos + 4:end - 4]) != crc:
                return []
            if kind == b'IDAT':
                ranges.append((pos + 8, end - 4))
            if kind == b'IEND':
                return ranges if size == 0 and end == len(data) else []
            pos = end
        return []
    if len(data) >= 12 and data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        if struct.unpack('<I', data[4:8])[0] + 8 != len(data):
            return []
        pos = 12
        while pos + 8 <= len(data):
            size = struct.unpack('<I', data[pos + 4:pos + 8])[0]
            end = pos + 8 + size
            if end + size % 2 > len(data):
                return []
            if data[pos:pos + 4] in {b'VP8 ', b'VP8L'}:
                ranges.append((pos + 8, end))
            pos = end + size % 2
        return ranges if pos == len(data) else []
    return []

def upload_marker_finding(data, suffix, execution_matches):
    markers = list(re.finditer(rb'<\?(?:php\b|=)', data, re.I))
    if not markers or (len(data) <= 4096 and COMMENT_ONLY_PHP.fullmatch(data)):
        return None
    ranges = image_payload_ranges(data)
    image_suffix = suffix in {'.png', '.webp'}
    if image_suffix and not execution_matches and ranges and all(
        m.group() == b'<?=' and any(start <= m.start() and m.end() <= end for start, end in ranges)
        for m in markers
    ):
        return dict(rule='image-binary-marker', severity='info', line=None,
                    reason='Short PHP-like bytes occur only inside compressed image payloads in a structurally checked container. Likely incidental bytes, not evidence of PHP code. Image contents were not decoded.')
    if suffix in {'.html', '.htm', '.js', '.txt'} and not execution_matches:
        return dict(rule='php-marker-in-text', severity='review', line=None,
                    reason='PHP opening marker in a text asset. May be generated source code or an example; context and server handling need review. A marker alone does not demonstrate execution.')
    executable = suffix in {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.php8', '.phar'}
    return dict(rule='php-in-uploads', severity='high' if executable or execution_matches else 'medium', line=None,
                reason='PHP opening marker in uploads. Review content and server handling; the marker alone does not prove malware or execution.')

def file_kinds(suffix, name, data):
    kinds = []
    # JavaScript, stylesheets, text and images only get PHP rules if they contain a PHP marker.
    # Minified bundles are the bulk of a typical site and PHP cannot run from them otherwise.
    lowered = data.lower()
    if suffix in PHP_SUFFIXES or suffix in {'.inc', '.ini', '.conf'} or name == '.htaccess' or b'<?php' in lowered or b'<?=' in lowered:
        kinds.append('php')
    if suffix in SCRIPT_SUFFIXES or suffix in PHP_SUFFIXES:
        kinds.append('js')
    if name == '.htaccess':
        kinds.append('htaccess')
    return kinds

def oversized_findings(path, rel, name, max_bytes):
    """Padding a file past the limit should not hide it: note it and check both ends."""
    suffix = path.suffix.lower()
    results = [dict(item, source='file', location=rel, content_complete=False) for item in path_findings(rel, name, suffix, b'')]
    if suffix not in TEXT_EXTENSIONS:
        return results
    if suffix in PHP_SUFFIXES:
        results.append(dict(source='file', location=rel, severity='review', rule='oversized-php', line=None, content_complete=False,
                            reason='PHP file larger than the scan size limit. Unusually large PHP can be padding used to avoid scanners.'))
    sample = min(max_bytes, 2097152)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        head = stream.read(sample)
        stream.seek(max(0, os.fstat(stream.fileno()).st_size - sample))
        tail = stream.read(sample)
    seen = set()
    for chunk in (head, tail):
        for item in detect(chunk.decode('utf-8', errors='replace'), file_kinds(suffix, name, chunk), rel):
            if item['rule'] not in seen:
                seen.add(item['rule'])
                results.append(dict(item, source='file', location=rel, line=None, content_complete=False,
                                    reason=item['reason'] + ' Seen in the start or end of an oversized file; the middle was not inspected.'))
    return results

def scan_files(root, max_bytes, max_files, inventory=None, separate_sites=()):
    findings, files, limitations = [], {}, []
    if inventory is not None:
        inventory.update(format='sentinel-file-inventory-1', site_root=str(root), status='in-progress',
                         started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         max_bytes=max_bytes, max_files=max_files, traversal_complete=True, entries={},
                         uninspected_directories=[], file_limit_reached=False, traversal_scope_known=True)
    def observed(path, status, **details):
        if inventory is not None:
            inventory['entries'][str(path)] = dict(status=status, **details)
    def directory_gap(relative):
        # Keep the gap specific so one skipped folder does not blind comparisons elsewhere.
        if inventory is not None:
            inventory['traversal_complete'] = False
            inventory['uninspected_directories'].append(relative)
    def symlink_finding(path, rel):
        try:
            target = Path(os.path.realpath(path))
        except OSError:
            return
        if not inside(target, root):
            findings.append(dict(source='file', location=rel, severity='medium', rule='symlink-leaves-site', line=None,
                                 reason='Symbolic link points outside the site, and its target was not inspected. It can be hosting layout, or a way to reach other files.'))
    skipped = dict(symlinks=0, oversized=0, unreadable=0, changed=0, nonregular=0)
    visited = 0
    stopped = False
    def walk_error(error):
        skipped['unreadable'] += 1
        try:
            directory_gap(Path(error.filename).relative_to(root).as_posix())
        except (TypeError, ValueError):
            if inventory is not None:
                inventory['traversal_complete'] = False
                inventory['traversal_scope_known'] = False
    for folder, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        safe_dirs = []
        for name in dirs:
            observed(Path(folder, name).relative_to(root).as_posix(), 'directory')
            if Path(folder, name).is_symlink():
                skipped['symlinks'] += 1
                relative = Path(folder, name).relative_to(root).as_posix()
                observed(relative, 'symlink-directory')
                directory_gap(relative)
                symlink_finding(Path(folder, name), relative)
            elif Path(folder, name).relative_to(root).as_posix() in separate_sites:
                # Its own scan covers it. The gap keeps comparisons honest about this folder.
                directory_gap(Path(folder, name).relative_to(root).as_posix())
                limitations.append('Not inspected here because it is scanned as its own site: ' + Path(folder, name).relative_to(root).as_posix())
            else:
                safe_dirs.append(name)
        dirs[:] = sorted(safe_dirs)
        for name in sorted(names):
            if visited >= max_files:
                stopped = True
                break
            visited += 1
            path = Path(folder, name)
            rel = path.relative_to(root).as_posix()
            observed(rel, 'unreadable-or-changed')
            try:
                if path.is_symlink():
                    observed(rel, 'symlink')
                    skipped['symlinks'] += 1
                    symlink_finding(path, rel)
                    continue
                if not path.is_file():
                    skipped['nonregular'] += 1
                    observed(rel, 'nonregular')
                    continue
                before = path.stat()
                if before.st_size > max_bytes:
                    skipped['oversized'] += 1
                    observed(rel, 'oversized')
                    limitations.append(f'Oversized file not fully inspected: {rel} ({before.st_size} bytes).')
                    findings.extend(oversized_findings(path, rel, name, max_bytes))
                    continue
                flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
                import stat
                with os.fdopen(os.open(path, flags), 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        skipped['nonregular'] += 1
                        continue
                    data = stream.read(max_bytes + 1)
                    after = os.fstat(stream.fileno())
                if len(data) > max_bytes:
                    skipped['oversized'] += 1
                    observed(rel, 'oversized')
                    limitations.append(f'File grew beyond scan size limit: {rel}.')
                    continue
                stable = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
                if stable(before) != stable(opened) or stable(opened) != stable(after) or (os.name == 'posix' and opened.st_ctime_ns != after.st_ctime_ns) or len(data) != after.st_size:
                    skipped['changed'] += 1
                    observed(rel, 'changed-during-read')
                    continue
                observed(rel, 'hashed', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                files[rel] = hashlib.md5(data).hexdigest()
                # Contents stay in memory: only rule names, line numbers and hashes are recorded,
                # which is what makes it safe to include configuration files holding secrets.
                text = data.decode('utf-8', errors='replace')
                matches = detect(text, file_kinds(path.suffix.lower(), name, data), rel)
                if rel.startswith('wp-content/uploads/'):
                    marker = upload_marker_finding(data, path.suffix.lower(), matches)
                    if marker:
                        matches.append(marker)
                matches.extend(path_findings(rel, name, path.suffix.lower(), data))
                if name in {'.htaccess', '.user.ini', 'php.ini'} and re.search(r'auto_(?:prepend|append)_file', text, re.I):
                    matches.append(dict(rule='php-auto-load', severity='medium', reason='Configuration automatically loads a PHP file. May be a legitimate firewall; verify its target.', line=None))
                for item in matches:
                    findings.append(dict(item, source='file', location=rel, sha256=hashlib.sha256(data).hexdigest()))
            except (OSError, ValueError):
                skipped['unreadable'] += 1
        if stopped:
            limitations.append('File count limit reached; remaining files were not inspected.')
            if inventory is not None:
                inventory['file_limit_reached'] = True
            break
    # WordPress also accepts wp-config.php one directory above the site root.
    outer = root.parent / 'wp-config.php'
    if not (root / 'wp-config.php').exists() and outer.is_file() and not outer.is_symlink() and outer.stat().st_size <= max_bytes:
        try:
            for item in detect(outer.read_bytes().decode('utf-8', errors='replace'), ('php',), '../wp-config.php'):
                findings.append(dict(item, source='file', location='../wp-config.php'))
        except OSError:
            limitations.append('wp-config.php above the site root could not be read.')
    limitations.append('wp-config.php and .env files are scanned in memory. Their contents are never saved; only rule names, line numbers and hashes are recorded.')
    for key, count in skipped.items():
        if count:
            limitations.append(f'{count} file/directory entries skipped: {key}.')
    if inventory is not None:
        inventory.update(status='finished', traversal_complete=inventory['traversal_complete'] and not stopped,
                         finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         limitations=list(limitations), skipped_counts=skipped)
    return findings, files, limitations, visited

def check_core(root, hashes, version, locale):
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', version):
        raise ValueError('Use an explicit stable WordPress version, such as 6.8.3.')
    if not re.fullmatch(r'[A-Za-z_]{2,20}', locale):
        raise ValueError('Invalid locale.')
    url = 'https://api.wordpress.org/core/checksums/1.0/?' + urllib.parse.urlencode({'version': version, 'locale': locale})
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read(4_000_001)
    if len(body) > 4_000_000:
        raise ValueError('Checksum response too large.')
    manifest = json.loads(body).get('checksums')
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('No official checksum manifest returned.')
    results, unchecked = [], 0
    for name, digest in manifest.items():
        parts = name.split('/')
        if name.startswith('/') or '\\' in name or any(p in {'', '.', '..'} for p in parts) or not re.fullmatch('[a-fA-F0-9]{32}', str(digest)):
            raise ValueError('Invalid official manifest entry.')
        if name.startswith('wp-content/'):
            continue
        target = root.joinpath(*parts)
        if not inside(target.resolve(), root):
            unchecked += 1
            continue
        if name in hashes:
            if hashes[name].lower() != digest.lower():
                results.append(dict(source='file', location=name, severity='medium', rule='core-checksum-mismatch', reason='Differs from the selected official release. This is not proof of malware.', line=None))
        elif not target.exists():
            results.append(dict(source='file', location=name, severity='medium', rule='core-file-missing', reason='Expected official core file is missing.', line=None))
        else:
            unchecked += 1
    for name in hashes:
        if name.startswith(('wp-admin/', 'wp-includes/')) and name not in manifest:
            results.append(dict(source='file', location=name, severity='medium', rule='unexpected-core-file', reason='Not listed in the selected official release; review this extra file.', line=None))
    return results, unchecked

def plugin_manifest(slug, version):
    url = f'https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json'
    with urllib.request.urlopen(url, timeout=20) as response:
        data = response.read(8_000_001)
    if len(data) > 8_000_000:
        raise ValueError('Manifest too large')
    manifest = json.loads(data).get('files')
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('No file checksums')
    validated = {}
    for name, entry in manifest.items():
        if not isinstance(name, str) or name.startswith('/') or '\\' in name or any(part in {'', '.', '..'} for part in name.split('/')):
            raise ValueError('Unsafe manifest path')
        # A file can have several accepted digests, so md5 may be a string or a list.
        digest = entry.get('md5') if isinstance(entry, dict) else None
        digests = digest if isinstance(digest, list) else [digest]
        if not digests or not all(isinstance(item, str) and re.fullmatch('[a-fA-F0-9]{32}', item) for item in digests):
            raise ValueError('Unsupported manifest digest')
        validated[name] = tuple(item.lower() for item in digests)
    return validated

def check_plugins(root, hashes):
    base = root / 'wp-content' / 'plugins'
    findings, statuses = [], []
    if base.is_symlink() or (root / 'wp-content').is_symlink() or not inside(base.resolve(), root) or not base.is_dir():
        return [], [{'status': 'unverified', 'reason': 'Plugin directory absent or symlinked'}]
    for directory in sorted(base.iterdir()):
        slug = directory.name
        status = {'plugin': slug, 'status': 'unverified'}
        if directory.is_file() and not directory.is_symlink():
            status['entry_type'] = 'standalone-file'
        statuses.append(status)
        if directory.is_symlink() or not directory.is_dir() or not re.fullmatch('[a-z0-9][a-z0-9-]*', slug):
            status['reason'] = 'Not an eligible ordinary plugin directory'
            continue
        headers = []
        try:
            for path in sorted(directory.glob('*.php')):
                if path.is_symlink() or not path.is_file():
                    continue
                with path.open('rb') as stream:
                    text = stream.read(8192).decode('utf-8', errors='replace')
                if re.search(r'^[ \t/*#]*Plugin Name\s*:', text, re.M | re.I):
                    version = re.search(r'^[ \t/*#]*Version\s*:\s*([^\s*]+)', text, re.M | re.I)
                    headers.append(version.group(1) if version else '')
            if len(headers) != 1 or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}', headers[0]):
                status['reason'] = 'Missing or ambiguous plugin header/version'
                continue
            status['version'] = headers[0]
            manifest = plugin_manifest(slug, headers[0])
            prefix = f'wp-content/plugins/{slug}/'
            local = {name[len(prefix):]: digest for name, digest in hashes.items() if name.startswith(prefix)}
            unchecked, matched, differences = 0, 0, 0
            unchecked_details = []
            for name, digest in manifest.items():
                target = directory.joinpath(*name.split('/'))
                if not inside(target.resolve(), directory.resolve()):
                    unchecked += 1
                    unchecked_details.append({'path': prefix + name, 'reason': 'Resolves outside plugin directory'})
                elif name in local:
                    if local[name] in digest:
                        matched += 1
                    else:
                        differences += 1
                        findings.append(dict(source='file', location=prefix + name, severity='medium', rule='plugin-checksum-mismatch', reason='Differs from the WordPress.org reference for the locally declared version; review before changing.', line=None))
                elif target.exists():
                    unchecked += 1
                    unchecked_details.append({'path': prefix + name, 'reason': 'Not hashed by file scan: size/access limit, symlink, changing file, or scan limit'})
                else:
                    differences += 1
                    findings.append(dict(source='file', location=prefix + name, severity='medium', rule='plugin-file-missing', reason='Expected WordPress.org reference file is missing.', line=None))
            for name in local.keys() - manifest.keys():
                differences += 1
                findings.append(dict(source='file', location=prefix + name, severity='review', rule='plugin-extra-file', reason='Extra file absent from the official plugin manifest; may be generated content or a local customization.', line=None))
            status.update(status='compared', matched_files=matched, unchecked_files=unchecked, unchecked_details=unchecked_details, differences=differences)
        except urllib.error.HTTPError as exc:
            status['reason'] = f'Official manifest unavailable (HTTP {exc.code}); custom/premium or unpublished versions may have no reference'
        except Exception as exc:
            status['reason'] = 'Could not verify: ' + type(exc).__name__
    return findings, statuses

def check_reference(root, hashes, specification):
    """Compare an explicitly supplied archive without extracting or executing it."""
    identity, archive = specification.split('=', 1)
    kind, slug = identity.split(':', 1)
    if kind not in {'plugin', 'theme'} or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,99}', slug):
        raise ValueError('Use plugin:directory=/path/file.zip or theme:directory=/path/file.zip')
    archive = Path(archive).resolve()
    if inside(archive, root) or archive.stat().st_size > 100 * 1024 * 1024:
        raise ValueError('Reference ZIP must be outside the website and at most 100 MiB')
    directory = root / 'wp-content' / ('plugins' if kind == 'plugin' else 'themes') / slug
    if not directory.is_dir() or not inside(directory.resolve(), root) or any(p.is_symlink() for p in [directory, directory.parent, directory.parent.parent]):
        raise ValueError('Target must be an existing ordinary directory inside the site')
    prefix = directory.relative_to(root).as_posix() + '/'
    expected = {}
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > 50000 or sum(i.file_size for i in entries) > 1024 * 1024 * 1024:
            raise ValueError('Reference exceeds entry or uncompressed-size limits')
        files = []
        packaging_metadata = []
        for entry in entries:
            name = entry.filename
            parts = name.rstrip('/').split('/')
            if name.startswith('/') or '\\' in name or ':' in name or any(p in {'', '.', '..'} for p in parts):
                raise ValueError('Unsafe archive path')
            if stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1:
                raise ValueError('Symlink or encrypted archive entry is unsupported')
            if parts[0] == '__MACOSX' or parts[-1] == '.DS_Store':
                packaging_metadata.append(name)
                continue
            if not entry.is_dir():
                if entry.file_size > 50 * 1024 * 1024:
                    raise ValueError('Archive member exceeds 50 MiB limit')
                files.append(entry)
        if not files:
            raise ValueError('Empty reference archive')
        wrapped = all(i.filename.startswith(slug + '/') for i in files)
        for entry in files:
            name = entry.filename[len(slug) + 1:] if wrapped else entry.filename
            if name in expected:
                raise ValueError('Duplicate archive path')
            digest = hashlib.md5()
            read = 0
            with z.open(entry) as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    read += len(chunk)
                    if read > 50 * 1024 * 1024:
                        raise ValueError('Archive member exceeds read limit')
                    digest.update(chunk)
            expected[name] = digest.hexdigest()
        # Reject a ZIP wrapper with an unrelated directory name instead of
        # silently comparing every file at the wrong relative location.
        if kind == 'theme' and 'style.css' not in expected:
            raise ValueError('Theme ZIP must have style.css at its root or under the target directory name')
        if kind == 'plugin' and not any('/' not in n and n.lower().endswith('.php') for n in expected):
            raise ValueError('Plugin ZIP must have a top-level PHP file or a wrapper matching the target directory')
    findings, unchecked = [], []
    matched = 0
    for name, digest in expected.items():
        target = directory.joinpath(*name.split('/'))
        location = prefix + name
        if not inside(target.resolve(), directory.resolve()):
            unchecked.append({'path': location, 'reason': 'Resolves outside target directory'})
        elif location in hashes:
            if hashes[location] == digest:
                matched += 1
            else:
                findings.append(dict(source='file', location=location, severity='medium', rule='reference-mismatch', reason='Differs from the supplied ZIP. Verify the reference version and any intentional edits.', line=None))
        elif target.exists():
            unchecked.append({'path': location, 'reason': 'Not hashed by bounded file scan; check exclusions, permissions, links, and size limits'})
        else:
            findings.append(dict(source='file', location=location, severity='medium', rule='reference-file-missing', reason='File from supplied reference ZIP is missing.', line=None))
    for location in hashes:
        if location.startswith(prefix) and location[len(prefix):] not in expected:
            findings.append(dict(source='file', location=location, severity='review', rule='reference-extra-file', reason='Inspected file is absent from supplied ZIP; may be generated content or intentional customization.', line=None))
    return findings, {'target': identity, 'reference_filename': archive.name, 'status': 'compared-to-user-supplied-reference', 'matched_files': matched, 'differences': len(findings), 'unchecked_details': unchecked, 'ignored_archive_metadata': packaging_metadata, 'trust_note': 'Archive provenance and matching release must be established by the user; matching is not a malware verdict. Listed macOS packaging metadata is excluded from the reference, not certified safe.'}

def database_error(stdout):
    """Render only allowlisted diagnostic fields, never raw helper output."""
    categories = {'mysqli-unavailable': 'PHP mysqli extension is unavailable',
                  'invalid-input': 'Invalid database input or table prefix',
                  'access-denied': 'Database access denied; verify credentials and database-user permissions',
                  'unknown-database': 'Database name was not found',
                  'connection-failed': 'Database connection failed; verify host and connection availability',
                  'database-check-failed': 'Database helper failed'}
    try:
        error = json.loads(stdout)['error']
        category = categories[error['category']]
        stage = error['stage'] if error['stage'] in {'input', 'connect', 'charset', 'queries'} else 'unknown'
        code = error['code'] if type(error['code']) is int else 0
        return f'{category} (stage: {stage}; code: {code}).'
    except (ValueError, TypeError, KeyError):
        return 'Database helper could not return a diagnostic. Check that the updated database.php is alongside sentinel.py and PHP CLI is available.'

def php_without_comments(text):
    """Blank out PHP comments, leaving strings alone, so commented-out settings are not read."""
    result, index, length = [], 0, len(text)
    while index < length:
        char = text[index]
        if char in '\'"':
            end = index + 1
            while end < length and text[end] != char:
                end += 2 if text[end] == '\\' else 1
            result.append(text[index:end + 1])
            index = end + 1
        elif char == '#' or text.startswith('//', index):
            index = text.find('\n', index)
            index = length if index < 0 else index
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            index = length if end < 0 else end + 2
            result.append(' ')
        else:
            result.append(char)
            index += 1
    return ''.join(result)

def php_literal(text, start):
    """Read a plain PHP string at start. Returns (value, end), or None for anything computed."""
    match = re.compile(r"\s*(?:'((?:[^'\\]|\\.)*)'|\"([^\"\\$]*)\")", re.S).match(text, start)
    if not match:
        return None
    if match.group(1) is None:
        return match.group(2), match.end()
    return re.sub(r"\\([\\'])", r'\1', match.group(1)), match.end()

def wp_config_path(root):
    """WordPress also allows wp-config.php one level up, unless that folder is another install."""
    if (root / 'wp-config.php').is_file():
        return root / 'wp-config.php'
    if (root.parent / 'wp-config.php').is_file() and not (root.parent / 'wp-settings.php').exists():
        return root.parent / 'wp-config.php'
    raise RuntimeError('wp-config.php was not found.')

def wp_config_credentials(root):
    """Read database settings from wp-config.php as text. The file is never executed."""
    path = wp_config_path(root)
    if path.is_symlink() or path.stat().st_size > 1048576:
        raise RuntimeError('wp-config.php is a symlink or too large to read.')
    text = php_without_comments(path.read_bytes().decode('utf-8', 'replace'))
    values = {}
    for name in ('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'):
        found = set()
        for match in re.finditer(r"\bdefine\s*\(\s*['\"]" + name + r"['\"]\s*,", text, re.I):
            literal = php_literal(text, match.end())
            if literal is None or not re.match(r'\s*\)', text[literal[1]:literal[1] + 200]):
                raise RuntimeError(f'{name} in wp-config.php is computed rather than plain text. Use --db-credentials instead.')
            found.add(literal[0])
        # Several values usually mean per-environment settings, which cannot be told apart without running the file.
        if len(found) != 1:
            raise RuntimeError(f'wp-config.php has {"no" if not found else "several values for"} {name}. Use --db-credentials instead.')
        values[name] = found.pop()
    prefixes = set()
    for match in re.finditer(r'\$table_prefix\s*=', text):
        literal = php_literal(text, match.end())
        if literal is None:
            raise RuntimeError('$table_prefix in wp-config.php is computed rather than plain text. Use --db-credentials instead.')
        prefixes.add(literal[0])
    if len(prefixes) != 1:
        raise RuntimeError('wp-config.php does not have one clear $table_prefix. Use --db-credentials instead.')
    return {'host': values['DB_HOST'], 'database': values['DB_NAME'], 'user': values['DB_USER'], 'password': values['DB_PASSWORD'], 'prefix': prefixes.pop()}

def file_credentials(path, root):
    """Read database settings from a private JSON file kept outside the website."""
    path = Path(os.path.abspath(path))
    if path.is_symlink() or inside(path.resolve(), root) or path.stat().st_size > 16384:
        raise RuntimeError('The credentials file must be a small regular file outside the website.')
    if os.name == 'posix' and path.stat().st_mode & 0o077:
        raise RuntimeError('The credentials file must have permissions 600.')
    values = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(values, dict) or not {'database', 'user', 'password'} <= set(values) <= {'host', 'database', 'user', 'password', 'prefix'} or not all(isinstance(v, str) for v in values.values()):
        raise RuntimeError('The credentials file needs database, user and password, and may have host and prefix.')
    return dict({'host': 'localhost', 'prefix': 'wp_'}, **values)

def split_db_host(host):
    """Follow WordPress: DB_HOST can be host, host:port or host:/path/to/socket."""
    host, separator, extra = host.partition(':')
    if extra.startswith('/'):
        return host or 'localhost', None, extra
    if separator and extra.isdigit():
        return host or 'localhost', int(extra), None
    return host + separator + extra, None, None

def prompt_credentials():
    try:
        print('Database details remain local and are passed through standard input, not command arguments.')
        return {'host': input('Database host [localhost]: ').strip() or 'localhost',
                'database': input('Database name: ').strip(), 'user': input('Database user: ').strip(),
                'password': getpass.getpass('Database password (hidden): '),
                'prefix': input('Table prefix [wp_]: ').strip() or 'wp_'}
    except EOFError:
        raise RuntimeError('No terminal to ask for database details. For unattended runs use --db-from-wp-config or --db-credentials.') from None

def scan_database(php, helper, row_limit, value_limit=65536, credentials=None):
    credentials = credentials or prompt_credentials()
    host, port, socket = split_db_host(credentials['host'])
    config = dict(credentials, host=host, port=port, socket=socket, limit=row_limit, value_limit=value_limit,
                  rules=[{key: rule[key] for key in ('id', 'severity', 'pattern', 'reason')} for rule in _rule_pack['database_rules']])
    # Run without php.ini; if mysqli needs one, load only that extension and retry.
    result = subprocess.run([php, '-n', str(helper)], input=json.dumps(config), text=True, capture_output=True, timeout=600)
    if result.returncode and '"mysqli-unavailable"' in result.stdout:
        result = subprocess.run([php, '-n', '-d', 'display_startup_errors=0', '-d', 'display_errors=0', '-d', 'extension=mysqli', str(helper)], input=json.dumps(config), text=True, capture_output=True, timeout=600)
    config['password'] = credentials['password'] = ''
    if result.returncode:
        raise RuntimeError(database_error(result.stdout))
    return json.loads(result.stdout)

def check_active_plugins(sites, hashes):
    """Compare the database's active plugin list with the files seen in the scan."""
    results = []
    for site in sites:
        for plugin in site.get('active_plugins', []):
            location = site.get('table', 'options') + ':option_name=active_plugins'
            parts = plugin.replace('\\', '/').split('/')
            if plugin.startswith(('/', '\\')) or '..' in parts or ':' in plugin:
                results.append(dict(source='database', location=location, severity='high', rule='active-plugin-path-escape', line=None, context={'plugin': plugin[:191]},
                                    reason='An active plugin path points outside the plugins folder, so WordPress loads it as code on every request.'))
            elif 'wp-content/plugins/' + plugin not in hashes:
                results.append(dict(source='database', location=location, severity='medium', rule='active-plugin-file-missing', line=None, context={'plugin': plugin[:191]},
                                    reason='Active plugin file was not seen in this scan. It may be removed, skipped by a limit, or in a custom plugin folder.'))
    return results

def detect_core_version(root):
    """Read the version from wp-includes/version.php as text; it is never executed."""
    data = (root / 'wp-includes' / 'version.php').read_bytes()[:65536].decode('utf-8', errors='replace')
    match = re.search(r'''^\s*\$wp_version\s*=\s*['"]([^'"]+)['"]''', data, re.M)
    if not match:
        raise ValueError('Could not find a version in wp-includes/version.php')
    return match.group(1)

def finding_commands(finding, index, report_path, profile):
    """Ready-to-paste commands for one finding. Previews only: none of these change anything."""
    digest = finding.get('sha256')
    if not digest or finding.get('content_complete') is False:
        return {}
    base = 'python3 -I -S sentinelctl.py --profile ' + shlex.quote(profile or 'PROFILE')
    commands = {'review': base + f" review --report {shlex.quote(str(report_path))} --finding-index {index} --sha256 {digest} --decision benign --note 'What you inspected and why it is benign'"}
    if finding.get('source') == 'file' and not finding['location'].startswith(('../', 'account-')):
        commands['quarantine'] = base + f" file-quarantine --file {shlex.quote(finding['location'])} --sha256 {digest}"
    return commands

def render_report(report, report_path, profile):
    """Build the HTML report: self-contained, with every imported value escaped."""
    escape = lambda value: html.escape(str(value), quote=True)
    labels = {'high': 'High', 'medium': 'Medium', 'review': 'Review', 'info': 'Info'}
    advice = {'high': 'Inspect first. Strong sign of malicious code, or code that should not be here.',
              'medium': 'Inspect soon. Suspicious, with some legitimate uses.',
              'review': 'Check it is expected. An observation rather than a sign of malware.',
              'info': 'Recorded for comparison. No action needed unless it changes unexpectedly.'}
    counts = report['priority_counts']
    page = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">",
            '<title>WordPress Sentinel report</title><style>',
            ':root{--ink:#182433;--muted:#566476;--line:#d5dce5;--panel:#f3f6f9;--high:#a4161a;--medium:#b45309;--review:#1d4ed8;--info:#566476}',
            'body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;padding:2em 1em;max-width:1400px;color:var(--ink);background:#fff}',
            'h1{margin:0 0 .2em}.cards{display:flex;flex-wrap:wrap;gap:.75em;margin:1.2em 0}.card{flex:1 1 150px;border:1px solid var(--line);border-left:5px solid;border-radius:6px;padding:.7em 1em}',
            '.card b{display:block;font-size:1.8em;line-height:1.2}.card small{color:var(--muted)}.high{border-color:var(--high);color:var(--high)}.medium{border-color:var(--medium);color:var(--medium)}.review{border-color:var(--review);color:var(--review)}.info{border-color:var(--info);color:var(--info)}',
            '.card small,.card span{color:var(--ink)}.controls{display:flex;flex-wrap:wrap;gap:1em;align-items:center;background:var(--panel);padding:.7em 1em;border-radius:6px;position:sticky;top:0}',
            'input[type=search]{flex:1 1 220px;font:inherit;padding:.3em .5em}.finding{border:1px solid var(--line);border-left:5px solid;border-radius:6px;padding:.8em 1em;margin:.8em 0;color:var(--ink)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.review{border-left-color:var(--review)}.finding.info{border-left-color:var(--info)}',
            '.finding h3{margin:0;font-size:1em;overflow-wrap:anywhere}.meta{color:var(--muted);font-size:.9em;overflow-wrap:anywhere}.tag{font-weight:700;text-transform:uppercase;font-size:.8em;margin-right:.5em}',
            'code,pre{font:13px/1.4 ui-monospace,Consolas,monospace;overflow-wrap:anywhere;white-space:pre-wrap}.cmd{display:flex;gap:.5em;align-items:flex-start;margin-top:.4em}.cmd code{flex:1;background:var(--panel);padding:.4em;border-radius:4px}',
            'button{font:inherit;font-size:.85em;cursor:pointer}summary{cursor:pointer;font-weight:600}section{margin-top:2em}li{margin:.5em 0}',
            '</style><h1>WordPress Sentinel report</h1>',
            f"<p class=\"meta\">{escape(report['site_root'])} · {escape(report['created_utc'])} · Sentinel {escape(report['version'])} · rules {escape(report.get('rules_version', 'unknown'))}</p>",
            f"<p>{escape(report['files_inspected'])} files inspected, {len(report['findings'])} findings. Findings need review and are not malware verdicts. No findings would not mean the site is clean.</p>",
            '<div class="cards">']
    for level in SEVERITIES:
        page.append(f'<div class="card {level}"><b>{counts.get(level, 0)}</b>{labels[level]}<br><small>{escape(advice[level])}</small></div>')
    page.append('</div><section><h2>Findings</h2><div class="controls">')
    for level in SEVERITIES:
        checked = '' if level == 'info' else ' checked'
        page.append(f'<label><input type="checkbox" data-level="{level}"{checked}> {labels[level]}</label>')
    page.append('<input type="search" id="search" placeholder="Filter by path or rule" aria-label="Filter by path or rule"></div><p class="meta" id="shown"></p>')
    for index, finding in enumerate(report['findings'], 1):
        level = finding.get('severity', 'review')
        text = (str(finding.get('location', '')) + ' ' + str(finding.get('rule', ''))).lower()
        line = f" · line {escape(finding['line'])}" if finding.get('line') else ''
        page.append(f'<article class="finding {escape(level)}" data-level="{escape(level)}" data-text="{escape(text)}"><span class="tag {escape(level)}">{escape(labels.get(level, level))}</span>#{index}')
        page.append(f"<h3>{escape(finding.get('location', ''))}</h3><div class=\"meta\">{escape(finding.get('rule', ''))} · {escape(finding.get('source', ''))}{line}</div><p>{escape(finding.get('reason', ''))}</p>")
        if finding.get('context'):
            page.append('<div class="meta">Context: <code>' + escape(json.dumps(finding['context'], ensure_ascii=False)) + '</code></div>')
        if finding.get('sha256'):
            page.append('<div class="meta">SHA-256: <code>' + escape(finding['sha256']) + '</code></div>')
        commands = finding_commands(finding, index, report_path, profile)
        if commands:
            page.append('<details><summary>Commands</summary>')
            names = {'review': 'Record that you reviewed this and found it benign', 'quarantine': 'Preview quarantine (add --apply to perform it)'}
            for name, command in commands.items():
                page.append(f'<div class="meta">{escape(names[name])}</div><div class="cmd"><code>{escape(command)}</code><button type="button" data-copy="{escape(command)}">Copy</button></div>')
            page.append('</details>')
        page.append('</article>')
    page.append('</section><section><h2>Coverage and limitations</h2><p>Read this before relying on the results: anything listed here was not fully checked.</p><ul>')
    page.extend('<li>' + escape(item) + '</li>' for item in report['limitations'])
    page.append('</ul><details><summary>Check results</summary><pre>' + escape(json.dumps(report['checks'], indent=2)) + '</pre></details>')
    if report.get('file_inventory'):
        page.append('<details><summary>File inventory</summary><pre>' + escape(json.dumps(report['file_inventory'], indent=2)) + '</pre></details>')
    page.append('</section><script>')
    page.append("""(function(){
var boxes=[].slice.call(document.querySelectorAll('input[data-level]')),search=document.getElementById('search'),items=[].slice.call(document.querySelectorAll('article.finding')),shown=document.getElementById('shown');
function update(){var on={},q=search.value.toLowerCase(),n=0;boxes.forEach(function(b){on[b.dataset.level]=b.checked});items.forEach(function(i){var v=on[i.dataset.level]&&i.dataset.text.indexOf(q)>=0;i.hidden=!v;if(v)n++});shown.textContent='Showing '+n+' of '+items.length+' findings';}
boxes.forEach(function(b){b.addEventListener('change',update)});search.addEventListener('input',update);update();
document.addEventListener('click',function(e){var c=e.target.dataset&&e.target.dataset.copy;if(c&&navigator.clipboard){navigator.clipboard.writeText(c).then(function(){e.target.textContent='Copied'})}});
})();""")
    page.append('</script></html>')
    return ''.join(page)

def write_atomic(path, text):
    """Publish complete files only, so an interrupted write cannot leave a damaged report."""
    pending = path.with_name(path.name + '.tmp')
    with pending.open('x', encoding='utf-8') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New report directory outside the website')
    parser.add_argument('--max-file-mb', type=int, default=2)
    parser.add_argument('--file-inventory', action='store_true', help='Save SHA-256 inventory from the same file reads')
    parser.add_argument('--max-files', type=int, default=100000)
    parser.add_argument('--core-version', help="Opt in to official checksum download for this known version, or 'auto' to read it from wp-includes/version.php")
    parser.add_argument('--rules', type=Path, help='Rule pack to use instead of rules.json beside this program')
    parser.add_argument('--fail-on', choices=SEVERITIES, help='Exit 4 if any finding has this priority or higher. Exit 0 otherwise still means only that the scan completed.')
    parser.add_argument('--command-profile', help='Profile path to show in the commands printed in the HTML report')
    parser.add_argument('--locale', default='en_US')
    parser.add_argument('--database', action='store_true', help='Prompt locally for database credentials')
    parser.add_argument('--db-from-wp-config', action='store_true', help='Check the database without prompting: read its details from wp-config.php as text, never executing it')
    parser.add_argument('--db-credentials', type=Path, help='Check the database without prompting: private JSON file outside the website')
    parser.add_argument('--php', default='php')
    parser.add_argument('--db-row-limit', type=int, default=10000)
    parser.add_argument('--db-value-limit', type=int, default=1048576, help='Maximum characters per selected database value (65536 to 4194304)')
    parser.add_argument('--plugins', action='store_true', help='Opt in to official WordPress.org plugin checksum downloads')
    parser.add_argument('--reference', action='append', default=[], help='Repeatable: plugin:folder=/private/reference.zip or theme:folder=/private/reference.zip')
    parser.add_argument('--persistence', action='store_true', help='Inventory common startup files and PHP configuration markers')
    parser.add_argument('--account-cron', action='store_true', help='Also list current SSH account crontab with command text redacted; implies --persistence')
    parser.add_argument('--separate-site', action='append', default=[], help='Repeatable: folder relative to --root that is scanned as its own site, so is skipped here')
    args = parser.parse_args()
    if any(item.startswith('/') or '\\' in item or '..' in item.split('/') for item in args.separate_site):
        parser.error('--separate-site must be a plain path relative to --root.')
    root, output = args.root.resolve(), args.output.resolve()
    if args.db_from_wp_config and args.db_credentials:
        parser.error('Use only one of --db-from-wp-config and --db-credentials.')
    if not root.is_dir() or not (root / 'wp-includes').is_dir():
        parser.error('--root must identify a WordPress installation with wp-includes.')
    if inside(output, root) or output.exists():
        parser.error('--output must be a NEW directory outside the website.')
    if not 1 <= args.max_file_mb <= 50 or not 1 <= args.max_files <= 1000000 or not 1 <= args.db_row_limit <= 100000:
        parser.error('Limits out of range (MB 1–50; files 1–1000000; DB rows 1–100000).')
    if not 65536 <= args.db_value_limit <= 4194304:
        parser.error('--db-value-limit must be between 65536 and 4194304 characters.')
    try:
        pack = load_rules(args.rules)
    except (OSError, ValueError, KeyError, TypeError, re.error) as error:
        parser.error('Could not load the rule pack: ' + str(error))
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    print('Scanning files with rule pack ' + pack['version'] + '. No website files will be modified.', flush=True)
    file_inventory = {} if args.file_inventory else None
    findings, hashes, limitations, visited = scan_files(root, args.max_file_mb * 1024 * 1024, args.max_files, file_inventory, set(args.separate_site))
    if file_inventory is not None:
        pending = output / 'file-inventory.json.tmp'
        with pending.open('x', encoding='utf-8') as stream:
            json.dump(file_inventory, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, output / 'file-inventory.json')
        print('File inventory saved: ' + str(output / 'file-inventory.json'), flush=True)
    checks = {'core': 'not requested', 'database': 'not requested', 'plugins': 'not requested'}
    if args.core_version:
        print('Downloading official core checksums...', flush=True)
        try:
            if args.core_version == 'auto':
                detected = version = detect_core_version(root)
            else:
                version = args.core_version
                try:
                    detected = detect_core_version(root)
                except (OSError, ValueError):
                    detected = version
            if detected != version:
                findings.append(dict(source='file', location='wp-includes/version.php', severity='review', rule='core-version-differs', line=None,
                                     reason=f'The site says it is WordPress {detected}, but this check used {version}. If you upgraded, update the profile or use --core-version auto; otherwise many core files will look changed.'))
            core, unchecked = check_core(root, hashes, version, args.locale)
            findings.extend(core)
            checks['core'] = f'Compared with {version} / {args.locale}; {unchecked} manifest files unchecked.'
        except Exception as exc:
            checks['core'] = 'FAILED: ' + type(exc).__name__
            limitations.append('Core checksum verification failed; no conclusion about core integrity.')
    if args.database or args.db_from_wp_config or args.db_credentials:
        try:
            credentials = wp_config_credentials(root) if args.db_from_wp_config else file_credentials(args.db_credentials, root) if args.db_credentials else None
            db = scan_database(args.php, Path(__file__).resolve().with_name('database.php'), args.db_row_limit, args.db_value_limit, credentials)
            findings.extend(db['findings'])
            findings.extend(check_active_plugins(db.get('sites', []), hashes))
            limitations.extend(db['limitations'])
            checks['database'] = db['summary']
        except Exception as exc:
            detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            checks['database'] = 'FAILED: ' + detail
            print('DATABASE CHECK FAILED: ' + detail, flush=True)
            limitations.append('Database inspection failed or was interrupted; no database conclusion.')
    if args.plugins:
        print('Checking WordPress.org plugin manifests; unavailable references will be marked unverified.', flush=True)
        try:
            plugin_findings, plugin_status = check_plugins(root, hashes)
            findings.extend(plugin_findings)
            checks['plugins'] = plugin_status
        except Exception as exc:
            checks['plugins'] = 'FAILED: ' + type(exc).__name__
            limitations.append('Plugin verification failed; no complete plugin integrity conclusion.')
    if args.reference:
        checks['references'] = []
        for specification in args.reference:
            try:
                reference_findings, reference_status = check_reference(root, hashes, specification)
                findings.extend(reference_findings)
                checks['references'].append(reference_status)
            except Exception as exc:
                checks['references'].append({'status': 'FAILED', 'reason': type(exc).__name__, 'target': specification.split('=', 1)[0]})
                limitations.append('A supplied reference ZIP comparison failed; check archive layout, target directory, and documented limits.')
    if args.persistence or args.account_cron:
        print('Inspecting common startup locations without executing site code...', flush=True)
        try:
            spec = importlib.util.spec_from_file_location('sentinel_persistence', Path(__file__).resolve().with_name('persistence.py'))
            persistence = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(persistence)
            startup_findings, startup_status, startup_limits = persistence.inspect(root, hashes, args.account_cron)
            findings.extend(startup_findings)
            checks['persistence'] = startup_status
            limitations.extend(startup_limits)
        except Exception as exc:
            checks['persistence'] = 'FAILED: ' + type(exc).__name__
            limitations.append('Optional persistence inspection failed; no startup-location conclusion.')
    limitations.extend([
        'Heuristic triage only: a report with no findings does not mean the site is clean.',
        'The scanner uses its own pattern rules, not an external malware signature service, and never changes site files. Optional file quarantine/restore is a separate utility. Plugin checks are optional. Theme and custom/premium plugin integrity requires explicitly supplied trusted reference ZIPs.',
        'Plugin identity/version is inferred from local headers, which may be modified. Custom/premium plugins, standalone files, mu-plugins, and renamed or ambiguous directories need trusted reference copies.',
        'Info and review entries are observations, not malware verdicts. Image marker classification checks container structure, not decoded pixels or server execution settings.',
        'Running processes, sibling websites, system configuration, and files outside the selected root are not inspected, apart from a wp-config.php directly above it. Account crontab is inspected only when explicitly requested.',
        'Live site files can change during scanning; for reliable forensics use a trusted offline snapshot.',
        'Symlinks are skipped where detected. This is not a secure sandbox against a hostile process changing directory paths during the scan.',
        'Reports contain relative file paths and database record identifiers; keep reports private.'
    ])
    # Add review fingerprints to reference findings only when bytes still match
    # the file snapshot used in that comparison. Missing files have no hash.
    for finding in findings:
        if finding.get('source') != 'file' or finding.get('sha256') or finding.get('location') not in hashes:
            continue
        path = root / finding['location']
        try:
            if path.is_symlink() or not inside(path.resolve(), root):
                continue
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
            with os.fdopen(os.open(path, flags), 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    continue
                data = stream.read(args.max_file_mb * 1024 * 1024 + 1)
            if len(data) <= args.max_file_mb * 1024 * 1024 and hashlib.md5(data).hexdigest() == hashes[finding['location']]:
                finding['sha256'] = hashlib.sha256(data).hexdigest()
                finding['content_complete'] = True
        except OSError:
            pass
    # Most important first. Finding numbers in the report and commands follow this order.
    findings.sort(key=lambda item: SEVERITIES.index(item['severity']) if item['severity'] in SEVERITIES else len(SEVERITIES))
    priorities = {level: sum(item['severity'] == level for item in findings) for level in SEVERITIES}
    report = dict(version=VERSION, rules_version=pack['version'], site_root=str(root), priority_counts=priorities, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  entries_visited=visited, files_inspected=len(hashes), checks=checks, findings=findings, limitations=limitations)
    if file_inventory is not None:
        report['file_inventory'] = {'filename': 'file-inventory.json', 'hashed_files': sum(e['status'] == 'hashed' for e in file_inventory['entries'].values()), 'traversal_complete': file_inventory['traversal_complete'], 'note': 'Saved from the file-scan phase; exclusions and skipped paths are listed in the inventory. Not an atomic snapshot or clean baseline.'}
    write_atomic(output / 'report.json', json.dumps(report, indent=2))
    write_atomic(output / 'report.html', render_report(report, output / 'report.json', args.command_profile))
    print(f'Finished: {len(hashes)} files inspected; {len(findings)} findings. Reports: {output}')
    print('Priority counts: ' + json.dumps(priorities))
    print('Review coverage and limitations before interpreting results. No quarantine actions were performed.')
    status = 0
    if any(isinstance(value, str) and value.startswith('FAILED:') for value in checks.values()):
        print('INCOMPLETE: an optional check failed. See the report for details.')
        status = 3
    if any(item.get('status') == 'FAILED' for item in checks.get('references', [])):
        print('INCOMPLETE: a reference ZIP comparison failed. See the report.')
        status = 3
    if isinstance(checks['database'], dict) and checks['database'].get('status') == 'partial':
        print('PARTIAL: database limits or table errors left some selected content unchecked.')
        status = 3
    if isinstance(checks.get('persistence'), dict) and checks['persistence'].get('status') == 'partial':
        print('PARTIAL: some startup locations or account-crontab details could not be inspected. See the report.')
        status = 3
    if args.fail_on:
        threshold = SEVERITIES[:SEVERITIES.index(args.fail_on) + 1]
        if any(priorities[level] for level in threshold):
            print(f'FINDINGS: at least one finding at {args.fail_on} priority or higher (exit 4).')
            return 4
    return status

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nInterrupted; report may be incomplete.', file=sys.stderr)
        sys.exit(130)
