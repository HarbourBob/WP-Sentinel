#!/usr/bin/env python3
"""Find the way in: check installed core, plugin and theme versions against the Wordfence Intelligence vulnerability feed.
Offline apart from downloading the feed. The API key is read from a file or WORDFENCE_API_KEY and never saved."""
import argparse
import datetime
import functools
import html
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production'
SOURCE = 'Wordfence Intelligence vulnerability data feed (production)'
MAX_FEED_BYTES = 1024 * 1024 * 1024
RATINGS = ('Critical', 'High', 'Medium', 'Low', 'None')
NOTE = ('A vulnerable version is a likely way in, not proof of how this site was entered. Fix these as well as removing malware: '
        'removing malware without closing the entry point usually means reinfection. Versions are read from file headers, which an attacker can edit, '
        'and custom code, must-use plugins and anything missing from the feed are not covered. No result here does not mean the site is safe.')

def now():
    return datetime.datetime.now(datetime.timezone.utc)

# Ordering of version words, as PHP's version_compare uses them; WordPress compares versions the same way.
SPECIAL = {'dev': 0, 'alpha': 1, 'a': 1, 'beta': 2, 'b': 2, 'rc': 3, '#': 4, 'pl': 5, 'p': 5}

def version_parts(value):
    value = re.sub(r'[-_+]', '.', str(value).strip())
    value = re.sub(r'(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)', '.', value)
    return [part for part in value.split('.') if part]

def compare_versions(a, b):
    """-1, 0 or 1, following PHP's version_compare."""
    def special(part):
        return SPECIAL.get(part.lower(), -1)
    pa, pb = version_parts(a), version_parts(b)
    for x, y in zip(pa, pb):
        if x.isdigit() and y.isdigit():
            result = (int(x) > int(y)) - (int(x) < int(y))
        else:
            sx, sy = (SPECIAL['#'] if x.isdigit() else special(x)), (SPECIAL['#'] if y.isdigit() else special(y))
            result = (sx > sy) - (sx < sy)
        if result:
            return result
    if len(pa) == len(pb):
        return 0
    longer, sign = (pb, -1) if len(pb) > len(pa) else (pa, 1)
    extra = longer[min(len(pa), len(pb))]
    if extra.isdigit():
        return sign
    return sign * ((special(extra) > SPECIAL['#']) - (special(extra) < SPECIAL['#']))

def in_range(version, rng):
    low, high = rng.get('from_version', '*'), rng.get('to_version', '*')
    if low != '*':
        c = compare_versions(version, low)
        if c < 0 or (c == 0 and not rng.get('from_inclusive', True)):
            return False
    if high != '*':
        c = compare_versions(version, high)
        if c > 0 or (c == 0 and not rng.get('to_inclusive', True)):
            return False
    return True

def read_key(key_file=None):
    if key_file:
        path = Path(key_file)
        if os.name == 'posix' and path.stat().st_mode & 0o077:
            raise ValueError('The API key file must have permissions 600.')
        key = path.read_text(encoding='utf-8-sig').strip()
    else:
        key = os.environ.get('WORDFENCE_API_KEY', '').strip()
    if key and not re.fullmatch(r'[\x21-\x7e]{8,1024}', key):
        raise ValueError('The API key does not look right: expected one line of printable characters.')
    return key or None

def slim(feed):
    """Keep only what matching and the report need; the full feed is large."""
    index = []
    for vid, record in feed.items():
        if not isinstance(record, dict) or not isinstance(record.get('software'), list):
            continue
        cvss = record.get('cvss') if isinstance(record.get('cvss'), dict) else {}
        refs = [r for r in record.get('references') or [] if isinstance(r, str) and r.startswith('https://')]
        rights = record.get('copyrights') if isinstance(record.get('copyrights'), dict) else {}
        index.append(dict(
            id=str(record.get('id', vid)), title=str(record.get('title', '')), informational=bool(record.get('informational')),
            score=cvss.get('score') if isinstance(cvss.get('score'), (int, float)) else None,
            rating=cvss.get('rating') if cvss.get('rating') in RATINGS else None,
            cve=record.get('cve') if isinstance(record.get('cve'), str) else None, published=record.get('published'),
            link=refs[0] if refs else 'https://www.wordfence.com/threat-intel/vulnerabilities/id/' + str(record.get('id', vid)),
            copyrights={k: {f: str(v.get(f, '')) for f in ('notice', 'license', 'license_url')} for k, v in rights.items() if isinstance(v, dict)},
            software=[dict(type=s.get('type'), slug=str(s.get('slug', '')), affected=[r for r in (s.get('affected_versions') or {}).values() if isinstance(r, dict)],
                           patched=bool(s.get('patched')), patched_versions=[str(v) for v in s.get('patched_versions') or []],
                           remediation=str(s.get('remediation') or ''))
                      for s in record['software'] if isinstance(s, dict) and s.get('type') in ('core', 'plugin', 'theme')]))
    return index

def write_index(index, cache, downloaded):
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = cache / 'wordfence-index.json.tmp'
    pending.write_text(json.dumps({'format': 'sentinel-vuln-index-1', 'source': SOURCE, 'downloaded_utc': downloaded, 'vulnerabilities': index}), encoding='utf-8')
    os.replace(pending, cache / 'wordfence-index.json')

def download(key, cache):
    """Fetch the whole feed to disk, then keep the slim index. Returns the index file contents."""
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = urllib.request.Request(FEED_URL, headers={'Authorization': 'Bearer ' + key, 'User-Agent': 'wp-sentinel'})
    pending = cache / 'wordfence-feed.json.tmp'
    try:
        with urllib.request.urlopen(request, timeout=300) as response, pending.open('wb') as target:
            total = 0
            while True:
                chunk = response.read(1048576)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FEED_BYTES:
                    raise ValueError('The feed is larger than expected; stopped downloading.')
                target.write(chunk)
        downloaded = now().isoformat()
        index = slim(json.loads(pending.read_text(encoding='utf-8')))
    finally:
        pending.unlink(missing_ok=True)
    write_index(index, cache, downloaded)
    return {'downloaded_utc': downloaded, 'vulnerabilities': index}

def load_feed(cache, key=None, feed_file=None, max_age_hours=24):
    """The feed index and any note about its age. Uses the cache while fresh, so the API is asked at most once a day."""
    notes = []
    if feed_file:
        index = slim(json.loads(Path(feed_file).read_text(encoding='utf-8')))
        return {'downloaded_utc': datetime.datetime.fromtimestamp(Path(feed_file).stat().st_mtime, datetime.timezone.utc).isoformat(), 'vulnerabilities': index}, notes
    cached = cache / 'wordfence-index.json'
    data = json.loads(cached.read_text(encoding='utf-8')) if cached.is_file() else None
    age = now() - datetime.datetime.fromisoformat(data['downloaded_utc']) if data else None
    if data and age < datetime.timedelta(hours=max_age_hours):
        return data, notes
    if not key:
        if data:
            notes.append(f'No API key given, so the cached feed from {data["downloaded_utc"][:16]} UTC was used.')
            return data, notes
        raise ValueError('No vulnerability feed yet. Create a free Wordfence Intelligence API key and pass --vuln-key-file, or set WORDFENCE_API_KEY. See VULNERABILITIES.txt.')
    try:
        return download(key, cache), notes
    except urllib.error.HTTPError as error:
        error.close()
        reason = {401: 'the API key was refused', 403: 'the API key was refused', 429: 'Wordfence is limiting requests; try again later'}.get(error.code, f'HTTP {error.code}')
    except (urllib.error.URLError, OSError, ValueError) as error:
        reason = type(error).__name__
    if data:
        notes.append(f'Could not refresh the feed ({reason}); the cached copy from {data["downloaded_utc"][:16]} UTC was used.')
        return data, notes
    raise ValueError('Could not download the vulnerability feed: ' + reason + '.')

def check(software, feed, notes=()):
    by_key = {}
    for record in feed['vulnerabilities']:
        for item in record['software']:
            by_key.setdefault((item['type'], item['slug'] if item['type'] != 'core' else ''), []).append((record, item))
    installed = []
    if software.get('core'):
        installed.append(('core', '', 'WordPress core', software['core']))
    unchecked = [] if software.get('core') else [dict(type='core', slug='wordpress', reason='Core version could not be read.')]
    for kind, label in (('plugins', 'plugin'), ('themes', 'theme')):
        for entry in software.get(kind, []):
            if entry.get('version'):
                installed.append((label, entry['slug'], entry['slug'], entry['version']))
            else:
                unchecked.append(dict(type=label, slug=entry['slug'], reason='No readable version header.'))
    found = []
    for kind, slug, name, version in installed:
        for record, item in by_key.get((kind, slug), []):
            if any(in_range(version, rng) for rng in item['affected']):
                fixed = sorted((v for v in item['patched_versions'] if compare_versions(v, version) > 0), key=functools.cmp_to_key(compare_versions))
                found.append(dict(type=kind, slug=slug or 'wordpress', name=name, installed_version=version, id=record['id'], title=record['title'],
                                  rating=record['rating'], score=record['score'], cve=record['cve'], informational=record['informational'],
                                  patched=item['patched'], fixed_in=fixed[:1],
                                  remediation=item['remediation'] or ('Update to ' + fixed[0] + ' or newer.' if fixed else 'No fixed version is known: remove or replace it.'),
                                  link=record['link'], published=record['published'], copyrights=record['copyrights']))
    found.sort(key=lambda v: (v['informational'], -(v['score'] or 0), v['type'], v['slug'], v['title']))
    counts = {r: sum(1 for v in found if v['rating'] == r and not v['informational']) for r in RATINGS}
    counts['informational'] = sum(1 for v in found if v['informational'])
    counts['unrated'] = sum(1 for v in found if v['rating'] is None and not v['informational'])
    return dict(format='sentinel-vulnerabilities-1', source=SOURCE, feed_downloaded_utc=feed['downloaded_utc'], created_utc=now().isoformat(), note=NOTE,
                checked=len(installed), affected_software=len({(v['type'], v['slug']) for v in found}), counts=counts,
                vulnerabilities=found, unchecked=unchecked, limitations=list(notes))

def render(result):
    e = lambda v: html.escape('' if v is None else str(v))
    page = ['<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel vulnerabilities</title>'
            '<style>body{font:15px system-ui;max-width:1100px;margin:2em auto;padding:0 1em}table{border-collapse:collapse;width:100%;font-size:14px}'
            'td,th{border-bottom:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}.r-Critical,.r-High{color:#b00020;font-weight:600}'
            '.scroll{overflow-x:auto}small{color:#555}</style>',
            '<h1>Find the way in</h1><p>' + e(result['note']) + '</p><p>Checked ' + e(result['checked']) + ' installed items against the ' + e(result['source'])
            + ', downloaded ' + e(result['feed_downloaded_utc'][:16].replace('T', ' ')) + ' UTC. ' + e(len(result['vulnerabilities'])) + ' known vulnerabilities in '
            + e(result['affected_software']) + ' items.</p>']
    for item in result['limitations']:
        page.append('<p><strong>' + e(item) + '</strong></p>')
    page.append('<div class="scroll"><table><tr><th>Severity</th><th>Software</th><th>Installed</th><th>Vulnerability</th><th>Fix</th></tr>')
    for v in result['vulnerabilities']:
        severity = 'Informational' if v['informational'] else (v['rating'] or 'Unrated') + (f' {v["score"]}' if v['score'] is not None else '')
        page.append('<tr><td class="r-' + e(v['rating']) + '">' + e(severity) + '</td><td>' + e(v['type']) + ': ' + e(v['slug']) + '</td><td>' + e(v['installed_version'])
                    + '</td><td><a href="' + e(v['link']) + '">' + e(v['title']) + '</a>' + (' (' + e(v['cve']) + ')' if v['cve'] else '')
                    + ''.join('<br><small>' + e(c['notice']) + '</small>' for c in v['copyrights'].values() if c.get('notice'))
                    + '</td><td>' + e(v['remediation']) + '</td></tr>')
    if not result['vulnerabilities']:
        page.append('<tr><td colspan="5">No known vulnerabilities matched the installed versions.</td></tr>')
    page.append('</table></div>')
    if result['unchecked']:
        page.append('<h2>Not checked (' + e(len(result['unchecked'])) + ')</h2><ul>' + ''.join('<li>' + e(u['type']) + ': ' + e(u['slug']) + ' — ' + e(u['reason']) + '</li>' for u in result['unchecked']) + '</ul>')
    licences = {}
    for v in result['vulnerabilities']:
        for c in v['copyrights'].values():
            if c.get('license'):
                licences[c['notice']] = c
    if licences:
        page.append('<h2>Copyright</h2>' + ''.join('<p><small>' + e(c['notice']) + '. ' + e(c['license']) + ' <a href="' + e(c['license_url']) + '">' + e(c['license_url']) + '</a></small></p>'
                                                  for c in licences.values()))
    return ''.join(page)

def write(result, folder):
    (folder / 'vulnerabilities.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (folder / 'vulnerabilities.html').write_text(render(result), encoding='utf-8')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True, help='report.json from a scan')
    p.add_argument('--output', type=Path, required=True, help='New folder for vulnerabilities.json and vulnerabilities.html')
    p.add_argument('--cache', type=Path, required=True, help='Private folder that keeps the downloaded feed between runs')
    p.add_argument('--key-file', type=Path, help='File holding your Wordfence Intelligence API key; otherwise WORDFENCE_API_KEY is used')
    p.add_argument('--feed-file', type=Path, help='Use a feed file you downloaded yourself instead')
    p.add_argument('--max-age-hours', type=int, default=24)
    a = p.parse_args(); os.umask(0o077)
    try:
        report = json.loads(a.report.read_text(encoding='utf-8'))
        if not isinstance(report.get('software'), dict):
            raise ValueError('This report has no software list. Run a new scan with this version of Sentinel.')
        feed, notes = load_feed(a.cache, read_key(a.key_file), a.feed_file, a.max_age_hours)
        result = check(report['software'], feed, notes)
        result['report'] = str(a.report)
        a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        write(result, a.output)
        print(json.dumps(dict(status='vulnerabilities-checked', output=str(a.output), checked=result['checked'], counts=result['counts'], limitations=result['limitations']), indent=2)); return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error)); return 2

if __name__ == '__main__':
    raise SystemExit(main())
