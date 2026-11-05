#!/usr/bin/env python3
"""Swap reported core, plugin and theme files for verified clean copies, and undo it. Preview is the default.

A plan is made from a report, holding the clean copies it would use. You review it, and applying it
needs the plan's exact hash. Each original is backed up first, and the swap is atomic.
No automatic malware decisions are made.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.error
import zipfile

def load_sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

s = load_sibling('replace_sentinel', 'sentinel.py')
b = load_sibling('replace_batch', 'batch.py')
q = b.q
m = b.m

PLAN_FORMAT = '# sentinel-replace-plan-1'
MAX_ZIP_BYTES = 200 * 1024 * 1024
MISSING = 'missing'
OPTIONAL_CORE = {'readme.html', 'license.txt', 'licenses.txt', 'wp-config-sample.php'}
HEADER = """{format}
# Replacement plan. Each line below is one file that will be swapped for a clean copy.
# Review it, above all the sources listed here: is this the release you expect?
# Delete a line, or start it with #, to leave that file alone.
# Then preview this plan again, because editing it changes its hash.
# Columns, separated by tabs: current SHA-256 (or missing), clean SHA-256, source, rules, path.
# site_root: {root}
# report: {report}
# created_utc: {created}
"""

class NoSource(Exception):
    """No clean copy can be offered. The message says what to do instead."""

def owner_of(location):
    parts = location.split('/')
    if parts[0] != 'wp-content':
        return 'core', ''
    if len(parts) >= 4 and parts[1] in ('plugins', 'themes'):
        return parts[1][:-1], parts[2]
    return None

class Sources:
    """Opens each clean source at most once, and hands out its files only after verifying them."""
    def __init__(self, root, folder, references, core_version, locale):
        if locale == 'auto':
            try:
                locale = s.detect_core_locale(root)
            except OSError:
                locale = 'en_US'
        self.root, self.folder, self.core_version, self.locale = root, folder, core_version, locale
        self.references = dict(item.split('=', 1) for item in references)
        self.opened, self.described = {}, {}

    def close(self):
        for source in self.opened.values():
            if isinstance(source, dict):
                source['zip'].close()

    def get(self, owner):
        if owner not in self.opened:
            try:
                self.opened[owner] = self.open(owner)
            except NoSource as error:
                self.opened[owner] = error
        if isinstance(self.opened[owner], NoSource):
            raise self.opened[owner]
        return self.opened[owner]

    def core_version_to_use(self):
        try:
            detected = s.detect_core_version(self.root)
        except (OSError, ValueError):
            detected = None
        if self.core_version and detected and self.core_version != detected:
            raise NoSource(f'the site says WordPress {detected} but the profile says {self.core_version}: settle which is right, then make a new plan')
        if not self.core_version and not detected:
            raise NoSource('could not read the WordPress version: set it in the profile')
        return self.core_version or detected

    def fetch(self, name, url):
        archive = self.folder / 'downloads' / name
        archive.parent.mkdir(mode=0o700, exist_ok=True)
        try:
            s.download(url, archive, MAX_ZIP_BYTES)
        except urllib.error.HTTPError as error:
            raise NoSource(f'no official copy found (HTTP {error.code})')
        except (OSError, ValueError) as error:
            raise NoSource('download failed: ' + type(error).__name__)
        return archive

    def open(self, owner):
        kind, slug = owner
        target = f'{kind}:{slug}'
        if kind == 'core':
            version = self.core_version_to_use()
            try:
                manifest = s.core_manifest(version, self.locale)
            except (OSError, ValueError) as error:
                raise NoSource('official checksums unavailable: ' + type(error).__name__)
            folder = '' if self.locale == 'en_US' else self.locale + '/'
            archive = self.fetch('core.zip', f'https://downloads.wordpress.org/release/{folder}wordpress-{version}.zip')
            digests = {name: (digest.lower(),) for name, digest in manifest.items() if not name.startswith('wp-content/')}
            return self.opened_zip(archive, 'wordpress/', f'wordpress.org-core-{version}', digests, f'WordPress {version} {self.locale} from WordPress.org, checked against the official checksums', set(digests))
        directory = q.target_path(self.root, f'wp-content/{kind}s/{slug}')
        if target in self.references:
            return self.opened_zip(Path(self.references[target]), slug + '/', f'your-zip-{kind}-{slug}', None, f'{target} from your own ZIP, {Path(self.references[target]).name}. Sentinel cannot vouch for it.')
        if not re.fullmatch('[a-z0-9][a-z0-9-]*', slug) or not directory.is_dir():
            raise NoSource(f'not an ordinary {kind} folder: add --reference {target}=YOUR.zip if you have a trusted copy')
        version = s.plugin_version(directory) if kind == 'plugin' else s.theme_version(directory)
        if not version:
            raise NoSource(f'its version could not be read: add --reference {target}=YOUR.zip if you have a trusted copy')
        digests, note = None, 'Themes have no published checksums, so this rests on the HTTPS download alone.'
        if kind == 'plugin':
            try:
                digests = s.plugin_manifest(slug, version)
            except urllib.error.HTTPError as error:
                raise NoSource(f'no official copy of version {version} (HTTP {error.code}), as with premium plugins: add --reference {target}=YOUR.zip if you have a trusted copy')
            except (OSError, ValueError) as error:
                raise NoSource('official checksums unavailable: ' + type(error).__name__)
            note = 'Checked against the published plugin checksums.'
        try:
            archive = self.fetch(f'{kind}-{slug}.zip', s.public_zip_url(kind, slug, version))
        except NoSource as error:
            raise NoSource(f'{error}, as with premium {kind}s: add --reference {target}=YOUR.zip if you have a trusted copy')
        return self.opened_zip(archive, slug + '/', f'wordpress.org-{kind}-{slug}-{version}', digests, f'{target} {version} from WordPress.org. {note}')

    def opened_zip(self, archive, wrapper, label, digests, description, allowed=None):
        try:
            z = zipfile.ZipFile(archive)
            files, _ = s.safe_zip_files(z)
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            raise NoSource(f'the ZIP could not be used ({error})')
        wrapped = all(item.filename.startswith(wrapper) for item in files)
        if not wrapped and wrapper == 'wordpress/':
            raise NoSource('the official ZIP has an unexpected layout')
        members = {(item.filename[len(wrapper):] if wrapped else item.filename): item for item in files}
        if not any('/' not in name for name in members):
            raise NoSource(f'the ZIP has no files at its top level or under a {wrapper} folder')
        self.described[label] = description
        return {'zip': z, 'members': members, 'label': label, 'digests': digests, 'allowed': allowed}

    def clean_copy(self, source, name):
        """The clean bytes, or None if the source does not have this file."""
        if name not in source['members'] or (source['allowed'] is not None and name not in source['allowed']):
            return None
        with source['zip'].open(source['members'][name]) as stream:
            data = stream.read(q.MAX_BYTES + 1)
        if len(data) > q.MAX_BYTES:
            raise ValueError('official copy is too large')
        digests = source['digests']
        if digests is not None and hashlib.md5(data).hexdigest() not in digests.get(name, ()):
            raise ValueError('the downloaded copy does not match the official checksums')
        return data

def member_name(location, owner):
    if owner[0] == 'core':
        return location
    return location.split('/', 3)[3]

def make_plan(report_path, root, reviews_dir, output, references=(), core_version=None, locale='en_US', rules=(), paths=()):
    root = q.no_links(root)
    report = m.report_load(m.private_path(report_path, root), root)
    if 'site_root' not in report:
        raise ValueError('This report does not say which site it belongs to. Run a new scan.')
    reviews = m.read_reviews(m.private_path(reviews_dir, root), root) if reviews_dir else []
    for item in references:
        m.private_path(item.split('=', 1)[1], root)
    files = collections.OrderedDict()
    skipped = collections.Counter()
    entries, skipped_lines, written = [], [], set()
    def skip(reason, location):
        skipped[reason.split(': ')[0]] += 1
        skipped_lines.append(reason + '\t' + (location if b.plain_name(location) else repr(location)))
    for finding in report['findings']:
        if isinstance(finding, dict) and finding.get('source') == 'file':
            files.setdefault(str(finding.get('location', '')), []).append(finding)
        elif isinstance(finding, dict) and finding.get('severity') in ('high', 'medium', 'review'):
            # Listed, not just counted, so it is clear these still need dealing with another way.
            skip('database finding: clean copies replace files only', str(finding.get('severity')) + ' ' + str(finding.get('rule', '')) + ' in ' + str(finding.get('location', '')))
        else:
            skipped['database or other non-file finding'] += 1
    output = m.private_path(output, root)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'clean').mkdir(mode=0o700)
    sources = Sources(root, output, references, core_version, locale)
    try:
        for location, findings in files.items():
            if not b.wanted_path(location, paths):
                skip('outside the --path filter', location)
                continue
            selected = [item for item in findings if not rules or item.get('rule') in rules]
            if not selected:
                skip('not in --rule', location)
                continue
            selected = [item for item in selected if not m.review_status(item, reviews).startswith('Reviewed benign')]
            if not selected:
                skip('you reviewed it as benign', location)
                continue
            if location.startswith('../') or not b.plain_name(location):
                skip('outside the site, or unusual name', location)
                continue
            owner = owner_of(location)
            if owner is None:
                skip('no official copy exists for this location: if it should not be there, use Quarantine (batch-plan)', location)
                continue
            try:
                source = sources.get(owner)
                clean = sources.clean_copy(source, member_name(location, owner))
            except NoSource as error:
                skip(f'no clean copy: {error}', location)
                continue
            except (OSError, ValueError, zipfile.BadZipFile) as error:
                skip(f'clean copy refused: {error}', location)
                continue
            if clean is None:
                if location in b.ROOT_CRITICAL:
                    skip('this file is unique to your site: inspect and clean it by hand', location)
                else:
                    skip('not part of the official copy: if it should not be there, use Quarantine (batch-plan)', location)
                continue
            new = q.sha(clean)
            try:
                path = q.target_path(root, location)
                if os.path.lexists(path):
                    data, _ = q.read_regular(path)
                    old = q.sha(data)
                else:
                    old = MISSING
            except (OSError, ValueError) as error:
                skip(f'the current file cannot be replaced: {error}', location)
                continue
            if old == new:
                skip('already identical to the clean copy: the finding is a false alarm or was already fixed', location)
                continue
            if old == MISSING and location in OPTIONAL_CORE:
                skip('often removed on purpose: put it back by hand if you want it', location)
                continue
            scanned = {str(item.get('sha256')).lower() for item in findings if item.get('sha256')}
            if scanned and old not in scanned:
                skip('changed since the scan: find out why, and rescan', location)
                continue
            if new not in written:
                q.write_exclusive(output / 'clean' / (new + '.bin'), clean)
                written.add(new)
            entries.append((old, new, source['label'], ','.join(sorted(str(item.get('rule', '')) for item in selected)), location))
    finally:
        sources.close()
        shutil.rmtree(output / 'downloads', ignore_errors=True)
    if len(entries) > b.MAX_ENTRIES:
        raise ValueError(f'The plan would hold {len(entries)} files; the limit is {b.MAX_ENTRIES}. Narrow it with --path or --rule.')
    entries.sort(key=lambda item: item[4])
    used = {entry[2] for entry in entries}
    described = ''.join(f'# source: {label}: {sources.described[label]}\n' for label in sorted(used))
    plan = HEADER.format(format=PLAN_FORMAT, root=root, report=report_path, created=b.now()) + described + ''.join('\t'.join(entry) + '\n' for entry in entries)
    (output / 'plan.txt').write_bytes(plan.encode('utf-8'))
    (output / 'skipped.txt').write_bytes(('# Findings left out of the plan, and why.\n' + ''.join(line + '\n' for line in skipped_lines)).encode('utf-8'))
    return {'status': 'plan-created' if entries else 'nothing-to-replace', 'plan': str(output / 'plan.txt'), 'skipped_list': str(output / 'skipped.txt'),
            'files_in_plan': len(entries), 'to_put_back': sum(entry[0] == MISSING for entry in entries), 'sources': [sources.described[label] for label in sorted(used)], 'skipped': dict(skipped),
            'note': 'Nothing on the site was changed. Check that each source is the release you expect, and read plan.txt and skipped.txt. Then preview with replace-apply --plan.'}

def load_plan(path, root):
    path = m.private_path(path, root)
    raw, _ = q.read_regular(path)
    if len(raw) > b.MAX_PLAN_BYTES:
        raise ValueError('Plan is too large.')
    lines = raw.decode('utf-8').splitlines()
    if not lines or lines[0].strip() != PLAN_FORMAT:
        raise ValueError('Not a Sentinel replacement plan.')
    named = [line.split(':', 1)[1].strip() for line in lines if line.startswith('# site_root:')]
    if named != [str(root)]:
        raise ValueError('This plan belongs to another website root.')
    entries, seen = [], set()
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) != 5 or not re.fullmatch('[a-fA-F0-9]{64}', parts[1]) or not (parts[0] == MISSING or re.fullmatch('[a-fA-F0-9]{64}', parts[0])):
            raise ValueError(f'Line {number} of the plan is not valid. Nothing was changed.')
        if parts[4] in seen:
            raise ValueError(f'Line {number} repeats a file. Nothing was changed.')
        seen.add(parts[4])
        q.target_path(root, parts[4])
        entries.append({'old': parts[0].lower(), 'new': parts[1].lower(), 'path': parts[4]})
    if len(entries) > b.MAX_ENTRIES:
        raise ValueError(f'The plan holds {len(entries)} files; the limit is {b.MAX_ENTRIES}.')
    return path, entries, hashlib.sha256(raw).hexdigest()

def clean_bytes(plan_path, entry):
    data, _ = q.read_regular(q.no_links(plan_path.parent / 'clean' / (entry['new'] + '.bin')))
    if q.sha(data) != entry['new']:
        raise ValueError('the clean copy beside the plan has been altered')
    return data

def check_entry(root, store, plan_path, entry):
    """Returns (state, detail): ready, done or problem. Changes nothing."""
    try:
        path = q.target_path(root, entry['path'])
        if not os.path.lexists(path):
            if entry['old'] != MISSING:
                return 'problem', 'file has gone missing since the plan was made'
            q.add_missing(root, store, entry['path'], clean_bytes(plan_path, entry))
            return 'ready', None
        current, _ = q.read_regular(path)
        digest = q.sha(current)
        if digest == entry['new']:
            return 'done', None
        if digest != entry['old']:
            return 'problem', 'file has changed since the plan was made'
        q.replace(root, store, entry['path'], clean_bytes(plan_path, entry), entry['old'])
        return 'ready', None
    except (OSError, ValueError) as error:
        return 'problem', str(error)

def store_index(store, root):
    """Replacements the store holds, so an interrupted run can still be undone."""
    found = {}
    if not store.is_dir():
        return found
    for folder in store.iterdir():
        if not re.fullmatch('[a-f0-9]{32}', folder.name) or folder.is_symlink() or not folder.is_dir():
            continue
        try:
            record = m.load_json(folder / 'record.json')
        except (OSError, ValueError):
            continue
        if record.get('root') == str(root) and record.get('replacement_sha256') and record.get('status') in ('backed-up', 'replaced'):
            found[(record.get('relative_path'), record.get('sha256'), record['replacement_sha256'])] = folder.name
    return found

def active_events(plan_path):
    current = {}
    for event in b.read_receipt(plan_path):
        if event.get('event') == 'replaced':
            current[event.get('path')] = event
        elif event.get('event') == 'undone':
            current.pop(event.get('path'), None)
    return current

def apply_plan(root, store, plan, apply=False, expected=None, limit=None, skip_problems=False):
    root, store = q.setup(root, store)
    plan_path, entries, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    ready, done, problems = [], [], []
    for entry in entries:
        state, detail = check_entry(root, store, plan_path, entry)
        if state == 'ready':
            ready.append(entry)
        elif state == 'done':
            done.append(entry)
        else:
            problems.append({'file': entry['path'], 'problem': detail})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'files_in_plan': len(entries), 'ready': len(ready), 'already_done': len(done), 'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To go ahead, add --apply --plan-sha256 {digest}' if ready else 'No files are ready to replace.')
                       + (' Problems stop the whole batch unless you also add --skip-problems, or remove those lines from the plan.' if problems else ''),
                       warning='A clean copy overwrites any local edits in that file, though the original is kept in the store. Pause traffic if you can, and use --limit to go in stages.')
        return summary
    if problems and not skip_problems:
        summary.update(status='stopped-before-changes', note='Files differ from the plan, so nothing was changed. A file that changed since the scan may need another look. Rescan, or use --skip-problems to leave them where they are.')
        return summary
    active = active_events(plan_path)
    index = store_index(store, root) if done else {}
    for entry in done:
        # Finished by an interrupted run: record it so the undo can find it.
        if entry['path'] not in active:
            item = None if entry['old'] == MISSING else index.get((entry['path'], entry['old'], entry['new']))
            if item or entry['old'] == MISSING:
                b.write_event(plan_path, event='replaced', path=entry['path'], old=entry['old'], new=entry['new'], id=item, note='found already in place')
    moved, failed, in_a_row, stopped = 0, [], 0, False
    for entry in (ready if limit is None else ready[:limit]):
        try:
            clean = clean_bytes(plan_path, entry)
            if entry['old'] == MISSING:
                q.add_missing(root, store, entry['path'], clean, True)
                item = None
            else:
                item = q.replace(root, store, entry['path'], clean, entry['old'], True)['id']
        except (OSError, ValueError) as error:
            failed.append({'file': entry['path'], 'problem': str(error)})
            b.write_event(plan_path, event='failed', path=entry['path'], problem=str(error))
            in_a_row += 1
            if in_a_row >= b.STOP_AFTER_FAILURES:
                stopped = True
                break
            continue
        in_a_row = 0
        moved += 1
        b.write_event(plan_path, event='replaced', path=entry['path'], old=entry['old'], new=entry['new'], id=item)
    summary.update(status='stopped-after-repeated-failures' if stopped else 'partly-done' if failed or problems else 'stage-done' if moved < len(ready) else 'done', replaced=moved, failed=failed[:100], failed_count=len(failed), still_to_do=len(ready) - moved,
                   note='Check the site now, then run a new scan: replacing files does not clear caches, end sessions or close the way in. Undo with replace-undo --plan.')
    return summary

def undo_plan(root, store, plan, apply=False, expected=None, only=()):
    root, store = q.setup(root, store)
    plan_path, _, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    current = active_events(plan_path)
    unknown = [item for item in only if item not in current]
    if unknown:
        raise ValueError('Not currently replaced by this plan: ' + ', '.join(unknown[:10]))
    ready, problems = [], []
    for path in reversed(list(current)):
        if only and path not in only:
            continue
        event = current[path]
        try:
            if event.get('old') == MISSING:
                q.remove_added(root, store, path, event['new'])
            else:
                preview = q.undo_replace(root, store, str(event.get('id')))
                if preview['file'] != path:
                    raise ValueError('Store record does not match the receipt.')
            ready.append(event)
        except (OSError, ValueError, KeyError, TypeError) as error:
            problems.append({'file': path, 'problem': str(error)})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'ready': len(ready), 'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To put the originals back, add --apply --plan-sha256 {digest}' if ready else 'No files are ready to undo.'),
                       warning='Undoing brings back the original files, including any malware among them. Use --only to undo just the ones you need.')
        return summary
    undone, failed = 0, []
    for event in ready:
        try:
            if event.get('old') == MISSING:
                q.remove_added(root, store, event['path'], event['new'], True)
            else:
                q.undo_replace(root, store, event['id'], True)
        except (OSError, ValueError) as error:
            failed.append({'file': event['path'], 'problem': str(error)})
            continue
        undone += 1
        b.write_event(plan_path, event='undone', path=event['path'], id=event.get('id'))
    summary.update(status='partly-done' if failed or problems else 'done', undone=undone, failed=failed[:100], failed_count=len(failed), note='The original files are active again. Their backups stay in the store.')
    return summary

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    c = sub.add_parser('plan')
    c.add_argument('--root', required=True, type=Path)
    c.add_argument('--report', required=True, type=Path)
    c.add_argument('--reviews', type=Path)
    c.add_argument('--output', required=True, type=Path)
    c.add_argument('--core-version')
    c.add_argument('--locale', default='en_US')
    c.add_argument('--rule', action='append', default=[])
    c.add_argument('--path', action='append', default=[])
    c.add_argument('--reference', action='append', default=[])
    for name in ('apply', 'undo'):
        c = sub.add_parser(name)
        c.add_argument('--root', required=True, type=Path)
        c.add_argument('--store', required=True, type=Path)
        c.add_argument('--plan', required=True, type=Path)
        c.add_argument('--apply', action='store_true')
        c.add_argument('--plan-sha256')
        if name == 'apply':
            c.add_argument('--limit', type=int)
            c.add_argument('--skip-problems', action='store_true')
        else:
            c.add_argument('--only', action='append', default=[])
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'plan':
            result = make_plan(args.report, args.root, args.reviews, args.output, args.reference, args.core_version, args.locale, args.rule, args.path)
        elif args.action == 'apply':
            if args.limit is not None and args.limit < 1:
                raise ValueError('--limit must be at least 1.')
            result = apply_plan(args.root, args.store, args.plan, args.apply, args.plan_sha256, args.limit, args.skip_problems)
        else:
            result = undo_plan(args.root, args.store, args.plan, args.apply, args.plan_sha256, args.only)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        print('If a plan was being applied, read receipt.jsonl beside it. Running the same plan again carries on safely.', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return b.exit_code(result)

if __name__ == '__main__':
    sys.exit(main())
