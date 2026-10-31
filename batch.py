#!/usr/bin/env python3
"""Quarantine many reviewed files from one plan, and undo it. Preview is the default.

A plan is a text file made from a report. You review it, deleting lines to spare files, and
applying it needs the plan's exact hash. Every file still goes through quarantine.py, so it is
hash-checked and backed up before removal. No automatic malware decisions are made.
"""
import argparse
import collections
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

def load_sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

q = load_sibling('batch_quarantine', 'quarantine.py')
m = load_sibling('batch_manage', 'manage.py')

PLAN_FORMAT = '# sentinel-quarantine-plan-1'
PRIORITIES = ('high', 'medium', 'review')
MAX_ENTRIES = 5000
MAX_PLAN_BYTES = 8 * 1024 * 1024
STOP_AFTER_FAILURES = 5
ROOT_CRITICAL = {'.htaccess', 'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php', 'wp-cron.php',
                 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'}
HEADER = """{format}
# Quarantine plan. Each line below is one file that will be moved out of the website.
# Review it. Delete a line, or start it with #, to leave that file alone.
# Then preview this plan again, because editing it changes its hash.
# Columns, separated by tabs: SHA-256, priority, rules, path.
# site_root: {root}
# report: {report}
# created_utc: {created}
"""

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def critical(location, rules):
    """Files WordPress needs in order to run. These usually need replacing, not just removing."""
    if 'core-checksum-mismatch' in rules or location in ROOT_CRITICAL:
        return True
    return location.startswith(('wp-admin/', 'wp-includes/')) and 'unexpected-core-file' not in rules

def plain_name(location):
    if re.search(r'[\x00-\x1f\x7f]', location) or location != location.strip():
        return False
    try:
        location.encode('utf-8')
    except UnicodeError:
        return False
    return True

def wanted_path(location, paths):
    return not paths or any(location == item.rstrip('/') or location.startswith(item.rstrip('/') + '/') for item in paths)

def make_plan(report_path, root, reviews_dir, output, priority='high', rules=(), paths=(), include_critical=False):
    root = q.no_links(root)
    report = m.report_load(m.private_path(report_path, root), root)
    if 'site_root' not in report:
        raise ValueError('This report does not say which site it belongs to. Run a new scan.')
    reviews = m.read_reviews(m.private_path(reviews_dir, root), root) if reviews_dir else []
    allowed = PRIORITIES[:PRIORITIES.index(priority) + 1]
    files = collections.OrderedDict()
    skipped = collections.Counter()
    for finding in report['findings']:
        if isinstance(finding, dict) and finding.get('source') == 'file':
            files.setdefault(str(finding.get('location', '')), []).append(finding)
        else:
            skipped['database or other non-file finding'] += 1
    entries, skipped_lines = [], []
    def skip(reason, location):
        skipped[reason] += 1
        skipped_lines.append(reason + '\t' + (location if plain_name(location) else repr(location)))
    for location, findings in files.items():
        names = {str(item.get('rule', '')) for item in findings}
        if not wanted_path(location, paths):
            skip('outside the --path filter', location)
            continue
        selected = [item for item in findings if item.get('severity') in allowed and (not rules or item.get('rule') in rules)]
        if not selected:
            skip('below the chosen priority, or not in --rule', location)
            continue
        selected = [item for item in selected if not m.review_status(item, reviews).startswith('Reviewed benign')]
        if not selected:
            skip('you reviewed it as benign', location)
            continue
        if location.startswith('../') or not plain_name(location):
            skip('outside the site, or unusual name: handle it with file-quarantine', location)
            continue
        hashes = {str(item.get('sha256', '')).lower() for item in findings if item.get('sha256')}
        if len(hashes) != 1 or not all(m.reviewable(item) for item in selected):
            skip('no complete file hash, or the file was missing or too large', location)
            continue
        if critical(location, names) and not include_critical:
            skip('WordPress needs this file: review it yourself, or use --include-critical', location)
            continue
        best = next(level for level in PRIORITIES if any(item['severity'] == level for item in selected))
        entries.append((hashes.pop(), best, ','.join(sorted(str(item.get('rule', '')) for item in selected)), location))
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f'The plan would hold {len(entries)} files; the limit is {MAX_ENTRIES}. Narrow it with --path or --rule.')
    entries.sort(key=lambda item: (PRIORITIES.index(item[1]), item[3]))
    output = m.private_path(output, root)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan = HEADER.format(format=PLAN_FORMAT, root=root, report=report_path, created=now()) + ''.join('\t'.join(entry) + '\n' for entry in entries)
    (output / 'plan.txt').write_bytes(plan.encode('utf-8'))
    (output / 'skipped.txt').write_bytes(('# Findings left out of the plan, and why.\n' + ''.join(line + '\n' for line in skipped_lines)).encode('utf-8'))
    folders = collections.Counter('/'.join(entry[3].split('/')[:3]) if '/' in entry[3] else '(site root)' for entry in entries)
    return {'status': 'plan-created' if entries else 'nothing-to-quarantine', 'plan': str(output / 'plan.txt'), 'skipped_list': str(output / 'skipped.txt'),
            'files_in_plan': len(entries), 'by_priority': dict(collections.Counter(entry[1] for entry in entries)), 'by_folder': dict(folders.most_common(15)), 'skipped': dict(skipped),
            'note': 'Nothing was changed. Read plan.txt and skipped.txt. Then preview with batch-quarantine --plan.'}

def load_plan(path, root):
    path = m.private_path(path, root)
    raw, _ = q.read_regular(path)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError('Plan is too large.')
    lines = raw.decode('utf-8').splitlines()
    if not lines or lines[0].strip() != PLAN_FORMAT:
        raise ValueError('Not a Sentinel quarantine plan.')
    named = [line.split(':', 1)[1].strip() for line in lines if line.startswith('# site_root:')]
    if named != [str(root)]:
        raise ValueError('This plan belongs to another website root.')
    entries, seen = [], set()
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) != 4 or not re.fullmatch('[a-fA-F0-9]{64}', parts[0]):
            raise ValueError(f'Line {number} of the plan is not valid. Nothing was changed.')
        if parts[3] in seen:
            raise ValueError(f'Line {number} repeats a file. Nothing was changed.')
        seen.add(parts[3])
        q.target_path(root, parts[3])
        entries.append({'sha256': parts[0].lower(), 'priority': parts[1], 'rules': parts[2], 'path': parts[3]})
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f'The plan holds {len(entries)} files; the limit is {MAX_ENTRIES}.')
    return path, entries, hashlib.sha256(raw).hexdigest()

def read_receipt(plan_path):
    """Events so far, oldest first. A crash can only damage the last line, which is ignored."""
    path = plan_path.with_name('receipt.jsonl')
    events = []
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return events

def write_event(plan_path, **event):
    with plan_path.with_name('receipt.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(dict(event, utc=now())) + '\n')
        stream.flush()
        os.fsync(stream.fileno())

def store_index(store, root):
    """What the store already holds, so an interrupted run does not look like missing files."""
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
        if record.get('root') == str(root) and record.get('status') in ('backed-up', 'quarantined'):
            found[(record.get('relative_path'), record.get('sha256'))] = folder.name
    return found

def check_entry(root, store, entry, index):
    """Returns (state, detail): ready, done or problem. Changes nothing."""
    try:
        path = q.target_path(root, entry['path'])
        if not os.path.lexists(path):
            item = index.get((entry['path'], entry['sha256']))
            return ('done', item) if item else ('problem', 'file is missing and not in the store')
        q.quarantine(root, store, entry['path'], False, entry['sha256'])
        return 'ready', None
    except (OSError, ValueError) as error:
        return 'problem', str(error)

def apply_plan(root, store, plan, apply=False, expected=None, limit=None, skip_problems=False):
    root, store = q.setup(root, store)
    plan_path, entries, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    index = store_index(store, root)
    ready, done, problems = [], [], []
    for entry in entries:
        state, detail = check_entry(root, store, entry, index)
        if state == 'ready':
            ready.append(entry)
        elif state == 'done':
            done.append((entry, detail))
        else:
            problems.append({'file': entry['path'], 'problem': detail})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'files_in_plan': len(entries), 'ready': len(ready), 'already_in_store': len(done), 'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To go ahead, add --apply --plan-sha256 {digest}' if ready else 'No files are ready to move.')
                       + (' Problems stop the whole batch unless you also add --skip-problems, or remove those lines from the plan.' if problems else ''),
                       warning='Removing files can break the site. Pause traffic if you can, and use --limit to go in stages so you can check the site between them.')
        return summary
    if problems and not skip_problems:
        summary.update(status='stopped-before-changes', note='Files differ from the plan, so nothing was changed. A file that changed since the scan may need another look. Rescan, or use --skip-problems to leave them where they are.')
        return summary
    known = {(event.get('path'), event.get('sha256')) for event in read_receipt(plan_path) if event.get('event') == 'quarantined'}
    for entry, item in done:
        # Finished by an interrupted run, or by hand: record it so the undo can find it.
        if (entry['path'], entry['sha256']) not in known:
            write_event(plan_path, event='quarantined', path=entry['path'], sha256=entry['sha256'], id=item, note='found in store')
    moved, failed, in_a_row = 0, [], 0
    selected = ready if limit is None else ready[:limit]
    stopped = False
    for entry in selected:
        try:
            result = q.quarantine(root, store, entry['path'], True, entry['sha256'])
        except (OSError, ValueError) as error:
            failed.append({'file': entry['path'], 'problem': str(error)})
            write_event(plan_path, event='failed', path=entry['path'], sha256=entry['sha256'], problem=str(error))
            in_a_row += 1
            if in_a_row >= STOP_AFTER_FAILURES:
                stopped = True
                break
            continue
        in_a_row = 0
        moved += 1
        write_event(plan_path, event='quarantined', path=entry['path'], sha256=entry['sha256'], id=result['id'])
    summary.update(status='stopped-after-repeated-failures' if stopped else 'partly-done' if failed or problems else 'stage-done' if moved < len(ready) else 'done', moved=moved, failed=failed[:100], failed_count=len(failed), still_to_do=len(ready) - moved,
                   note='Check the site now, then run a new scan: quarantine does not clear caches, end sessions or close the way in. Undo with batch-restore --plan.')
    return summary

def restore_plan(root, store, plan, apply=False, expected=None, only=()):
    root, store = q.setup(root, store)
    plan_path, _, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    current = {}
    for event in read_receipt(plan_path):
        if event.get('event') == 'quarantined':
            current[event.get('path')] = event
        elif event.get('event') == 'restored':
            current.pop(event.get('path'), None)
    unknown = [item for item in only if item not in current]
    if unknown:
        raise ValueError('Not currently quarantined by this plan: ' + ', '.join(unknown[:10]))
    items = [current[path] for path in reversed(list(current)) if not only or path in only]
    ready, problems = [], []
    for event in items:
        try:
            preview = q.restore(root, store, str(event.get('id')), False, event.get('sha256'))
            if preview['file'] != event['path']:
                raise ValueError('Store record does not match the receipt.')
            ready.append(event)
        except (OSError, ValueError, KeyError, TypeError) as error:
            problems.append({'file': event.get('path'), 'problem': str(error)})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'ready': len(ready), 'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To put these files back, add --apply --plan-sha256 {digest}' if ready else 'No files are ready to restore.'),
                       warning='Restoring reactivates these files, including any malware among them. Use --only to restore just the ones you need.')
        return summary
    restored, failed = 0, []
    for event in ready:
        try:
            q.restore(root, store, event['id'], True, event['sha256'])
        except (OSError, ValueError) as error:
            failed.append({'file': event['path'], 'problem': str(error)})
            continue
        restored += 1
        write_event(plan_path, event='restored', path=event['path'], sha256=event['sha256'], id=event['id'])
    summary.update(status='partly-done' if failed or problems else 'done', restored=restored, failed=failed[:100], failed_count=len(failed), note='Backups stay in the store. These files are active again.')
    return summary

def exit_code(result):
    return 3 if result.get('status', '').startswith(('stopped', 'partly')) else 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    c = sub.add_parser('plan')
    c.add_argument('--root', required=True, type=Path)
    c.add_argument('--report', required=True, type=Path)
    c.add_argument('--reviews', type=Path)
    c.add_argument('--output', required=True, type=Path)
    c.add_argument('--priority', choices=PRIORITIES, default='high')
    c.add_argument('--rule', action='append', default=[])
    c.add_argument('--path', action='append', default=[])
    c.add_argument('--include-critical', action='store_true')
    for name in ('quarantine', 'restore'):
        c = sub.add_parser(name)
        c.add_argument('--root', required=True, type=Path)
        c.add_argument('--store', required=True, type=Path)
        c.add_argument('--plan', required=True, type=Path)
        c.add_argument('--apply', action='store_true')
        c.add_argument('--plan-sha256')
        if name == 'quarantine':
            c.add_argument('--limit', type=int)
            c.add_argument('--skip-problems', action='store_true')
        else:
            c.add_argument('--only', action='append', default=[])
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'plan':
            result = make_plan(args.report, args.root, args.reviews, args.output, args.priority, args.rule, args.path, args.include_critical)
        elif args.action == 'quarantine':
            if args.limit is not None and args.limit < 1:
                raise ValueError('--limit must be at least 1.')
            result = apply_plan(args.root, args.store, args.plan, args.apply, args.plan_sha256, args.limit, args.skip_problems)
        else:
            result = restore_plan(args.root, args.store, args.plan, args.apply, args.plan_sha256, args.only)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        print('If a batch was being applied, read receipt.jsonl beside the plan. Running the same plan again carries on safely.', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return exit_code(result)

if __name__ == '__main__':
    sys.exit(main())
