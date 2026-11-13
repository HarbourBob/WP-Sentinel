#!/usr/bin/env python3
"""Remove reviewed pieces of flagged code from database entries, from one plan, and undo it. Preview is the default.

A plan is made from a report. Each line is one piece of code (a script element, a hidden iframe or a PHP
block) inside one database value. You review it, deleting lines to keep pieces, and applying it needs the
plan's exact hash. db-fix.php does the database work: each original value is kept for undo, the change is
all-or-nothing, and nothing else in the value is touched. No automatic malware decisions are made.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

def load_sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

b = load_sibling('dbfix_batch', 'batch.py')
s = load_sibling('dbfix_sentinel', 'sentinel.py')
q = b.q
m = b.m

PLAN_FORMAT = '# sentinel-dbfix-plan-1'
# Findings whose flagged code this tool knows how to take out.
RULES = {'db-script-tag', 'db-encoded-execution', 'db-obfuscated-javascript', 'db-php-tag', 'db-hidden-iframe'}
HEADER = """{format}
# Database fix plan. Each line below is one piece of code that will be removed from a database entry.
# Review it. Delete a line, or start it with #, to keep that piece.
# Then preview this plan again, because editing it changes its hash.
# Columns, separated by tabs: SHA-256 of the entry's value, SHA-256 of the piece, kind, what it is, entry#piece.
# site_root: {root}
# report: {report}
# created_utc: {created}
"""
REASONS = {
    'unsupported-entry': 'this kind of database entry cannot be changed here',
    'record-not-found': 'the entry no longer exists',
    'record-size-limit': 'the entry is larger than 4 MiB',
    'entry-changed-since-list': 'the entry has changed since the list was made: scan again and make a new list',
    'nothing-to-remove': 'none of the chosen code is there any more',
    'would-break-structure': 'removing it would damage the data around it: edit it by hand',
    'serialized-value-unsupported': 'the value is packed in a way that cannot be rebuilt exactly: edit it by hand',
    'serialized-objects-unsupported': 'the value holds PHP objects, which cannot be rebuilt safely: edit it by hand',
    'transactional-table-required': 'the table does not support all-or-nothing changes (it is not InnoDB)',
    'table-triggers-unsupported': 'the table has database triggers, so a change could have side effects',
    'unsupported-primary-key': 'the table does not have the standard WordPress key',
    'entry-changed-since-fix': 'the entry has been edited since it was fixed, so it is left alone',
    'backup-integrity-failed': 'the saved original does not match its record',
    'backup-identity-mismatch': 'the saved original belongs to another database or entry',
    'mysqli-unavailable': 'PHP on the host has no mysqli extension',
}

def reason(report):
    category = str(report.get('category', 'unknown'))
    return REASONS.get(category, f'the database step failed ({category}, at {report.get("stage", "?")})')

def credentials(root):
    """Database details read from wp-config.php as text. They go to the helper on standard input only."""
    values = s.wp_config_credentials(root)
    host, port, socket = s.split_db_host(values['host'])
    return dict(values, host=host, port=port, socket=socket)

def helper(php, config):
    """Run db-fix.php without php.ini; if mysqli needs one, load only that extension and retry."""
    path = str(Path(__file__).resolve().with_name('db-fix.php'))
    payload = json.dumps(config)
    result = subprocess.run([php, '-n', path], input=payload, text=True, capture_output=True, timeout=300)
    if result.returncode and '"mysqli-unavailable"' in result.stdout:
        result = subprocess.run([php, '-n', '-d', 'display_startup_errors=0', '-d', 'display_errors=0', '-d', 'extension=mysqli', path],
                                input=payload, text=True, capture_output=True, timeout=300)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise ValueError('The database helper returned no valid answer. If a change was being applied, read receipt.jsonl beside the plan before retrying.') from None
    if not isinstance(report, dict):
        raise ValueError('The database helper returned an unexpected answer.')
    return report

def one_line(text, limit):
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', str(text))[:limit]

def make_plan(report_path, root, reviews_dir, output, php='php'):
    root = q.no_links(root)
    report = m.report_load(m.private_path(report_path, root), root)
    if 'site_root' not in report:
        raise ValueError('This report does not say which site it belongs to. Run a new scan.')
    reviews = m.read_reviews(m.private_path(reviews_dir, root), root) if reviews_dir else []
    skipped = collections.Counter()
    skipped_lines = []
    def skip(why, what):
        skipped[why.split(':')[0]] += 1
        skipped_lines.append(why + '\t' + (what if b.plain_name(what) else repr(what)))
    wanted = collections.OrderedDict()
    for finding in report['findings']:
        if not isinstance(finding, dict) or finding.get('source') != 'database':
            skipped['file finding: use quarantine or clean copies'] += 1
            continue
        if finding.get('severity') not in b.PRIORITIES:
            skipped['recorded for information only'] += 1
            continue
        location = str(finding.get('location', ''))
        what = f"{finding.get('severity')} {finding.get('rule', '')} in {location}"
        if m.review_status(finding, reviews).startswith('Reviewed benign'):
            skip('you reviewed it as benign', what)
        elif finding.get('rule') not in RULES:
            skip('this kind of finding cannot be fixed here: look at it by hand', what)
        elif not m.reviewable(finding):
            skip('no fingerprint of the whole entry, usually because it is too large to read in full', what)
        else:
            wanted.setdefault(location, []).append(finding)
    config = dict(credentials(root), action='inspect', apply=False, site_root=str(root))
    lines, details = [], {}
    locations = list(wanted)
    for start in range(0, len(locations), 200):
        answer = helper(php, dict(config, targets=locations[start:start + 200]))
        if answer.get('status') != 'inspected':
            raise ValueError('The database could not be read: ' + reason(answer))
        for entry in answer.get('entries', []):
            location = str(entry.get('location', ''))
            findings = wanted.get(location)
            if not findings:
                continue
            if entry.get('error'):
                skip(REASONS.get(entry['error'], 'the entry could not be read'), location)
                continue
            if entry.get('value_sha256') != str(findings[0].get('sha256', '')).lower():
                skip('changed since the scan: scan again', location)
                continue
            pieces = [piece for piece in entry.get('fragments', []) if isinstance(piece, dict) and re.fullmatch('[a-f0-9]{64}', str(piece.get('sha256', '')))]
            if not pieces:
                skip('no removable code was found in it: look at it by hand', location)
                continue
            for piece in pieces:
                key = location + '#' + piece['sha256'][:12]
                if not piece.get('removable'):
                    skip('cannot be taken out without damaging the data around it: edit it by hand', key)
                    continue
                label = one_line(piece.get('label', ''), 120).replace('\t', ' ') or str(piece.get('kind', ''))
                lines.append('\t'.join((entry['value_sha256'], piece['sha256'], one_line(piece.get('kind', ''), 20), label, key)))
                details[key] = {'location': location, 'kind': one_line(piece.get('kind', ''), 20), 'label': label, 'warn': bool(piece.get('warn')),
                                'excerpt': one_line(piece.get('excerpt', ''), 200), 'count': int(piece.get('count', 1)), 'bytes': int(piece.get('bytes', 0)),
                                'format': one_line(entry.get('format', ''), 20), 'context': findings[0].get('context') if isinstance(findings[0].get('context'), dict) else {},
                                'rules': sorted({str(item.get('rule', '')) for item in findings})}
    if len(wanted) > b.MAX_ENTRIES:
        raise ValueError(f'The plan would cover {len(wanted)} entries; the limit is {b.MAX_ENTRIES}.')
    output = m.private_path(output, root)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan = HEADER.format(format=PLAN_FORMAT, root=root, report=report_path, created=b.now()) + ''.join(line + '\n' for line in lines)
    (output / 'plan.txt').write_bytes(plan.encode('utf-8'))
    (output / 'skipped.txt').write_bytes(('# Findings left out of the plan, and why.\n' + ''.join(line + '\n' for line in skipped_lines)).encode('utf-8'))
    (output / 'fragments.json').write_bytes(json.dumps(details, indent=1).encode('utf-8'))
    return {'status': 'plan-created' if lines else 'nothing-to-fix', 'plan': str(output / 'plan.txt'), 'skipped_list': str(output / 'skipped.txt'),
            'files_in_plan': len(lines), 'entries': len({line.rsplit('\t', 1)[1].rsplit('#', 1)[0] for line in lines}), 'skipped': dict(skipped),
            'note': 'Nothing was changed. Read plan.txt and skipped.txt. Then preview with apply --plan.'}

def load_plan(path, root):
    """The plan's entries, each with the pieces to remove from it, and the plan's hash."""
    path = m.private_path(path, root)
    raw, _ = q.read_regular(path)
    if len(raw) > b.MAX_PLAN_BYTES:
        raise ValueError('Plan is too large.')
    lines = raw.decode('utf-8').splitlines()
    if not lines or lines[0].strip() != PLAN_FORMAT:
        raise ValueError('Not a Sentinel database fix plan.')
    named = [line.split(':', 1)[1].strip() for line in lines if line.startswith('# site_root:')]
    if named != [str(root)]:
        raise ValueError('This plan belongs to another website root.')
    entries = collections.OrderedDict()
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) != 5 or not re.fullmatch('[a-fA-F0-9]{64}', parts[0]) or not re.fullmatch('[a-fA-F0-9]{64}', parts[1]) or '#' not in parts[4]:
            raise ValueError(f'Line {number} of the plan is not valid. Nothing was changed.')
        location = parts[4].rsplit('#', 1)[0]
        entry = entries.setdefault(location, {'location': location, 'sha256': parts[0].lower(), 'remove': []})
        if entry['sha256'] != parts[0].lower() or parts[1].lower() in entry['remove']:
            raise ValueError(f'Line {number} of the plan does not agree with an earlier line. Nothing was changed.')
        entry['remove'].append(parts[1].lower())
    if len(entries) > b.MAX_ENTRIES:
        raise ValueError(f'The plan covers {len(entries)} entries; the limit is {b.MAX_ENTRIES}.')
    return path, list(entries.values()), hashlib.sha256(raw).hexdigest()

def active_events(plan_path):
    """Entries this plan has fixed and not yet undone."""
    current = collections.OrderedDict()
    for event in b.read_receipt(plan_path):
        if event.get('event') == 'fixed':
            current[event.get('path')] = event
        elif event.get('event') == 'undone':
            current.pop(event.get('path'), None)
    return current

def apply_plan(root, store, plan, php='php', apply=False, expected=None, limit=None, skip_problems=False):
    root, store = q.setup(root, store)
    plan_path, entries, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    config = dict(credentials(root), site_root=str(root))
    done = active_events(plan_path)
    ready, already, problems = [], 0, []
    for entry in entries:
        if entry['location'] in done:
            already += 1
            continue
        preview = helper(php, dict(config, action='fix', apply=False, location=entry['location'], expected_sha256=entry['sha256'], remove=entry['remove']))
        if preview.get('status') == 'preview' and re.fullmatch('[a-f0-9]{64}', str(preview.get('new_sha256', ''))):
            ready.append(dict(entry, new=preview['new_sha256']))
        else:
            problems.append({'file': entry['location'], 'problem': reason(preview)})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'files_in_plan': len(entries), 'ready': len(ready), 'already_done': already,
               'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To go ahead, add --apply --plan-sha256 {digest}' if ready else 'No entries are ready to fix.'),
                       warning='Back up the database first. Afterwards clear every cache, or the old content can keep being served.')
        return summary
    if problems and not skip_problems:
        summary.update(status='stopped-before-changes', note='Entries differ from the plan, so nothing was changed. Scan again, or use --skip-problems to leave them as they are.')
        return summary
    fixed, failed, in_a_row, stopped = 0, [], 0, False
    with q.store_lock(store):
        for entry in (ready if limit is None else ready[:limit]):
            item = uuid.uuid4().hex
            folder = store / item
            folder.mkdir(mode=0o700)
            try:
                result = helper(php, dict(config, action='fix', apply=True, location=entry['location'], expected_sha256=entry['sha256'], remove=entry['remove'],
                                          expected_new_sha256=entry['new'], folder=str(folder)))
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                result = {'status': 'failed', 'category': type(error).__name__, 'stage': 'helper'}
            if result.get('status') != 'fixed':
                failed.append({'file': entry['location'], 'problem': reason(result)})
                b.write_event(plan_path, event='failed', path=entry['location'], problem=reason(result), id=item)
                if not any(folder.iterdir()):
                    folder.rmdir()
                in_a_row += 1
                if in_a_row >= b.STOP_AFTER_FAILURES:
                    stopped = True
                    break
                continue
            in_a_row = 0
            fixed += 1
            b.write_event(plan_path, event='fixed', path=entry['location'], id=item, old=entry['sha256'], new=entry['new'])
    summary.update(status='stopped-after-repeated-failures' if stopped else 'partly-done' if failed or problems else 'stage-done' if fixed < len(ready) else 'done',
                   fixed=fixed, failed=failed[:100], failed_count=len(failed), still_to_do=len(ready) - fixed,
                   note='Clear every cache now (page cache, object cache and any page-builder cache), check the site, then scan again. Undo with undo --plan.')
    return summary

def undo_plan(root, store, plan, php='php', apply=False, expected=None, only=()):
    root, store = q.setup(root, store)
    plan_path, _, digest = load_plan(plan, root)
    if apply and (not expected or expected.lower() != digest):
        raise ValueError('--apply needs --plan-sha256 from the preview of this exact plan. Nothing was changed.')
    current = active_events(plan_path)
    unknown = [item for item in only if item not in current]
    if unknown:
        raise ValueError('Not currently fixed by this plan: ' + ', '.join(unknown[:10]))
    config = dict(credentials(root), site_root=str(root))
    ready, problems = [], []
    for location in reversed(list(current)):
        if only and location not in only:
            continue
        event = current[location]
        if not re.fullmatch('[a-f0-9]{32}', str(event.get('id', ''))):
            problems.append({'file': location, 'problem': 'the receipt has no saved original for it'})
            continue
        preview = helper(php, dict(config, action='restore', apply=False, location=location, folder=str(q.no_links(store / event['id']))))
        if preview.get('status') == 'preview':
            ready.append(dict(event, new=preview.get('new_sha256')))
        else:
            problems.append({'file': location, 'problem': reason(preview)})
    summary = {'plan': str(plan_path), 'plan_sha256': digest, 'ready': len(ready), 'problems': problems[:100], 'problem_count': len(problems)}
    if not apply:
        summary.update(status='preview', note='Nothing was changed. ' + (f'To put the originals back, add --apply --plan-sha256 {digest}' if ready else 'No entries are ready to undo.'),
                       warning='Undoing brings back the original values, including any malware in them.')
        return summary
    undone, failed = 0, []
    with q.store_lock(store):
        for event in ready:
            try:
                result = helper(php, dict(config, action='restore', apply=True, location=event['path'], folder=str(q.no_links(store / event['id'])),
                                          expected_new_sha256=event['new']))
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                result = {'status': 'failed', 'category': type(error).__name__, 'stage': 'helper'}
            if result.get('status') != 'restored':
                failed.append({'file': event['path'], 'problem': reason(result)})
                continue
            undone += 1
            b.write_event(plan_path, event='undone', path=event['path'], id=event['id'])
    summary.update(status='partly-done' if failed or problems else 'done', undone=undone, failed=failed[:100], failed_count=len(failed),
                   note='The original values are back. Clear every cache. Their saved copies stay in the store.')
    return summary

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    c = sub.add_parser('plan')
    c.add_argument('--root', required=True, type=Path)
    c.add_argument('--report', required=True, type=Path)
    c.add_argument('--reviews', type=Path)
    c.add_argument('--output', required=True, type=Path)
    c.add_argument('--php', default='php')
    for name in ('apply', 'undo'):
        c = sub.add_parser(name)
        c.add_argument('--root', required=True, type=Path)
        c.add_argument('--store', required=True, type=Path)
        c.add_argument('--plan', required=True, type=Path)
        c.add_argument('--apply', action='store_true')
        c.add_argument('--plan-sha256')
        c.add_argument('--php', default='php')
        if name == 'apply':
            c.add_argument('--limit', type=int)
            c.add_argument('--skip-problems', action='store_true')
        else:
            c.add_argument('--only', action='append', default=[])
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'plan':
            result = make_plan(args.report, args.root, args.reviews, args.output, args.php)
        elif args.action == 'apply':
            if args.limit is not None and args.limit < 1:
                raise ValueError('--limit must be at least 1.')
            result = apply_plan(args.root, args.store, args.plan, args.php, args.apply, args.plan_sha256, args.limit, args.skip_problems)
        else:
            result = undo_plan(args.root, args.store, args.plan, args.php, args.apply, args.plan_sha256, args.only)
    except subprocess.TimeoutExpired:
        print('Stopped: the database helper timed out. Read receipt.jsonl beside the plan before retrying.', file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        print('If a plan was being applied, read receipt.jsonl beside it. Running the same plan again carries on safely.', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return b.exit_code(result)

if __name__ == '__main__':
    sys.exit(main())
