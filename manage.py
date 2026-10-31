#!/usr/bin/env python3
"""Offline report history, hash-bound review notes, and quarantine inventory."""
import argparse
import base64
import datetime
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import uuid

MAX_REPORTS = 1000

class WrongSiteError(ValueError):
    pass

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def load_json(path):
    if path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Symlink or oversized JSON input rejected')
    return json.loads(path.read_text(encoding='utf-8-sig'))

def private_path(path, root):
    original = Path(os.path.abspath(path))
    if any(p.is_symlink() for p in [original, *original.parents]):
        raise ValueError('Private output paths cannot contain symlinks')
    path = original.resolve()
    if path == root or root in path.parents:
        raise ValueError('Reports, reviews, and inventory stores must be outside the website')
    return path

def report_load(path, root):
    report = load_json(path)
    if not isinstance(report, dict) or not isinstance(report.get('findings'), list) or not isinstance(report.get('checks'), dict):
        raise ValueError('Not a Sentinel scan report: ' + path.name)
    if report.get('site_root') and report['site_root'] != str(root):
        raise WrongSiteError('Report belongs to another website root: ' + str(path))
    timestamp = datetime.datetime.fromisoformat(report['created_utc'])
    if timestamp.tzinfo is None:
        raise ValueError('Report timestamp must include timezone')
    report['_time'] = timestamp
    return report

def finding_key(finding):
    return tuple(str(finding.get(k, '')) for k in ('source', 'location', 'rule'))

def reviewable(finding):
    return bool(re.fullmatch('[a-fA-F0-9]{64}', str(finding.get('sha256', '')))) and finding.get('content_complete', True) is True

def review_status(finding, records):
    if not reviewable(finding):
        return 'Unreviewed: complete content hash unavailable'
    matching = [r for r in records if tuple(r.get('finding_key', [])) == finding_key(finding)]
    matching.sort(key=lambda r: r['created_utc'])
    if not matching:
        return 'Unreviewed'
    latest = matching[-1]
    if latest.get('sha256') != finding['sha256'].lower():
        return 'Changed since last review: review again'
    if latest.get('decision') == 'benign':
        return 'Reviewed benign for this exact content hash'
    return 'Review withdrawn: review again'

def read_reviews(directory, root):
    if not directory or not directory.exists():
        return []
    records = []
    paths = sorted(directory.glob('*.json'))
    if len(paths) > 10000:
        raise ValueError('Too many review records')
    for path in paths:
        r = load_json(path)
        if r.get('format') != 'sentinel-review-1' or r.get('site_root') != str(root):
            raise ValueError('Review record format or website root mismatch')
        records.append(r)
    return records

def record_review(report_path, index, expected, note, decision, directory, root):
    report = report_load(report_path, root)
    if index < 1 or index > len(report['findings']):
        raise ValueError('Finding index is out of range (use the original report, counting from 1)')
    finding = report['findings'][index - 1]
    if not reviewable(finding) or finding['sha256'].lower() != expected.lower():
        raise ValueError('Complete content hash missing or different from the supplied SHA-256; no review recorded')
    if not note.strip() or len(note) > 2000:
        raise ValueError('A review note of 1–2000 characters is required')
    directory = private_path(directory, root)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'posix' and directory.stat().st_mode & 0o077:
        raise ValueError('Review directory must be private (mode 700)')
    record = {'format': 'sentinel-review-1', 'site_root': str(root), 'created_utc': now(),
              'finding_key': finding_key(finding), 'sha256': expected.lower(), 'decision': decision,
              'note': note, 'source_report': str(report_path), 'original_finding_index': index,
              'legacy_report_without_site_identity': 'site_root' not in report}
    name = directory / (uuid.uuid4().hex + '.json')
    with name.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
    return {'status': 'review-recorded', 'record': name.name, 'decision': decision, 'note': 'This records a human review of a snapshot, not a scan of live content.'}

def inventory(store, root):
    store = private_path(store, root)
    if not store.exists():
        return {'status': 'store-not-found', 'items': []}
    spec = importlib.util.spec_from_file_location('quarantine_inventory', Path(__file__).resolve().with_name('quarantine.py'))
    q = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(q)
    result = []
    entries = sorted(store.iterdir())
    if len(entries) > 10000:
        raise ValueError('Too many quarantine entries')
    for folder in entries:
        if folder.name == '.operation-lock':
            continue
        item = {'id': folder.name}
        result.append(item)
        if not re.fullmatch('[a-f0-9]{32}', folder.name) or folder.is_symlink() or not folder.is_dir():
            item['status'] = 'unrecognized store entry; not opened'
            continue
        try:
            record = load_json(folder / 'record.json')
            if record.get('id') != folder.name or record.get('root') != str(root) or record.get('format') != 1:
                raise ValueError('Record identity mismatch')
            item.update(file=record['relative_path'], recorded_state=record.get('status'), created_utc=record.get('created_utc'))
            payload, _ = q.read_regular(q.no_links(folder / 'payload.bin'))
            item['backup_integrity'] = 'verified' if q.sha(payload) == record['sha256'] and len(payload) == record['bytes'] else 'FAILED'
            source = q.target_path(root, record['relative_path'])
            if source.exists():
                active, _ = q.read_regular(source)
                item['active_path'] = 'present: same bytes' if q.sha(active) == record['sha256'] else 'present: different bytes'
            else:
                item['active_path'] = 'absent'
            item['status'] = 'inspected; recorded state and observed path are shown separately'
        except (OSError, ValueError, KeyError, TypeError) as error:
            item['status'] = 'inspection failed: ' + type(error).__name__
    return {'status': 'inventory-read', 'tool_lock_present': (store / '.operation-lock').exists(), 'items': result,
            'note': 'Read-only snapshot; source files and backups are never executed. Same-account tampering cannot be ruled out by stored hashes.'}

def php_snapshot_hash(snapshot):
    """Match PHP's sorted json_encode for the ASCII keys/base64 values we save."""
    if not isinstance(snapshot, dict) or not snapshot:
        raise ValueError('Invalid row snapshot')
    for key, value in snapshot.items():
        if not isinstance(key, str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key):
            raise ValueError('Unsupported snapshot column name')
        if value is not None:
            if not isinstance(value, str):
                raise ValueError('Invalid snapshot value')
            decoded = base64.b64decode(value, validate=True)
            if base64.b64encode(decoded).decode('ascii') != value:
                raise ValueError('Noncanonical base64 snapshot')
    encoded = json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=True).replace('/', '\\/')
    return hashlib.sha256(encoded.encode('ascii')).hexdigest()

def last_database_verification(folder, root, record):
    paths = sorted(folder.glob('verification-*.json'))
    if not paths:
        return {'status': 'not performed', 'note': 'No saved authenticated verification result'}
    if len(paths) > 1000:
        return {'status': 'not verified', 'reason': 'Too many verification receipts'}
    receipts = []
    try:
        for path in paths:
            receipt = load_json(path)
            if receipt.get('verification_format') != 'sentinel-db-verification-1' or receipt.get('site_root') != str(root) or receipt.get('id') != folder.name or receipt.get('database_identity') != record['database_identity']:
                raise ValueError('Receipt identity mismatch')
            stamp = datetime.datetime.fromisoformat(receipt['observed_utc'])
            if stamp.tzinfo is None:
                raise ValueError('Receipt time lacks timezone')
            receipts.append((stamp, path.name, receipt))
        _, _, receipt = max(receipts, key=lambda item: (item[0], item[1]))
        result = {'observed_at': receipt['observed_utc'], 'note': 'Saved authenticated-read result, not a new database query by this inventory. It does not prove the row is unchanged now.'}
        if receipt.get('status') == 'failed':
            return dict(result, status='latest verification attempt failed; no live-state conclusion')
        if receipt.get('status') != 'verified-read' or receipt.get('action') != 'verify' or str(receipt.get('post_id')) != str(record['post_id']) or receipt.get('table') != record['table']:
            raise ValueError('Invalid verification result')
        content_hash, row_hash = receipt.get('content_sha256'), receipt.get('row_sha256')
        if not all(re.fullmatch('[a-f0-9]{64}', str(value)) for value in [content_hash, row_hash]):
            raise ValueError('Invalid verification hashes')
        original = content_hash == record['original_sha256'] and row_hash == record['original_row_sha256']
        replacement = content_hash == record['replacement_sha256'] and row_hash == record['expected_replaced_row_sha256']
        state = 'matches-original-row' if original else 'matches-replacement-row' if replacement else 'differs-from-both-recorded-states'
        if receipt.get('live_state') != state:
            raise ValueError('Receipt state inconsistent with hashes')
        return dict(result, status='authenticated read recorded', state=state,
                    content_matches_original=content_hash == record['original_sha256'],
                    content_matches_replacement=content_hash == record['replacement_sha256'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {'status': 'not verified', 'reason': 'Invalid or unreadable verification receipt: ' + type(error).__name__}

def database_inventory(store, root):
    store = private_path(store, root)
    if not store.exists():
        return {'status': 'store-not-found', 'items': [], 'live_database_state': 'not checked'}
    spec = importlib.util.spec_from_file_location('database_inventory_file_safety', Path(__file__).resolve().with_name('quarantine.py'))
    q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
    entries = sorted(store.iterdir())
    if len(entries) > 10000:
        raise ValueError('Too many database store entries')
    items = []
    for folder in entries:
        if folder.name == '.operation-lock':
            continue
        item = {'id': folder.name, 'live_database_state': 'not checked; no database connection made'}
        items.append(item)
        if not re.fullmatch('[a-f0-9]{32}', folder.name) or folder.is_symlink() or not folder.is_dir():
            item['status'] = 'unrecognized store entry; not opened'
            continue
        try:
            record_path = q.no_links(folder / 'record.json')
            if not record_path.exists():
                item['status'] = 'incomplete operation folder: no recovery record'
                continue
            if record_path.stat().st_size > 12582912:
                raise ValueError('Record exceeds size limit')
            record = load_json(record_path)
            if not isinstance(record, dict) or record.get('format') != 'sentinel-db-content-1' or record.get('site_root') != str(root):
                raise ValueError('Record format or site root mismatch')
            if not re.fullmatch('[A-Za-z0-9_]+posts', str(record.get('table', ''))) or not re.fullmatch('[1-9][0-9]{0,17}', str(record.get('post_id', ''))):
                raise ValueError('Invalid record target')
            for name in ['database_identity', 'original_sha256', 'replacement_sha256', 'original_row_sha256', 'expected_replaced_row_sha256']:
                if not re.fullmatch('[a-f0-9]{64}', str(record.get(name, ''))):
                    raise ValueError('Missing or invalid digest')
            if record.get('state') not in {'prepared', 'content-replaced', 'restored'}:
                raise ValueError('Unknown operation state')
            item.update(table=record['table'], post_id=str(record['post_id']), recorded_state=record['state'],
                        created_utc=record.get('created_utc'), last_operation_utc=record.get('last_operation_utc'))
            payload_path = q.no_links(folder / 'original.bin')
            if payload_path.stat().st_size > 4194304:
                raise ValueError('Payload exceeds limit')
            payload, _ = q.read_regular(payload_path)
            snapshot = record.get('original_row_base64')
            row_valid = php_snapshot_hash(snapshot) == record['original_row_sha256']
            saved_content = base64.b64decode(snapshot['post_content'], validate=True)
            row_id = base64.b64decode(snapshot['ID'], validate=True).decode('ascii')
            payload_valid = hashlib.sha256(payload).hexdigest() == record['original_sha256']
            item['original_payload_integrity'] = 'verified' if payload_valid else 'FAILED'
            item['row_snapshot_integrity'] = 'verified' if row_valid else 'FAILED'
            item['snapshot_matches_payload_and_id'] = saved_content == payload and row_id == str(record['post_id'])
            item['original_bytes'] = len(payload)
            item['snapshot_column_count'] = len(snapshot)
            item['backup_integrity'] = 'verified' if payload_valid and row_valid and item['snapshot_matches_payload_and_id'] else 'FAILED'
            item['status'] = 'backup inspected; operation state is historical, not live database verification'
            if record['state'] == 'prepared':
                item['recovery_note'] = 'Prepared may precede or follow an interrupted commit. Inspect the live record before retrying or restoring.'
            item['replacement_state_integrity'] = 'Expected replacement-row hash is recorded, but cannot be independently checked without replacement contents or an authenticated database read.'
            item['last_authenticated_check'] = last_database_verification(folder, root, record)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
            item['status'] = 'inspection failed: ' + type(error).__name__
            item['backup_integrity'] = 'not verified'
    return {'status': 'database-backup-inventory-read', 'observed_at': now(), 'tool_lock_present': (store / '.operation-lock').exists(),
            'items': items, 'live_database_state': 'not checked',
            'note': 'Offline verification only. No credentials requested, no database connection, no backup content included. Stored hashes are not authentication against same-account tampering. Old record format does not bind the operation ID into the manifest; the ID is the folder name.'}

def consolidate(reports_dir, output, root, reviews_dir=None, store=None, db_store=None):
    reports_dir = private_path(reports_dir, root)
    paths = sorted(reports_dir.glob('report-*/report.json'), key=lambda p: (p.stat().st_mtime_ns, str(p)))
    if not paths:
        raise ValueError('Expected report-*/report.json files directly below --reports-dir')
    # A damaged or old report must not block a summary of the others. Both are declared.
    omitted_old = paths[:-MAX_REPORTS]
    reports, unreadable = [], []
    for path in paths[-MAX_REPORTS:]:
        try:
            reports.append((path, report_load(path, root)))
        except WrongSiteError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            unreadable.append({'report': str(path), 'reason': type(error).__name__})
    if not reports:
        raise ValueError('No readable report-*/report.json files were found below --reports-dir')
    reports.sort(key=lambda pair: (pair[1]['_time'], str(pair[0])))
    reviews = read_reviews(private_path(reviews_dir, root), root) if reviews_dir else []
    observations, checks, history = {}, {}, []
    for path, report in reports:
        stamp = report['created_utc']
        history.append({'report': str(path), 'created_utc': stamp, 'version': report.get('version'),
                        'files_inspected': report.get('files_inspected'), 'findings': len(report['findings']),
                        'legacy_site_identity_unverified': 'site_root' not in report, 'limitations': report.get('limitations', [])})
        for category, value in report['checks'].items():
            if value == 'not requested':
                continue
            if category in {'plugins', 'references'} and isinstance(value, list):
                for entry in value:
                    key = category + ':' + str(entry.get('target', entry.get('plugin', 'unknown')))
                    checks[key] = {'observed_at': stamp, 'report': str(path), 'result': entry}
            else:
                checks[category] = {'observed_at': stamp, 'report': str(path), 'result': value}
        for index, finding in enumerate(report['findings'], 1):
            # Preserve each distinct content snapshot; never hide an older hash.
            key = finding_key(finding) + (finding.get('sha256', 'no-content-hash'),)
            if key not in observations:
                observations[key] = {'first_seen': stamp}
            observations[key].update(finding=finding, last_seen=stamp, report=str(path), finding_index=index,
                                     review=review_status(finding, reviews), status='historical observation; not a statement about current live content')
    result = {'format': 'sentinel-summary-1', 'created_utc': now(), 'site_root': str(root),
              'note': 'Cumulative history, not a fresh scan. Last-known checks retain their timestamps. Absence from a later report does not mean resolved. Legacy reports are grouped only because you selected their directory; their site identity cannot be verified.',
              'unreadable_reports': unreadable, 'older_reports_not_included': len(omitted_old),
              'scan_history': history, 'last_known_checks': checks, 'observations': list(observations.values()),
              'review_records': reviews, 'quarantine': inventory(store, root) if store else {'status': 'not requested'},
              'database_recovery': database_inventory(db_store, root) if db_store else {'status': 'not requested'}}
    latest = {}
    for obs in result['observations']:
        key = finding_key(obs['finding'])
        if key not in latest or (obs['last_seen'], obs['report']) > (latest[key]['last_seen'], latest[key]['report']):
            latest[key] = obs
    groups = {'needs_review': [], 'reviewed_snapshots': [], 'older_history': []}
    for obs in result['observations']:
        if latest[finding_key(obs['finding'])] is not obs:
            group = 'older_history'
        elif obs['review'].startswith('Reviewed benign'):
            group = 'reviewed_snapshots'
        else:
            group = 'needs_review'
        groups[group].append(obs)
    result['presentation_groups'] = groups
    result['presentation_note'] = 'Latest observed snapshot per finding identity, not necessarily live state. Older snapshots remain in history; no finding is automatically resolved.'
    result['latest_scan_coverage'] = {'report': str(reports[-1][0]), 'created_utc': reports[-1][1]['created_utc'],
                                      'checks': reports[-1][1]['checks'], 'limitations': reports[-1][1].get('limitations', [])}
    output = private_path(output, root)
    if output.exists():
        raise ValueError('Output must be a NEW private directory')
    output.mkdir(mode=0o700, parents=True)
    (output / 'summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    esc = lambda value: html.escape(str(value))
    page = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sentinel history</title><style>body{font:16px system-ui;margin:2em;color:#192536}table{border-collapse:collapse;width:100%}td,th{padding:10px;border:1px solid #ccc;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer;padding:10px;background:#edf2f7}</style><h1>WordPress Sentinel — review history</h1>'
    page += '<p>' + esc(result['note']) + '</p><p>' + esc(result['presentation_note']) + '</p>'
    if unreadable or omitted_old:
        page += '<h2>Reports not included</h2><p>' + str(len(omitted_old)) + ' older reports are beyond the ' + str(MAX_REPORTS) + '-report limit. ' + str(len(unreadable)) + ' could not be read:</p><pre>' + esc(json.dumps(unreadable, indent=2)) + '</pre>'
    for group, title in [('needs_review', 'Needs review'), ('reviewed_snapshots', 'Reviewed snapshots'), ('older_history', 'Older history')]:
        page += '<h2>' + title + ' (' + str(len(groups[group])) + ')</h2>'
        if group != 'needs_review':
            page += '<details><summary>Show observations</summary>'
        page += '<table><tr><th>Location / rule</th><th>Priority</th><th>Review</th><th>Last observed / report index</th></tr>'
        for obs in groups[group]:
            finding = obs['finding']
            page += '<tr><td>' + esc(finding['location']) + '<br>' + esc(finding['rule']) + '</td><td>' + esc(finding['severity']) + '</td><td>' + esc(obs['review']) + '</td><td>' + esc(obs['last_seen']) + '<br>' + esc(obs['report']) + ' / #' + str(obs['finding_index']) + '</td></tr>'
        page += '</table>'
        if group != 'needs_review':
            page += '</details>'
    page += '<h2>Latest scan coverage and limitations</h2><p>Checks not requested or unavailable are not clean results. Consult dated last-known checks below for earlier coverage.</p><pre>' + esc(json.dumps(result['latest_scan_coverage'], indent=2)) + '</pre>'
    for title, value in [('Last-known checks (not necessarily current)', checks), ('File quarantine inventory', result['quarantine']), ('Database recovery inventory (offline)', result['database_recovery']), ('Review records', reviews), ('Scan history and coverage limits', history)]:
        page += '<h2>' + esc(title) + '</h2><details><summary>Show details</summary><pre>' + esc(json.dumps(value, indent=2)) + '</pre></details>'
    (output / 'summary.html').write_text(page + '</html>', encoding='utf-8')
    return {'status': 'summary-created', 'reports': len(reports), 'unreadable_reports': len(unreadable), 'older_reports_not_included': len(omitted_old), 'distinct_observations': len(observations), 'output': str(output)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ['consolidate', 'review', 'inventory', 'database-inventory']:
        p = sub.add_parser(name)
        p.add_argument('--root', required=True, type=Path)
        if name == 'consolidate':
            p.add_argument('--reports-dir', required=True, type=Path)
            p.add_argument('--output', required=True, type=Path)
            p.add_argument('--reviews', type=Path)
            p.add_argument('--store', type=Path)
            p.add_argument('--db-store', type=Path)
        elif name == 'review':
            p.add_argument('--report', required=True, type=Path)
            p.add_argument('--finding-index', required=True, type=int)
            p.add_argument('--sha256', required=True)
            p.add_argument('--note', required=True)
            p.add_argument('--decision', choices=['benign', 'withdraw'], default='benign')
            p.add_argument('--reviews', required=True, type=Path)
        elif name == 'database-inventory':
            p.add_argument('--db-store', required=True, type=Path)
        else:
            p.add_argument('--store', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    try:
        if args.action == 'consolidate':
            result = consolidate(args.reports_dir, args.output, root, args.reviews, args.store, args.db_store)
        elif args.action == 'review':
            result = record_review(args.report, args.finding_index, args.sha256, args.note, args.decision, args.reviews, root)
        elif args.action == 'database-inventory':
            result = database_inventory(args.db_store, root)
        else:
            result = inventory(args.store, root)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
