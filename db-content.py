#!/usr/bin/env python3
"""Explicit post/page content replacement with preserved backup and guarded restore."""
import argparse
import contextlib
import datetime
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

def validate_apply(args):
    if getattr(args, 'action', None) == 'verify' and args.apply:
        raise ValueError('verify is always read-only; --apply is not accepted.')
    if args.apply and (not args.maintenance_window or not all(re.fullmatch('[a-fA-F0-9]{64}', value or '') for value in [args.sha256, args.row_sha256, args.replacement_sha256])):
        raise ValueError('Apply requires --maintenance-window and all three exact hashes from a reviewed preview: --sha256, --row-sha256, --replacement-sha256.')

def run_helper(php, helper, payload):
    """Run without php.ini; if mysqli needs one, load only that extension and retry."""
    result = subprocess.run([php, '-n', helper], input=payload, text=True, capture_output=True, timeout=120)
    if result.returncode and '"mysqli-unavailable"' in result.stdout:
        result = subprocess.run([php, '-n', '-d', 'display_startup_errors=0', '-d', 'display_errors=0', '-d', 'extension=mysqli', helper], input=payload, text=True, capture_output=True, timeout=120)
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['replace', 'restore', 'verify'])
    p.add_argument('--root', required=True, type=Path)
    p.add_argument('--store', required=True, type=Path)
    p.add_argument('--post-id', type=int)
    p.add_argument('--replacement', type=Path, help='Private UTF-8 file with the exact replacement content')
    p.add_argument('--id', help='Preserved operation ID for restore')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--maintenance-window', action='store_true', help='Acknowledge paused writers/traffic and responsibility for cache clearing')
    p.add_argument('--sha256')
    p.add_argument('--row-sha256')
    p.add_argument('--replacement-sha256')
    p.add_argument('--php', default='php')
    args = p.parse_args()
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('sentinel_file_safety', Path(__file__).resolve().with_name('quarantine.py'))
    q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
    try:
        validate_apply(args)
        root, store = q.setup(args.root, args.store)
        if args.action == 'replace':
            if not args.post_id or args.post_id < 1 or not args.replacement:
                raise ValueError('replace requires --post-id and --replacement')
            replacement_path = q.no_links(args.replacement)
            if root == replacement_path or root in replacement_path.parents:
                raise ValueError('Keep replacement files outside the website root')
            data, _ = q.read_regular(replacement_path)
            if len(data) > 4194304:
                raise ValueError('Replacement exceeds 4 MiB')
            data.decode('utf-8')
            import base64
            encoded = base64.b64encode(data).decode('ascii')
            item_id = uuid.uuid4().hex if args.apply else None
            folder = store / item_id if item_id else None
        else:
            if not re.fullmatch('[a-f0-9]{32}', args.id or ''):
                raise ValueError('restore/verify requires a valid --id')
            item_id = args.id; folder = q.no_links(store / item_id)
            raw, _ = q.read_regular(q.no_links(folder / 'record.json'))
            record = json.loads(raw)
            if record.get('format') != 'sentinel-db-content-1' or record.get('site_root') != str(root):
                raise ValueError('Backup does not match this website root')
            args.post_id = int(record['post_id']); encoded = ''
        print('Read-only database verification; a dated result will be saved in the private recovery folder.' if args.action == 'verify' else 'Only one post/page post_content value is supported. Preview is read-only; --apply changes that value.', flush=True)
        cfg = {'host': input('Database host [localhost]: ').strip() or 'localhost',
               'database': input('Database name: ').strip(), 'user': input('Database user: ').strip(),
               'password': getpass.getpass('Database password (hidden): '),
               'prefix': input('Table prefix [wp_]: ').strip() or 'wp_',
               'action': args.action, 'post_id': str(args.post_id), 'apply': args.apply,
               'site_root': str(root), 'folder': str(folder) if folder else None,
               'replacement_base64': encoded, 'expected_sha256': (args.sha256 or '').lower(),
               'expected_row_sha256': (args.row_sha256 or '').lower(),
               'expected_replacement_sha256': (args.replacement_sha256 or '').lower()}
        with q.store_lock(store) if args.apply or args.action == 'verify' else contextlib.nullcontext():
            if args.action == 'replace' and args.apply:
                folder.mkdir(mode=0o700)
            if folder and args.apply:
                print('Preserved operation ID: ' + item_id, flush=True)
                print('Private evidence folder: ' + str(folder), flush=True)
            try:
                result = run_helper(args.php, str(Path(__file__).resolve().with_name('db-content.php')), json.dumps(cfg))
            finally:
                cfg['password'] = ''
            try:
                report = json.loads(result.stdout)
            except ValueError:
                raise ValueError('Helper returned no valid report. Raw output omitted; inspect evidence before retrying an applied operation.')
            if item_id:
                report['id'] = item_id
            if args.action == 'verify':
                report.update(verification_format='sentinel-db-verification-1', site_root=str(root),
                              database_identity=record['database_identity'],
                              observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
                q.write_exclusive(folder / ('verification-' + uuid.uuid4().hex + '.json'), json.dumps(report, indent=2).encode())
            if args.apply and folder:
                q.write_exclusive(folder / ('result-' + uuid.uuid4().hex + '.json'), json.dumps(report, indent=2).encode())
            print(json.dumps(report, indent=2))
            return 0 if result.returncode == 0 and report.get('status') != 'failed' else 1
    except subprocess.TimeoutExpired:
        print('Timed out. Outcome may be uncertain. Inspect the private record and current database value before retrying; do not assume rollback.')
        return 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error))
        print('For an applied operation, inspect preserved evidence before retrying. No automatic recovery or cache purge is attempted.')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
