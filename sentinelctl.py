#!/usr/bin/env python3
"""WordPress Sentinel 0.21.0-rc1: one entry point, explicit operations."""
import argparse
import datetime
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import uuid

# Leave no __pycache__ folders behind on the host.
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sentinel_paths', HERE / 'quarantine.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
FORMAT = 'sentinel-profile-1'
FIELDS = {'format', 'root', 'private_dir', 'core_version', 'locale'}

def validate(profile, filename):
    if not isinstance(profile, dict) or set(profile) not in (FIELDS, FIELDS | {'references'}) or profile.get('format') != FORMAT:
        raise ValueError('Unsupported profile fields. Credentials are not supported in profiles.')
    if not all(isinstance(profile[k], str) for k in FIELDS):
        raise ValueError('Profile values must be strings.')
    if not Path(profile['root']).is_absolute() or not Path(profile['private_dir']).is_absolute():
        raise ValueError('Profile paths must be absolute.')
    root, private = q.setup(Path(profile['root']), Path(profile['private_dir']))
    filename = q.no_links(filename)
    if root == filename or root in filename.parents:
        raise ValueError('Keep profiles outside the website root.')
    if not private.is_dir():
        raise ValueError('Private directory must already exist.')
    if os.name == 'posix' and private.stat().st_mode & 0o077:
        raise ValueError('Private directory must have permissions 700.')
    refs = profile.get("references", [])
    if not isinstance(refs, list) or len(refs) > 100:
        raise ValueError("Expected at most 100 saved references")
    targets = set()
    for ref in refs:
        target, path = reference_parts(ref, root)
        if not Path(ref.split('=', 1)[1]).is_absolute() or target in targets:
            raise ValueError("Saved reference paths must be absolute and targets unique")
        targets.add(target)
    return root, private

def reference_parts(value, root):
    if not isinstance(value, str) or '=' not in value:
        raise ValueError('Use plugin:directory=ZIP or theme:directory=ZIP')
    target, path = value.split('=', 1)
    if not re.fullmatch(r'(plugin|theme):[A-Za-z0-9][A-Za-z0-9._-]{0,99}', target) or not path:
        raise ValueError('Invalid reference target/path')
    safe = q.no_links(path)
    if safe == root or root in safe.parents:
        raise ValueError('Keep reference ZIPs outside the website')
    return target, str(safe)


def read_profile(filename):
    filename = q.no_links(filename)
    if filename.stat().st_size > 16384:
        raise ValueError('Profile too large.')
    if os.name == 'posix' and filename.stat().st_mode & 0o077:
        raise ValueError('Profile must have permissions 600.')
    raw, _ = q.read_regular(filename)
    profile = json.loads(raw)
    validate(profile, filename)
    return profile

def parser():
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--profile', required=True, type=Path)
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('init', allow_abbrev=False)
    c.add_argument('--root', required=True, type=Path)
    c.add_argument('--private-dir', required=True, type=Path)
    c.add_argument('--core-version', default='')
    c.add_argument('--locale', default='en_US')
    sub.add_parser('show')
    c = sub.add_parser('save-references', allow_abbrev=False)
    c.add_argument('--output', type=Path, required=True)
    c.add_argument('--reference', action='append', required=True)
    c = sub.add_parser('changes', allow_abbrev=False)
    c.add_argument('--before', type=Path, required=True)
    c.add_argument('--after', type=Path, required=True)
    c = sub.add_parser('file-changes', allow_abbrev=False)
    c.add_argument('--before', type=Path, required=True)
    c.add_argument('--after', type=Path, required=True)
    for scan_name in ('scan', 'routine-check'):
        c = sub.add_parser(scan_name, allow_abbrev=False)
        c.add_argument('--file-inventory', action='store_true')
        c.add_argument('--no-saved-references', action='store_true')
        c.add_argument('--max-file-mb', type=int, default=20)
        c.add_argument('--max-files', type=int)
        c.add_argument('--db-row-limit', type=int)
        c.add_argument('--db-value-limit', type=int)
        c.add_argument('--php')
        c.add_argument('--fail-on', choices=['high', 'medium', 'review', 'info'])
        for flag in ['database', 'plugins', 'persistence', 'account-cron', 'core']:
            c.add_argument('--' + flag, action='store_true')
        c.add_argument('--db-from-wp-config', action='store_true', help='Check the database without prompting, reading its details from wp-config.php as text')
        c.add_argument('--db-credentials', type=Path, help='Check the database without prompting, using this private JSON file')
        c.add_argument('--reference', action='append', default=[])
        if scan_name == 'routine-check':
            c.add_argument('--before', type=Path, help='Optional explicit earlier inventory; otherwise select newest valid finished inventory')
            c.add_argument('--alert-config', type=Path, help='Alert settings: tell you about new or changed findings and failures')
            c.add_argument('--prune-keep', type=int, help='After a successful run, permanently remove older report folders, keeping the first and this many newest')
    c = sub.add_parser('prune', allow_abbrev=False)
    c.add_argument('--keep', type=int, required=True)
    c.add_argument('--apply', action='store_true')
    c = sub.add_parser('alert-test', allow_abbrev=False)
    c.add_argument('--alert-config', type=Path, required=True)
    sub.add_parser('summary')
    sub.add_parser('inventory')
    sub.add_parser('db-inventory')
    sub.add_parser('selftest')
    c = sub.add_parser('db-selftest', allow_abbrev=False)
    c.add_argument('--allow-test-table', action='store_true', required=True)
    for name in ['file-quarantine', 'file-restore', 'db-replace', 'db-restore', 'db-verify']:
        c = sub.add_parser(name, allow_abbrev=False)
        if name == 'file-quarantine':
            c.add_argument('--file', required=True)
        elif name == 'db-replace':
            c.add_argument('--post-id', type=int, required=True)
            c.add_argument('--replacement', type=Path, required=True)
        else:
            c.add_argument('--id', required=True)
        if name != 'db-verify':
            c.add_argument('--apply', action='store_true')
            c.add_argument('--sha256')
        if name in ['db-replace', 'db-restore']:
            c.add_argument('--row-sha256')
            c.add_argument('--replacement-sha256')
            c.add_argument('--maintenance-window', action='store_true')
        if name.startswith('db-'):
            c.add_argument('--php')
    c = sub.add_parser('batch-plan', allow_abbrev=False, help='Make a reviewable list of files to quarantine from a report. Changes nothing.')
    c.add_argument('--report', type=Path, required=True)
    c.add_argument('--priority', choices=['high', 'medium', 'review'], default='high', help='Include findings at this priority or higher')
    c.add_argument('--rule', action='append', default=[], help='Only this rule; repeatable')
    c.add_argument('--path', action='append', default=[], help='Only this file or folder, relative to the site; repeatable')
    c.add_argument('--include-critical', action='store_true', help='Allow files WordPress needs in order to run')
    for name in ['batch-quarantine', 'batch-restore']:
        c = sub.add_parser(name, allow_abbrev=False)
        c.add_argument('--plan', type=Path, required=True)
        c.add_argument('--apply', action='store_true')
        c.add_argument('--plan-sha256')
        if name == 'batch-quarantine':
            c.add_argument('--limit', type=int, help='Move at most this many files now; run again for the rest')
            c.add_argument('--skip-problems', action='store_true', help='Leave files that differ from the plan where they are, and move the rest')
        else:
            c.add_argument('--only', action='append', default=[], help='Restore only this file; repeatable')
    c = sub.add_parser('review', allow_abbrev=False)
    c.add_argument('--report', type=Path, required=True)
    c.add_argument('--finding-index', type=int, required=True)
    c.add_argument('--sha256', required=True)
    c.add_argument('--note', required=True)
    c.add_argument('--decision', choices=['benign', 'withdraw'], default='benign')
    return p

def command(args, profile):
    root, private = validate(profile, args.profile)
    common = ['--root', str(root)]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    name = args.command
    if name == 'scan':
        tail = common + ['--output', str(private / ('report-' + stamp)), '--max-file-mb', str(args.max_file_mb)]
        if args.file_inventory:
            tail += ['--file-inventory']
        if args.core:
            if not profile['core_version']:
                raise ValueError('Profile has no core version. Create a new profile with a reviewed version, or --core-version auto.')
            tail += ['--core-version', profile['core_version'], '--locale', profile['locale']]
        for flag in ['database', 'db-from-wp-config', 'plugins', 'persistence', 'account-cron']:
            if getattr(args, flag.replace('-', '_')):
                tail.append('--' + flag)
        for flag in ['db-credentials', 'max-files', 'db-row-limit', 'db-value-limit', 'php', 'fail-on']:
            value = getattr(args, flag.replace('-', '_'), None)
            if value is not None:
                tail += ['--' + flag, str(value)]
        tail += ['--command-profile', str(args.profile)]
        refs = [] if args.no_saved_references else list(profile.get('references', []))
        refs += args.reference
        targets = set()
        for reference in refs:
            target, path = reference_parts(reference, root)
            if target in targets:
                raise ValueError('Duplicate reference target; use --no-saved-references to replace saved mappings')
            targets.add(target)
            if not Path(path).is_file():
                raise ValueError('Reference ZIP is missing: ' + path)
            reference = target + '=' + path
            tail += ['--reference', reference]
        script = 'sentinel.py'
    elif name == 'file-changes':
        script = 'file_changes.py'
        tail = common + ['--before', str(args.before), '--after', str(args.after), '--output', str(private / ('file-changes-' + stamp))]
    elif name == 'changes':
        script = 'changes.py'
        tail = common + ['--before', str(args.before), '--after', str(args.after),
                         '--reviews', str(private / 'review-notes'),
                         '--output', str(private / ('changes-' + stamp))]
    elif name in ['summary', 'inventory', 'db-inventory', 'review']:
        script = 'manage.py'
        tail = [{'summary': 'consolidate', 'db-inventory': 'database-inventory'}.get(name, name)] + common
        if name in ['summary', 'inventory']:
            tail += ['--store', str(private / 'quarantine-store')]
        if name in ['summary', 'db-inventory']:
            tail += ['--db-store', str(private / 'db-quarantine-store')]
        if name in ['summary', 'review']:
            tail += ['--reviews', str(private / 'review-notes')]
        if name == 'summary':
            tail += ['--reports-dir', str(private), '--output', str(private / ('summary-' + stamp))]
        if name == 'review':
            for key in ['report', 'finding_index', 'sha256', 'note', 'decision']:
                tail += ['--' + key.replace('_', '-'), str(getattr(args, key))]
    elif name == 'batch-plan':
        script = 'batch.py'
        tail = ['plan'] + common + ['--report', str(args.report), '--reviews', str(private / 'review-notes'), '--output', str(private / ('batch-' + stamp)), '--priority', args.priority]
        for item in args.rule:
            tail += ['--rule', item]
        for item in args.path:
            tail += ['--path', item]
        if args.include_critical:
            tail.append('--include-critical')
    elif name in ['batch-quarantine', 'batch-restore']:
        script = 'batch.py'
        tail = [name.split('-')[1]] + common + ['--store', str(private / 'quarantine-store'), '--plan', str(args.plan)]
        if args.plan_sha256:
            tail += ['--plan-sha256', args.plan_sha256]
        for flag in ['apply', 'skip_problems']:
            if getattr(args, flag, False):
                tail.append('--' + flag.replace('_', '-'))
        if getattr(args, 'limit', None) is not None:
            tail += ['--limit', str(args.limit)]
        for item in getattr(args, 'only', []):
            tail += ['--only', item]
    elif name in ['selftest', 'db-selftest']:
        script = name + '.py'
        tail = ['--work-dir', str(private)]
        if name == 'db-selftest':
            tail += ['--allow-test-table']
    else:
        database = name.startswith('db-')
        script = 'db-content.py' if database else 'quarantine.py'
        tail = [name.split('-', 1)[1]] + common + ['--store', str(private / ('db-quarantine-store' if database else 'quarantine-store'))]
        for key in ['file', 'id', 'post_id', 'replacement', 'sha256', 'row_sha256', 'replacement_sha256', 'php']:
            value = getattr(args, key, None)
            if value is not None:
                tail += ['--' + key.replace('_', '-'), str(value)]
        for key in ['apply', 'maintenance_window']:
            if getattr(args, key, False):
                tail.append('--' + key.replace('_', '-'))
    if name in ('selftest', 'db-selftest') and not (HERE / script).is_file():
        raise ValueError('Self-tests are not included in the hosting package. Use the development package locally; do not upload test fixtures to hosting.')
    return [sys.executable, '-B', '-I', '-S', str(HERE / script)] + tail

def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == 'init':
            profile = dict(format=FORMAT, root=str(q.no_links(args.root)), private_dir=str(q.no_links(args.private_dir)), core_version=args.core_version, locale=args.locale)
            validate(profile, args.profile)
            q.write_exclusive(q.no_links(args.profile), (json.dumps(profile, indent=2) + '\n').encode())
            print('Created password-free profile: ' + str(args.profile))
            return 0
        profile = read_profile(args.profile)
        if args.command == 'save-references':
            root, _ = validate(profile, args.profile)
            profile['references'] = ['='.join(reference_parts(ref, root)) for ref in args.reference]
            validate(profile, args.output)
            for ref in profile['references']:
                if not Path(ref.split('=', 1)[1]).is_file():
                    raise ValueError('Missing reference ZIP: ' + ref)
            q.write_exclusive(q.no_links(args.output), (json.dumps(profile, indent=2) + '\n').encode())
            print('Created profile with saved reference mappings: ' + str(args.output))
            return 0
        if args.command in ('prune', 'alert-test'):
            spec = importlib.util.spec_from_file_location('sentinel_monitoring', HERE / 'monitoring.py')
            monitoring = importlib.util.module_from_spec(spec); spec.loader.exec_module(monitoring)
            root, private = validate(profile, args.profile)
            if args.command == 'alert-test':
                failures = monitoring.send_test(monitoring.load_config(args.alert_config), root.name)
                print('Test alert sent.' if not failures else 'Test alert failed: ' + '; '.join(failures))
                return monitoring.EXIT_ALERT_FAILED if failures else 0
            result = monitoring.prune_hosted(private, args.keep, args.apply)
            print(json.dumps(result, indent=2))
            if not args.apply:
                print('Preview only. Add --apply to remove these folders permanently. Quarantine stores and review notes are never touched.')
            return 0
        if args.command == 'routine-check':
            spec = importlib.util.spec_from_file_location('sentinel_routine', HERE / 'routine.py')
            routine = importlib.util.module_from_spec(spec); spec.loader.exec_module(routine)
            return routine.run(args, profile, command, validate)
        if args.command == 'show':
            print(json.dumps(profile, indent=2))
            return 0
        # Inherit the terminal for hidden password prompts. Never use a shell.
        return subprocess.run(command(args, profile)).returncode
    except (OSError, ValueError, TypeError) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Interrupted. If applying a change, inspect recovery evidence and live state before retrying.', file=sys.stderr)
        return 130

if __name__ == '__main__':
    raise SystemExit(main())
