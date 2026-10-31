"""Manual scan, inventory comparison and summary orchestration. No remediation."""
import argparse
import datetime
import importlib.util
import json
import html
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location('routine_file_changes', Path(__file__).with_name('file_changes.py'))
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)

def brief_status(report, receipt, summary=None):
    """Describe this scan only; reviews never transfer across changed hashes."""
    records = summary['review_records'] if summary is not None else None
    attention, reviewed = [], 0
    for index, finding in enumerate(report['findings'], 1):
        review = fc.m.review_status(finding, records) if records is not None else 'Review history unavailable'
        if review.startswith('Reviewed benign'):
            reviewed += 1
        else:
            attention.append({'finding_index': index, 'location': finding.get('location'),
                              'rule': finding.get('rule'), 'severity': finding.get('severity'), 'review': review,
                              'sha256': finding.get('sha256')})
    coverage = []
    for name, value in report['checks'].items():
        if isinstance(value, str):
            coverage.append(name + ': ' + value)
        elif isinstance(value, list):
            for entry in value:
                label = str(entry.get('target', entry.get('plugin', name)))
                coverage.append(name + ' / ' + label + ': ' + str(entry.get('status', 'unknown'))
                                + '; differences=' + str(entry.get('differences', 'not assessed'))
                                + '; unchecked=' + str(len(entry.get('unchecked_details', [])))
                                + ('; ' + str(entry['reason']) if entry.get('reason') else ''))
        elif isinstance(value, dict):
            coverage.append(name + ': ' + str(value.get('status', 'unknown')))
            if name == 'database':
                coverage.append('Database rows inspected: ' + json.dumps(value.get('rows_inspected', {})))
            if name == 'persistence':
                coverage.append('Startup unchecked entries: ' + json.dumps(value.get('unchecked_entries', [])))
                coverage.append('Account crontab: ' + json.dumps(value.get('account_crontab', {})))
    omitted = receipt.get('optional_checks_not_requested', [])
    if omitted:
        coverage.append('Optional checks not requested: ' + ', '.join(omitted))
    return {'format': 'sentinel-run-status-1', 'status': receipt['status'],
            'observed_utc': report['created_utc'], 'current_findings': len(report['findings']),
            'matching_benign_reviews': reviewed if records is not None else None,
            'needs_attention': attention, 'review_history_available': records is not None,
            'file_change_counts': receipt.get('file_change_counts'),
            'comparison_status': receipt.get('comparison_status', 'See comparison stage exit code'),
            'coverage': coverage, 'warnings': list(receipt['warnings']),
            'note': 'Current scan observations only. Needs attention includes existing unresolved items, not just new findings. Matching reviews apply to exact content snapshots. Completion and unchanged files do not establish a clean site.'}

def write_status(directory, status, receipt):
    lines = ['SENTINEL RUN STATUS', 'Workflow: ' + status['status'],
             'Observed: ' + status['observed_utc'],
             'Findings: ' + str(status['current_findings']),
             'Matching benign reviews: ' + str(status['matching_benign_reviews']),
             'Needs attention: ' + str(len(status['needs_attention'])), status['note'], '', 'FILE COMPARISON',
             json.dumps(status['file_change_counts']) if status['file_change_counts'] is not None else status['comparison_status'],
             '', 'FINDINGS NEEDING ATTENTION']
    for item in status['needs_attention']:
        lines.append('#{finding_index} [{severity}] {location} — {rule}: {review}; sha256={sha256}'.format(**item))
    lines += ['', 'COVERAGE'] + status['coverage'] + ['', 'WARNINGS'] + status['warnings']
    content = '\n'.join(lines) + '\n'
    with (directory / 'run-status.txt').open('x', encoding='utf-8') as stream:
        stream.write(content)
    links = []
    for key in ('report', 'comparison', 'summary'):
        if key in receipt:
            target = Path(receipt[key]).with_suffix('.html')
            # Relative local links work when the private folder tree is retained.
            import os
            from urllib.parse import quote
            href = quote(os.path.relpath(target, directory).replace(os.sep, '/'), safe='/')
            links.append('<a href="' + html.escape(href, quote=True) + '">' + key.capitalize() + '</a>')
    with (directory / 'run-status.html').open('x', encoding='utf-8') as stream:
        stream.write('<!doctype html><meta charset="utf-8"><title>Sentinel run status</title>'
                     '<style>body{font:16px system-ui;max-width:1100px;margin:2em auto;padding:1em}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{margin-right:1em}</style>'
                     '<nav>' + ' '.join(links) + '</nav><pre>' + html.escape(content) + '</pre>')
    return content

def previous_inventory(private, root, explicit=None):
    if explicit:
        value = fc.read(explicit, root)
        return explicit, value, []
    paths = sorted(private.glob('report-*/file-inventory.json'))
    if len(paths) > 1000:
        raise ValueError('More than 1000 inventories; select one explicitly with --before')
    newest, warnings = None, []
    # Hold only the newest so far: inventories can be very large on big sites.
    for path in paths:
        try:
            value = fc.read(path, root)
            candidate = (datetime.datetime.fromisoformat(value['finished_utc']), str(path), value)
            if newest is None or candidate[:2] > newest[:2]:
                newest = candidate
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            warnings.append('Ignored invalid, unreadable or wrong-site inventory: ' + str(path))
    if newest is None:
        return None, None, warnings
    return Path(newest[1]), newest[2], warnings

def load_monitoring():
    spec = importlib.util.spec_from_file_location('routine_monitoring', Path(__file__).with_name('monitoring.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def run(args, profile, build, validate):
    root, private = validate(profile, args.profile)
    monitoring = config = None
    if args.prune_keep is not None and args.prune_keep < 1:
        raise ValueError('--prune-keep must be at least 1.')
    if args.alert_config:
        monitoring = load_monitoring()
        config = monitoring.load_config(args.alert_config)
    site = (config or {}).get('site_name') or root.name
    before, previous, warnings = previous_inventory(private, root, args.before)
    print('Routine check: scan, file comparison and summary. No automatic remediation.', flush=True)
    print('Previous inventory: ' + (str(before) if before else 'none; this run establishes the first observation'), flush=True)
    for warning in warnings:
        print('Coverage warning: ' + warning, flush=True)
    scan_args = argparse.Namespace(**vars(args))
    scan_args.command = 'scan'; scan_args.file_inventory = True
    scan_cmd = build(scan_args, profile)
    report_dir = Path(scan_cmd[scan_cmd.index('--output') + 1])
    result = {'format': 'sentinel-routine-1', 'site_root': str(root), 'status': 'incomplete',
              'report': str(report_dir / 'report.json'), 'inventory': str(report_dir / 'file-inventory.json'),
              'before_inventory': str(before) if before else None, 'warnings': warnings,
              'optional_checks_requested': [name for name in ('core', 'database', 'plugins', 'persistence', 'account_cron') if getattr(args, name, False) or (name == 'database' and (args.db_from_wp_config or args.db_credentials))],
              'optional_checks_not_requested': [name for name in ('core', 'database', 'plugins', 'persistence', 'account_cron') if not getattr(args, name, False) and not (name == 'database' and (args.db_from_wp_config or args.db_credentials))],
              'note': 'Manual read-only checks of website content. Private evidence files are written; no baseline, review, website file or database record is replaced. Completion is not a clean-site verdict.'}
    def execute(cmd):
        try:
            return subprocess.run(cmd).returncode
        except OSError as error:
            warnings.append('Could not start stage: ' + type(error).__name__)
            return 2
    result['scan_exit_code'] = execute(scan_cmd)
    try:
        report = fc.m.report_load(report_dir / 'report.json', root)
        result['priority_counts'] = report.get('priority_counts', {})
        result['checks'] = report['checks']
        result['limitations'] = report.get('limitations', [])
    except (OSError, ValueError, KeyError, TypeError):
        warnings.append('No valid scan report was produced; comparison and summary were not run.')
        print(json.dumps(result, indent=2), flush=True)
        if config:
            outcome = monitoring.process_failure(config, private / 'alert-state.json', site, 'No valid scan report was produced.')
            if outcome['failures']:
                print('WARNING: failure alert not delivered: ' + '; '.join(outcome['failures']), flush=True)
        return 2
    try:
        current = fc.read(report_dir / 'file-inventory.json', root)
        result['inventory_traversal_complete'] = current['traversal_complete']
        if before:
            # Validate compatibility before starting the comparison command.
            fc.compare(previous, current, root)
            compare_args = argparse.Namespace(command='file-changes', profile=args.profile, before=before, after=report_dir / 'file-inventory.json')
            compare_cmd = build(compare_args, profile)
            result['comparison_exit_code'] = execute(compare_cmd)
            compare_dir = Path(compare_cmd[compare_cmd.index('--output') + 1])
            if result['comparison_exit_code'] == 0:
                data = json.loads((compare_dir / 'file-changes.json').read_text(encoding='utf-8'))
                result['file_change_counts'] = data['counts']
                result['comparison'] = str(compare_dir / 'file-changes.json')
        else:
            result['comparison_status'] = 'not performed: no previous valid inventory'
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        result['comparison_exit_code'] = 2
        warnings.append('Inventory comparison unavailable: ' + type(error).__name__)
    summary_cmd = build(argparse.Namespace(command='summary', profile=args.profile), profile)
    result['summary_exit_code'] = execute(summary_cmd)
    summary_dir = Path(summary_cmd[summary_cmd.index('--output') + 1])
    if result['summary_exit_code'] == 0:
        result['summary'] = str(summary_dir / 'summary.json')
    summary = None
    if result['summary_exit_code'] == 0:
        try:
            summary = fc.m.load_json(summary_dir / 'summary.json')
            if summary.get('site_root') != str(root) or not isinstance(summary.get('review_records'), list):
                raise ValueError('Invalid review history')
        except (OSError, ValueError, TypeError, AttributeError):
            summary = None
            warnings.append('Review history unavailable; no findings treated as reviewed.')
    # Scan exit 4 means --fail-on matched: the scan itself completed.
    partial = bool(warnings) or result['scan_exit_code'] not in (0, 4) or any(result.get(k, 0) != 0 for k in ('comparison_exit_code','summary_exit_code')) or not result.get('inventory_traversal_complete', False)
    result['status'] = 'completed-with-gaps' if partial else 'completed'
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result['run_status'] = brief_status(report, result, summary)
    status_text = write_status(report_dir, result['run_status'], result)
    # The scan directory is new. Never overwrite an existing receipt.
    with (report_dir / 'routine.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({k:v for k,v in result.items() if k not in ('checks','limitations','run_status')}, indent=2), flush=True)
    print(status_text, flush=True)
    print('Readable status report: ' + str(report_dir / 'run-status.html'), flush=True)
    print('Coverage details and limitations: ' + str(report_dir / 'routine.json'), flush=True)
    alert_failed = False
    if config:
        outcome = monitoring.process_report(config, private / 'alert-state.json', site, report, report_dir / 'report.html', result.get('file_change_counts'))
        alert_failed = bool(outcome['failures'])
        print(('WARNING: alert not delivered, will be tried again next run: ' + '; '.join(outcome['failures'])) if alert_failed
              else 'Alert sent.' if outcome['sent'] else 'No alert needed: nothing new or changed since the last alert.', flush=True)
    if args.prune_keep is not None:
        removed = load_monitoring().prune_hosted(private, args.prune_keep, True)['folders']
        if removed:
            print(f'Removed {len(removed)} older report folders; the first and newest {args.prune_keep} of each kind are kept.', flush=True)
    if alert_failed:
        return load_monitoring().EXIT_ALERT_FAILED
    return 4 if result['scan_exit_code'] == 4 else 3 if partial else 0
