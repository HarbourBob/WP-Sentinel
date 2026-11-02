#!/usr/bin/env python3
"""Run WordPress Sentinel on a host over SSH from your own computer and keep the evidence here.

Nothing is left installed on the host. Reports and inventories are copied back, recorded in a
hash chain, and compared with earlier runs held on this computer, which the host cannot alter.
A compromised host can still lie about what it sees. See documentation/REMOTE.txt.
"""
import argparse
import contextlib
import datetime
import hashlib
import html
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
PROGRAM_FILES = ('sentinel.py', 'database.php', 'persistence.py', 'rules.json')
MAX_PULL_BYTES = 1024 * 1024 * 1024
MAX_PULL_FILES = 50
RUN_NAME = re.compile(r'\.sentinel-run-[A-Za-z0-9_]{6,}')
RUN_FOLDER = re.compile(r'\d{8}T\d{6}Z-[0-9a-f]{6}')
ACCOUNT_SUMMARY = re.compile(r'summary-\d{8}T\d{6}Z-[0-9a-f]{6}\.(?:json|html)')
CONTROL_TEXT = re.compile('[\x00-\x1f\x7f]')
LOCK_EXPIRY_SECONDS = 12 * 3600

# Small programs run on the host. They receive paths as arguments and never go through a shell pipeline.
AGENT_MAKE = "import os,sys,tempfile;os.umask(0o077);print(tempfile.mkdtemp(prefix='.sentinel-run-',dir=os.path.expanduser(sys.argv[1])))"
AGENT_RECEIVE = "import sys,tarfile;t=tarfile.open(fileobj=sys.stdin.buffer,mode='r|');[t.extract(m,sys.argv[1]) for m in t if m.isfile() and '/' not in m.name and not m.name.startswith('.')]"
AGENT_HASH = "import hashlib,json,os,sys;d=sys.argv[1];print(json.dumps({n:hashlib.sha256(open(os.path.join(d,n),'rb').read()).hexdigest() for n in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d,n))}))"
AGENT_SEND = "import sys,tarfile;t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|');t.add(sys.argv[1],arcname='report');t.close()"
AGENT_REMOVE = "import os,re,shutil,sys;p=sys.argv[1];assert re.fullmatch(r'\\.sentinel-run-[A-Za-z0-9_]{6,}',os.path.basename(p)) and not os.path.islink(p);shutil.rmtree(p)"

def now():
    return datetime.datetime.now(datetime.timezone.utc)

def load_module(name):
    spec = importlib.util.spec_from_file_location('sentinel_remote_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_file_changes():
    return load_module('file_changes')

class Host:
    """Runs argument lists on the host through ssh. Host-key checking stays at ssh's own settings."""
    def __init__(self, args):
        self.ssh = shlex.split(args.ssh_command) + (['-p', str(args.port)] if args.port else []) + (['-i', str(args.identity)] if args.identity else [])
        # Fail rather than wait on a port that is not answering as SSH, such as FTP on 21.
        # Not on Windows: its ssh sits out the whole timeout on every connection, and hosts may drop it.
        if os.name != 'nt':
            self.ssh += ['-o', 'ConnectTimeout=30']
        if args.unattended:
            # Fail rather than wait forever for a passphrase or host-key answer nobody will give.
            self.ssh += ['-o', 'BatchMode=yes']
        self.target = args.host
        self.python = args.remote_python

    def command(self, argv, tty=False):
        return self.ssh + (['-t'] if tty else ['-T']) + [self.target, shlex.join(argv)]

    def agent(self, code, *values):
        return [self.python, '-I', '-S', '-c', code, *values]

    def capture(self, argv, payload=None):
        try:
            result = subprocess.run(self.command(argv), input=payload, capture_output=True, timeout=600)
        except subprocess.TimeoutExpired:
            raise RuntimeError('SSH did not finish within 10 minutes. Check --port (many hosts do not use 22; FTP is usually 21). See "IF IT WILL NOT CONNECT" in REMOTE.txt.') from None
        if result.returncode == 255:
            # ssh's own failure. Its reason is what the user needs, once made safe to print.
            lines = [CONTROL_TEXT.sub('?', line.strip())[:200] for line in result.stderr.decode('utf-8', 'replace').splitlines() if line.strip()]
            raise RuntimeError('SSH could not connect or log in (exit 255). ' + ('SSH said: ' + ' / '.join(lines[-3:]) + '. ' if lines else '')
                               + 'Check the login name, --port (many hosts do not use 22) and --identity. See "IF IT WILL NOT CONNECT" in REMOTE.txt.')
        if result.returncode:
            # Only the exit code is reported: host output is untrusted and may carry terminal escapes.
            raise RuntimeError(f'A step on the host failed (exit {result.returncode}). Check that "{self.python}" exists there and that key-based SSH works.')
        return result.stdout

def package_tar(extra):
    """Bundle the program files, and any reference ZIPs, for upload."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tar:
        for name in PROGRAM_FILES:
            tar.add(HERE / name, arcname=name)
        for name, path in extra.items():
            tar.add(path, arcname=name)
    return buffer.getvalue()

def file_hashes(names, extra):
    result = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}
    result.update({name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in extra.items()})
    return result

def safe_extract(stream, destination):
    """Unpack only plain files under report/. The host is untrusted, so nothing else is accepted."""
    total, count = 0, 0
    with tarfile.open(fileobj=stream, mode='r|') as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.isdir() and parts == ('report',):
                continue
            if not member.isfile() or len(parts) != 2 or parts[0] != 'report' or parts[1] in ('.', '..') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}', parts[1]):
                raise ValueError('Unexpected entry in the evidence sent by the host; nothing further was accepted.')
            count += 1
            total += member.size
            if count > MAX_PULL_FILES or total > MAX_PULL_BYTES:
                raise ValueError('Evidence sent by the host exceeds the size limit.')
            source = tar.extractfile(member)
            with (destination / parts[1]).open('xb') as target:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1048576, remaining))
                    if not chunk:
                        raise ValueError('Evidence sent by the host was truncated.')
                    target.write(chunk)
                    remaining -= len(chunk)
    if not count:
        raise ValueError('The host sent no evidence.')

def site_directory(evidence, host, root):
    identity = hashlib.sha256((host + '\0' + root).encode()).hexdigest()[:12]
    slug = re.sub(r'[^A-Za-z0-9.-]+', '-', host.split('@')[-1])[:40].strip('-') or 'site'
    return evidence / (slug + '-' + identity)

def seal(run_dir, site_dir, metadata):
    """Record a hash of each file, linked to the previous run, so later edits can be detected."""
    chain_path = site_dir / 'chain.json'
    chain = json.loads(chain_path.read_text(encoding='utf-8')) if chain_path.exists() else {'format': 'sentinel-evidence-chain-1', 'runs': []}
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run_dir.iterdir()) if p.is_file() and p.name != 'EVIDENCE.json'}
    record = dict(metadata, format='sentinel-evidence-1', run=run_dir.name, sealed_utc=now().isoformat(), files=files,
                  previous_seal=chain['runs'][-1]['seal'] if chain['runs'] else None)
    body = json.dumps(record, indent=2, sort_keys=True).encode()
    (run_dir / 'EVIDENCE.json').write_bytes(body)
    chain['runs'].append({'run': run_dir.name, 'seal': hashlib.sha256(body).hexdigest()})
    write_chain(chain_path, chain)
    return chain['runs'][-1]['seal']

def write_chain(chain_path, chain):
    pending = chain_path.with_name('chain.json.tmp')
    pending.write_text(json.dumps(chain, indent=2), encoding='utf-8')
    os.replace(pending, chain_path)

def verify_chain(site_dir):
    """Check every sealed run against the chain. Returns a list of problems."""
    chain = json.loads((site_dir / 'chain.json').read_text(encoding='utf-8'))
    problems, previous = [], None
    for entry in chain['runs']:
        run_dir = site_dir / entry['run']
        if entry.get('pruned_utc'):
            # Removed on request. Its seal stays so the next run's link can still be checked.
            previous = entry['seal']
            continue
        try:
            body = (run_dir / 'EVIDENCE.json').read_bytes()
        except OSError:
            problems.append(entry['run'] + ': EVIDENCE.json is missing')
            previous = entry['seal']
            continue
        if hashlib.sha256(body).hexdigest() != entry['seal']:
            problems.append(entry['run'] + ': EVIDENCE.json does not match the chain')
        record = json.loads(body)
        if record.get('previous_seal') != previous:
            problems.append(entry['run'] + ': link to the previous run is wrong')
        previous = entry['seal']
        for name, digest in record.get('files', {}).items():
            path = run_dir / name
            if not path.is_file():
                problems.append(f'{entry["run"]}: {name} is missing')
            elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                problems.append(f'{entry["run"]}: {name} has changed since it was sealed')
    return problems, len(chain['runs'])

def prune_site(site_dir, keep, apply):
    """Keep the first run and the newest runs. The chain records what was removed, and when."""
    monitoring = load_module('monitoring')
    chain_path = site_dir / 'chain.json'
    chain = json.loads(chain_path.read_text(encoding='utf-8'))
    live = [entry for entry in chain['runs'] if not entry.get('pruned_utc')]
    remove = live[1:-keep]
    oldest_kept = live[-keep]['run'] if len(live) >= keep else ''
    sealed = {entry['run'] for entry in chain['runs']}
    # Folders never sealed come from scans that failed; old ones hold nothing to check.
    unsealed = [p for p in site_dir.iterdir() if p.is_dir() and not p.is_symlink() and RUN_FOLDER.fullmatch(p.name) and p.name not in sealed and p.name < oldest_kept]
    names = sorted([entry['run'] for entry in remove] + [p.name for p in unsealed])
    if not all(RUN_FOLDER.fullmatch(str(name)) for name in names):
        raise ValueError('Unexpected run name in chain.json; nothing was removed.')
    if apply and names:
        stamp = now().isoformat()
        for entry in remove:
            entry['pruned_utc'] = stamp
        write_chain(chain_path, chain)
        for name in names:
            if (site_dir / name).exists():
                monitoring.remove_folder(site_dir / name, site_dir)
    return names

def prune(args):
    if args.keep < 1:
        raise ValueError('--keep must be at least 1.')
    evidence = Path(os.path.abspath(args.evidence_dir))
    sites = [p for p in sorted(evidence.iterdir()) if (p / 'chain.json').is_file()] if evidence.is_dir() else []
    if not sites:
        print('No sealed evidence found in ' + str(evidence))
        return 2
    for site_dir in sites:
        # Names in chain.json are checked in prune_site before anything is removed.
        names = prune_site(site_dir, args.keep, args.apply)
        print(f'{site_dir.name}: {"removed" if args.apply else "would remove"} {len(names)} run folders')
        for name in names:
            print('  ' + name)
    for account_dir in sorted(p for p in evidence.iterdir() if p.is_dir() and p.name.startswith('account-')):
        names = prune_account(account_dir, args.keep, args.apply)
        print(f'{account_dir.name}: {"removed" if args.apply else "would remove"} {len(names)} account summaries')
    if not args.apply:
        print('Preview only. The first and newest ' + str(args.keep) + ' runs are kept. Add --apply to remove these folders permanently.')
    return 0

def alert_test(args):
    monitoring = load_module('monitoring')
    failures = monitoring.send_test(monitoring.load_config(args.alert_config), args.site_name)
    print('Test alert sent.' if not failures else 'Test alert failed: ' + '; '.join(failures))
    return 0 if not failures else monitoring.EXIT_ALERT_FAILED

def read_report(run_dir):
    try:
        report = json.loads((run_dir / 'report.json').read_text(encoding='utf-8'))
        if not isinstance(report, dict) or not isinstance(report.get('findings'), list) or not isinstance(report.get('checks'), dict):
            raise ValueError('not a report')
    except (OSError, ValueError):
        raise RuntimeError('The host sent a report that could not be read.') from None
    return report

def send_alerts(args, monitoring, config, site_dir, run_dir, comparison):
    """Returns True if an alert that was due could not be delivered."""
    outcome = monitoring.process_report(config, site_dir / 'alert-state.json', config.get('site_name') or args.host.split('@')[-1], read_report(run_dir),
                                        run_dir / 'report.html', comparison['counts'] if comparison else None)
    if outcome['failures']:
        print('WARNING: alert not delivered (' + '; '.join(outcome['failures']) + '). It will be tried again next run.', file=sys.stderr)
    elif outcome['sent']:
        print(f'Alert sent: {outcome["new"]} new, {outcome["changed"]} changed findings.')
    else:
        print('No alert needed: nothing new or changed since the last alert.')
    return bool(outcome['failures'])

def previous_run(site_dir, current):
    """Newest earlier run holding a finished inventory, by name, which starts with its UTC time."""
    for run_dir in sorted((p for p in site_dir.iterdir() if p.is_dir() and p.name < current), reverse=True):
        if (run_dir / 'file-inventory.json').is_file():
            return run_dir
    return None

def compare_with_previous(site_dir, run_dir):
    earlier = previous_run(site_dir, run_dir.name)
    if earlier is None:
        return None, 'First run for this site: nothing earlier to compare with.'
    fc = load_file_changes()
    try:
        before = json.loads((earlier / 'file-inventory.json').read_text(encoding='utf-8'))
        after = json.loads((run_dir / 'file-inventory.json').read_text(encoding='utf-8'))
        # The host reports its resolved path, which can differ from the --root given here.
        result = fc.compare(before, after, after['site_root'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        return None, 'Could not compare with the previous run: ' + type(error).__name__
    result['before']['run'] = earlier.name
    (run_dir / 'file-changes.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result, None

def write_timeline(run_dir):
    """Build timeline.html from this run's inventory, before sealing so it is covered by the seal."""
    timeline = load_module('timeline')
    try:
        inventory = json.loads((run_dir / 'file-inventory.json').read_text(encoding='utf-8'))
        # The inventory came from the host, so it is checked before anything is built from it.
        timeline.fc.validate(inventory, inventory['site_root'])
        timeline.write(timeline.build(inventory), run_dir)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return 'Could not build the timeline: ' + type(error).__name__
    return None

def write_vulns(run_dir, evidence, args):
    """Check the host's software list against the vulnerability feed, on this computer, before sealing."""
    if args.no_vuln_check:
        return 'Vulnerability check skipped (--no-vuln-check).'
    vulns = load_module('vulns')
    cache = evidence / 'vuln-feed'
    try:
        key = vulns.read_key(args.vuln_key_file)
        if not key and not (cache / 'wordfence-index.json').is_file():
            return 'Vulnerability check skipped: no API key. See VULNERABILITIES.txt to set one up.'
        report = json.loads((run_dir / 'report.json').read_text(encoding='utf-8'))
        if not isinstance(report.get('software'), dict):
            return 'Vulnerability check skipped: the report has no software list.'
        feed, notes = vulns.load_feed(cache, key)
        result = vulns.check(report['software'], feed, notes)
        vulns.write(result, run_dir)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # The key never appears here: errors are reported by type or by our own messages.
        return 'Vulnerability check failed: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__)
    serious = sum(result['counts'][r] for r in ('Critical', 'High'))
    return (f'Vulnerabilities: {len(result["vulnerabilities"])} known in {result["affected_software"]} installed items, {serious} critical or high. '
            + str(run_dir / 'vulnerabilities.html'))

def make_checklist(args):
    checklist = load_module('checklist')
    run_dir = Path(os.path.abspath(args.run))
    if not RUN_FOLDER.fullmatch(run_dir.name) or not (run_dir / 'report.json').is_file():
        raise ValueError('--run must be a run folder holding report.json, such as sentinel-evidence/SITE/20261101T204908Z-c29d80')
    load = lambda name: json.loads((run_dir / name).read_text(encoding='utf-8')) if (run_dir / name).is_file() else None
    sealed = load('EVIDENCE.json') or {}
    scan_command = monitor_command = None
    if sealed.get('host') and sealed.get('root'):
        base = ['python', 'sentinel-remote.py', 'scan', '--host', sealed['host'], '--root', sealed['root'], '--core', '--plugins', '--themes', '--persistence']
        scan_command = shlex.join(base)
        monitor_command = shlex.join(base + ['--unattended', '--alert-config', 'alerts.json', '--prune-keep', '30'])
    result = checklist.build(load('report.json'), load('vulnerabilities.json'), load('timeline.json'), scan_command, monitor_command)
    output = run_dir.parent / ('checklist-' + run_dir.name)
    output.mkdir(mode=0o700)
    checklist.write(result, output)
    print('Checklist: ' + str(output / 'checklist.html'))
    return 0

def remote_scan_arguments(args, run_path, references):
    tail = [args.remote_python, '-I', '-S', run_path + '/sentinel.py', '--root', args.root, '--output', run_path + '/report',
            '--file-inventory', '--max-file-mb', str(args.max_file_mb)]
    if args.core:
        tail += ['--core-version', args.core_version, '--locale', args.locale]
    for flag in ('database', 'db_from_wp_config', 'plugins', 'themes', 'persistence', 'account_cron'):
        if getattr(args, flag):
            tail.append('--' + flag.replace('_', '-'))
    for flag in ('db_credentials', 'max_files', 'db_row_limit', 'db_value_limit', 'php', 'fail_on'):
        value = getattr(args, flag)
        if value is not None:
            tail += ['--' + flag.replace('_', '-'), str(value)]
    for target, name in references:
        tail += ['--reference', f'{target}={run_path}/{name}']
    for relative in getattr(args, 'separate_sites', ()):
        tail += ['--separate-site', relative]
    return tail

def valid_remote_root(root):
    return root.startswith('/') and '..' not in root.split('/')

def valid_run_path(path):
    return RUN_NAME.fullmatch(re.split(r'[\\/]', path)[-1]) is not None

@contextlib.contextmanager
def run_lock(site_dir):
    """Scheduled runs can overlap, and two writers would damage the chain. A crash's lock expires."""
    site_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = site_dir / '.run-lock'
    try:
        if time.time() - lock.stat().st_mtime > LOCK_EXPIRY_SECONDS:
            lock.unlink()
    except FileNotFoundError:
        pass
    try:
        lock.open('x').close()
    except FileExistsError:
        raise RuntimeError('Another run for this site is still going, or crashed in the last 12 hours. If none is running, delete ' + str(lock)) from None
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)

def scan(args):
    """Run a scan, with alerts if asked for. Failures become an alert too: silence must not hide them."""
    monitoring = load_module('monitoring') if args.alert_config else None
    config = monitoring.load_config(args.alert_config) if monitoring else None
    if args.unattended and args.database:
        raise ValueError('--database prompts for details, which an unattended run cannot answer. Use --db-from-wp-config or --db-credentials.')
    if args.database and (args.db_from_wp_config or args.db_credentials):
        raise ValueError('Use only one way of giving database details.')
    if args.db_from_wp_config and args.db_credentials:
        raise ValueError('Use only one of --db-from-wp-config and --db-credentials.')
    if args.prune_keep is not None and args.prune_keep < 1:
        raise ValueError('--prune-keep must be at least 1.')
    site_dir = site_directory(Path(os.path.abspath(args.evidence_dir)), args.host, args.root)
    try:
        with run_lock(site_dir):
            code, run_dir, comparison = run_scan(args)
            alert_failed = send_alerts(args, monitoring, config, site_dir, run_dir, comparison) if config else False
            if args.prune_keep is not None:
                names = prune_site(site_dir, args.prune_keep, True)
                if names:
                    print(f'Removed {len(names)} older run folders; the first and newest {args.prune_keep} are kept.')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        if config:
            site_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            outcome = monitoring.process_failure(config, site_dir / 'alert-state.json', config.get('site_name') or args.host.split('@')[-1], error)
            if outcome['failures']:
                print('WARNING: failure alert not delivered (' + '; '.join(outcome['failures']) + ').', file=sys.stderr)
        raise
    return monitoring.EXIT_ALERT_FAILED if alert_failed else code

def run_scan(args):
    if not valid_remote_root(args.root):
        raise ValueError('--root must be an absolute path on the host.')
    host = Host(args)
    extra, references = {}, []
    for number, value in enumerate(args.reference):
        target, separator, path = value.partition('=')
        if not separator or not re.fullmatch(r'(plugin|theme):[A-Za-z0-9][A-Za-z0-9._-]{0,99}', target) or not Path(path).is_file():
            raise ValueError('Use --reference plugin:folder=LOCAL.zip or theme:folder=LOCAL.zip with an existing file.')
        name = f'reference-{number}.zip'
        extra[name] = path
        references.append((target, name))
    evidence = Path(os.path.abspath(args.evidence_dir))
    site_dir = site_directory(evidence, args.host, args.root)
    site_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = now()
    run_dir = site_dir / (started.strftime('%Y%m%dT%H%M%SZ') + '-' + os.urandom(3).hex())
    run_dir.mkdir(mode=0o700)
    print('Evidence folder: ' + str(run_dir), flush=True)
    print('Creating a temporary folder on the host...', flush=True)
    run_path = host.capture(host.agent(AGENT_MAKE, args.remote_temp)).decode('ascii', 'replace').strip()
    if not valid_run_path(run_path):
        raise RuntimeError('The host returned an unexpected temporary folder name; stopping.')
    code = 2
    try:
        print('Uploading Sentinel ' + str(len(PROGRAM_FILES)) + ' program files...', flush=True)
        host.capture(host.agent(AGENT_RECEIVE, run_path), package_tar(extra))
        reported = json.loads(host.capture(host.agent(AGENT_HASH, run_path)))
        expected = file_hashes(PROGRAM_FILES, extra)
        if reported != expected:
            raise RuntimeError('Uploaded files do not match on the host; stopping before the scan. The host may be altering files.')
        print('Scanning. Output from here on comes from the host.', flush=True)
        # A terminal is only needed for the hidden database password prompt.
        code = subprocess.run(host.command(remote_scan_arguments(args, run_path, references), tty=args.database)).returncode
        if code not in (0, 3, 4):
            raise RuntimeError(f'The scan on the host stopped (exit {code}).')
        print('Copying the evidence back...', flush=True)
        process = subprocess.Popen(host.command(host.agent(AGENT_SEND, run_path + '/report')), stdout=subprocess.PIPE)
        try:
            safe_extract(process.stdout, run_dir)
            process.stdout.read()
        finally:
            process.stdout.close()
            sent = process.wait(timeout=120)
        if sent:
            raise RuntimeError(f'Copying the evidence failed (exit {sent}).')
    finally:
        try:
            host.capture(host.agent(AGENT_REMOVE, run_path))
            print('Temporary folder removed from the host.', flush=True)
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            print('WARNING: could not remove the temporary folder on the host: ' + run_path, file=sys.stderr, flush=True)
    comparison, note = compare_with_previous(site_dir, run_dir)
    timeline_problem = write_timeline(run_dir)
    vuln_line = write_vulns(run_dir, evidence, args)
    seal_value = seal(run_dir, site_dir, {'host': args.host, 'root': args.root, 'started_utc': started.isoformat(), 'scan_exit_code': code,
                                          'program_sha256': expected, 'note': 'Records what this computer received. It cannot prove the host reported honestly.'})
    print('Sealed run ' + run_dir.name + ' (' + seal_value[:16] + '...)')
    if comparison:
        print('Changes since ' + comparison['before']['run'] + ': ' + json.dumps({k: v for k, v in comparison['counts'].items() if v and k != 'unchanged'}))
    else:
        print(note)
    print(timeline_problem or 'Timeline: ' + str(run_dir / 'timeline.html'))
    print(vuln_line)
    print('Open the report: ' + str(run_dir / 'report.html'))
    return code, run_dir, comparison

def account_directory(evidence, host):
    site = site_directory(evidence, host, 'account')
    return site.with_name('account-' + site.name)

def prune_account(account_dir, keep, apply):
    """Account summaries are only an overview, so just the newest are kept."""
    stamps = sorted({p.name[:-5] for p in account_dir.iterdir() if p.is_file() and ACCOUNT_SUMMARY.fullmatch(p.name)})
    remove = stamps[:-keep]
    if apply:
        for stamp in remove:
            for suffix in ('.json', '.html'):
                (account_dir / (stamp + suffix)).unlink(missing_ok=True)
    return remove

def discover_installs(args):
    """Ask the host for its installs. The discovery program is sent for this one command; nothing is stored."""
    host = Host(args)
    raw = host.capture(host.agent((HERE / 'discover.py').read_text(encoding='utf-8'), *args.start))
    try:
        data = json.loads(raw)
        installs = data['installs']
        if not isinstance(installs, list) or not all(isinstance(i, dict) and isinstance(i.get('path'), str) and valid_remote_root(i['path']) and not CONTROL_TEXT.search(i['path']) for i in installs):
            raise ValueError('bad list')
        for key in ('config_without_core', 'unreadable'):
            if not isinstance(data.get(key), list) or not all(isinstance(item, str) for item in data[key]):
                raise ValueError('bad list')
    except (ValueError, KeyError, TypeError):
        raise RuntimeError('The host sent a list of installs that could not be read.') from None
    return data

def show_discovery(data, clean, write=print):
    for install in data['installs']:
        write(f'  {clean(install["path"], 300)}  WordPress {clean(install.get("version") or "unknown", 40)}' + ('  (inside wp-content: unusual)' if install.get('inside_wp_content') else '') + ('' if install.get('has_config') else '  (no wp-config.php here)'))
    for path in data['config_without_core']:
        write(f'  wp-config.php without WordPress core: {clean(path, 300)}')
    for path in data['unreadable']:
        write(f'  Could not read: {clean(path, 300)}')
    if data.get('truncated'):
        write('  The search hit its depth or size limit, so this list may be incomplete. Use --start to narrow it.')

def discover(args):
    monitoring = load_module('monitoring')
    data = discover_installs(args)
    print(f'{len(data["installs"])} WordPress installs found under ' + ', '.join(monitoring.clean(item, 300) for item in args.start))
    show_discovery(data, monitoring.clean)
    return 3 if data.get('truncated') else 0

def excluded(path, exclusions):
    return any(path == item or path.startswith(item + '/') for item in exclusions)

def scan_one_install(args, monitoring, config, evidence, install, nested, first):
    """Scan one install. A failure here must not stop the others, so it comes back as a row."""
    path = install['path']
    site_dir = site_directory(evidence, args.host, path)
    site_args = argparse.Namespace(**vars(args))
    # The crontab belongs to the account, so one site's report is enough.
    site_args.root, site_args.separate_sites, site_args.account_cron = path, nested, args.account_cron and first
    site_args.database, site_args.db_credentials, site_args.core_version, site_args.reference = False, None, 'auto', []
    row = {'path': path, 'version': install.get('version'), 'inside_wp_content': bool(install.get('inside_wp_content')), 'separate_sites': nested}
    try:
        with run_lock(site_dir):
            code, run_dir, comparison = run_scan(site_args)
            report = read_report(run_dir)
            counts = comparison['counts'] if comparison else None
            prepared = monitoring.prepare_report(config, site_dir / 'alert-state.json', path, report, run_dir / 'report.html', counts) if config else None
            if args.prune_keep is not None:
                prune_site(site_dir, args.prune_keep, True)
        row.update(status='scanned with gaps' if code == 3 or monitoring.failed_checks(report) else 'scanned', exit_code=code, report=str(run_dir / 'report.html'),
                   priority_counts=report.get('priority_counts', {}), file_changes={k: counts[k] for k in ('added', 'changed', 'missing')} if counts else None,
                   gaps=monitoring.failed_checks(report))
        return row, prepared
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print('This site failed: ' + monitoring.clean(error, 400), file=sys.stderr, flush=True)
        row.update(status='failed', exit_code=2, reason=monitoring.clean(error, 400))
        return row, monitoring.prepare_failure(site_dir / 'alert-state.json', path, error) if config else None

def account_changes(account_dir, monitoring, data, coverage):
    """What changed about the account itself since it was last recorded. Nothing is claimed on a first run."""
    path = account_dir / 'installs.json'
    installs = {item['path']: item for item in data['installs']}
    try:
        known = json.loads(path.read_text(encoding='utf-8'))
        previous, previous_coverage = set(known['installs']), set(known['coverage'])
    except (OSError, ValueError, KeyError, TypeError):
        previous, previous_coverage = None, set()
    lines = []
    if previous is not None:
        for name in sorted(set(installs) - previous):
            note = ' It is inside wp-content, which is unusual: attackers sometimes plant a copy there.' if installs[name].get('inside_wp_content') else ''
            lines.append('New WordPress install: ' + monitoring.clean(name, 300) + '.' + note)
        # A cut-short search cannot say something has gone.
        if not data.get('truncated'):
            lines += ['WordPress install no longer found: ' + monitoring.clean(name, 300) for name in sorted(previous - set(installs))]
    lines += [monitoring.clean(item, 400) for item in coverage if item not in previous_coverage]
    def commit():
        pending = path.with_name('installs.json.tmp')
        pending.write_text(json.dumps({'installs': sorted(installs), 'coverage': coverage}, indent=1), encoding='utf-8')
        os.replace(pending, path)
    return {'due': bool(lines), 'account': True, 'subject': None, 'body': '\n'.join(lines), 'commit': commit}, lines

def render_account_summary(summary):
    """A self-contained overview page. Every value from the host is escaped."""
    escape = lambda value: html.escape(str(value), quote=True)
    page = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
            '<title>Sentinel account summary</title><style>',
            ':root{--ink:#182433;--muted:#566476;--line:#d5dce5;--panel:#f3f6f9;--bad:#a4161a;--warn:#b45309;--link:#1d4ed8;--bg:#fff}',
            '@media (prefers-color-scheme:dark){:root{--ink:#e6ebf1;--muted:#a3afbd;--line:#3a4654;--panel:#222b35;--bad:#ff8f8f;--warn:#f0b35a;--link:#8ab4ff;--bg:#151b22}}',
            'body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;padding:2em 1em;max-width:1400px;color:var(--ink);background:var(--bg)}a{color:var(--link)}h1{margin:0 0 .2em}',
            '.meta{color:var(--muted);font-size:.9em;overflow-wrap:anywhere}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.5em .7em;border-bottom:1px solid var(--line);vertical-align:top}',
            'th{background:var(--panel);font-size:.85em}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.path{overflow-wrap:anywhere;min-width:16em;font-weight:600}.note{display:block;font-weight:400;color:var(--muted);font-size:.9em}',
            '.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}li{margin:.4em 0;overflow-wrap:anywhere}',
            '</style><h1>Account summary</h1>',
            f'<p class="meta">{escape(summary["host"])} · {escape(summary["created_utc"])} · Sentinel account scan</p>',
            f'<p>{summary["scanned"]} of {len(summary["sites"])} WordPress installs scanned. Findings need review and are not malware verdicts. No findings would not mean a site is clean.</p>']
    if summary['account_changes']:
        page.append('<h2>Changes on the account</h2><ul>' + ''.join(f'<li>{escape(line)}</li>' for line in summary['account_changes']) + '</ul>')
    page.append('<h2>Sites</h2><div class="scroll"><table><tr><th>Site</th><th>WordPress</th><th>Status</th><th class="n">High</th><th class="n">Medium</th><th class="n">Review</th><th class="n">Info</th><th>Files since last run</th></tr>')
    for row in summary['sites']:
        counts = row.get('priority_counts') or {}
        status_class = {'failed': 'bad', 'scanned with gaps': 'warn', 'not scanned: limit reached': 'bad'}.get(row['status'], '')
        notes = ['Inside wp-content: unusual location.'] if row.get('inside_wp_content') else []
        if row.get('separate_sites'):
            notes.append('Scanned separately: ' + ', '.join(row['separate_sites']))
        if row.get('reason'):
            notes.append(row['reason'])
        notes += row.get('gaps') or []
        name = escape(row['path'])
        if row.get('report'):
            href = urllib.parse.quote(os.path.relpath(row['report'], summary['_folder']).replace(os.sep, '/'), safe='/')
            name = f'<a href="{escape(href)}">{name}</a>'
        changes = row.get('file_changes')
        changed = 'First run' if row.get('report') and not changes else ', '.join(f'{v} {k}' for k, v in changes.items() if v) or 'None' if changes else ''
        cells = ''.join(f'<td class="n{" bad" if level == "high" and counts.get(level) else ""}">{escape(counts.get(level, "")) }</td>' for level in ('high', 'medium', 'review', 'info'))
        page.append(f'<tr><td class="path">{name}' + ''.join(f'<span class="note">{escape(note)}</span>' for note in notes) + f'</td><td>{escape(row.get("version") or "")}</td><td class="{status_class}">{escape(row["status"])}</td>{cells}<td>{escape(changed)}</td></tr>')
    page.append('</table></div>')
    for title, key in (('wp-config.php without WordPress core', 'config_without_core'), ('Folders that could not be read', 'unreadable')):
        if summary[key]:
            page.append(f'<h2>{title}</h2><ul>' + ''.join(f'<li>{escape(item)}</li>' for item in summary[key]) + '</ul>')
    page.append(f'<h2>What was searched</h2><p class="meta">{escape(", ".join(summary["starts"]))}. Only WordPress installs under these folders were scanned. Other software and other accounts were not.' + (' The search hit its limit, so it may be incomplete.' if summary['truncated'] else '') + '</p>')
    return ''.join(page)

def scan_account(args, monitoring, config, evidence, account_dir, label):
    data = discover_installs(args)
    if not data['installs']:
        raise RuntimeError('No WordPress installs were found under: ' + ', '.join(args.start))
    exclusions = [item.rstrip('/') for item in args.exclude]
    chosen = [item for item in data['installs'] if not excluded(item['path'], exclusions)]
    over_limit, chosen = chosen[args.max_sites:], chosen[:args.max_sites]
    print(f'{len(data["installs"])} WordPress installs found; scanning {len(chosen)}.', flush=True)
    show_discovery(data, monitoring.clean, lambda line: print(line, flush=True))
    paths = [item['path'] for item in chosen]
    rows, prepared = [], []
    for number, install in enumerate(chosen, 1):
        print(f'\n=== [{number}/{len(chosen)}] {monitoring.clean(install["path"], 300)}', flush=True)
        # Only skip a nested install that really is being scanned on its own.
        nested = [other[len(install['path']) + 1:] for other in paths if other.startswith(install['path'] + '/')]
        row, item = scan_one_install(args, monitoring, config, evidence, install, nested, number == 1)
        rows.append(row)
        if item:
            prepared.append(item)
    for install in data['installs']:
        if excluded(install['path'], exclusions):
            rows.append({'path': install['path'], 'version': install.get('version'), 'status': 'excluded by --exclude', 'inside_wp_content': bool(install.get('inside_wp_content'))})
    rows += [{'path': item['path'], 'version': item.get('version'), 'status': 'not scanned: limit reached', 'inside_wp_content': bool(item.get('inside_wp_content'))} for item in over_limit]
    coverage = []
    if data.get('truncated'):
        coverage.append('The search for installs hit its limit, so some may have been missed.')
    coverage += [f'Not scanned because --max-sites is {args.max_sites}: {item["path"]}' for item in over_limit]
    account_item, change_lines = account_changes(account_dir, monitoring, data, coverage)
    stamp = 'summary-' + now().strftime('%Y%m%dT%H%M%SZ') + '-' + os.urandom(3).hex()
    summary = {'format': 'sentinel-account-summary-1', 'host': args.host, 'created_utc': now().isoformat(), 'starts': data.get('starts', []), 'truncated': bool(data.get('truncated')),
               'scanned': sum(row['status'].startswith('scanned') for row in rows), 'account_changes': change_lines, 'sites': rows,
               'config_without_core': data['config_without_core'], 'unreadable': data['unreadable'], 'excluded': exclusions,
               'note': 'Overview of the scans below. Not a verdict on any site.'}
    (account_dir / (stamp + '.json')).write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (account_dir / (stamp + '.html')).write_text(render_account_summary(dict(summary, _folder=str(account_dir))), encoding='utf-8')
    location = account_dir / (stamp + '.html')
    alert_failed = False
    if config:
        prepared.append(monitoring.prepare_report(config, account_dir / 'alert-state.json', label, {'findings': [], 'checks': {}}, location))
        prepared.append(account_item)
        outcome = monitoring.send_digest(config, label, prepared, len(chosen), location)
        alert_failed = bool(outcome['failures'])
        if alert_failed:
            print('WARNING: alert not delivered (' + '; '.join(outcome['failures']) + '). It will be tried again next run.', file=sys.stderr)
        else:
            print('Alert sent.' if outcome['sent'] else 'No alert needed: nothing new or changed since the last alert.')
    else:
        account_item['commit']()
    if args.prune_keep is not None:
        prune_account(account_dir, args.prune_keep, True)
    print('\nSite results:')
    for row in rows:
        print(f'  {monitoring.clean(row["path"], 300)}: {row["status"]}' + (' ' + json.dumps(row['priority_counts']) if row.get('priority_counts') else ''))
    for line in change_lines:
        print('  ' + line)
    print('Open the account summary: ' + str(location))
    codes = [row['exit_code'] for row in rows if 'exit_code' in row]
    if 2 in codes:
        return 2
    if alert_failed:
        return monitoring.EXIT_ALERT_FAILED
    if 4 in codes:
        return 4
    return 3 if 3 in codes or coverage else 0

def scan_all(args):
    """Scan every install found. One failing site does not stop the rest, and a failed search still alerts."""
    monitoring = load_module('monitoring')
    config = monitoring.load_config(args.alert_config) if args.alert_config else None
    if args.prune_keep is not None and args.prune_keep < 1:
        raise ValueError('--prune-keep must be at least 1.')
    if args.max_sites < 1:
        raise ValueError('--max-sites must be at least 1.')
    evidence = Path(os.path.abspath(args.evidence_dir))
    account_dir = account_directory(evidence, args.host)
    label = (config or {}).get('site_name') or args.host.split('@')[-1]
    try:
        with run_lock(account_dir):
            return scan_account(args, monitoring, config, evidence, account_dir, label)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        if config:
            outcome = monitoring.process_failure(config, account_dir / 'alert-state.json', label, error)
            if outcome['failures']:
                print('WARNING: failure alert not delivered (' + '; '.join(outcome['failures']) + ').', file=sys.stderr)
        raise

def verify(args):
    evidence = Path(os.path.abspath(args.evidence_dir))
    status = 0
    sites = [p for p in sorted(evidence.iterdir()) if (p / 'chain.json').is_file()] if evidence.is_dir() else []
    if not sites:
        print('No sealed evidence found in ' + str(evidence))
        return 2
    for site_dir in sites:
        try:
            problems, runs = verify_chain(site_dir)
        except (OSError, ValueError, KeyError, TypeError) as error:
            problems, runs = ['chain.json could not be read: ' + type(error).__name__], 0
        print(f'{site_dir.name}: {runs} runs, ' + ('all match' if not problems else f'{len(problems)} problems'))
        for problem in problems:
            print('  ' + problem)
            status = 1
    return status

def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    sub = p.add_subparsers(dest='action', required=True)
    def connection(c):
        c.add_argument('--host', required=True, help='SSH target, such as user@example.com')
        c.add_argument('--port', type=int)
        c.add_argument('--identity', type=Path, help='SSH private key file')
        c.add_argument('--ssh-command', default='ssh', help='SSH program to use')
        c.add_argument('--remote-python', default='python3')
        c.add_argument('--unattended', action='store_true', help='For scheduled runs: fail rather than wait for any answer')
    def scanning(c):
        c.add_argument('--evidence-dir', default='sentinel-evidence', help='Folder on this computer for evidence')
        c.add_argument('--remote-temp', default='~', help='Host folder for the temporary run folder. Must be outside every website.')
        c.add_argument('--core', action='store_true')
        c.add_argument('--locale', default='en_US')
        for flag in ('plugins', 'themes', 'persistence', 'account-cron'):
            c.add_argument('--' + flag, action='store_true')
        c.add_argument('--db-from-wp-config', action='store_true', help='Check the database without prompting, reading its details from wp-config.php on the host as text')
        c.add_argument('--alert-config', type=Path, help='Alert settings on this computer: tell you about new or changed findings and failures')
        c.add_argument('--prune-keep', type=int, help='After a successful run, permanently remove older runs, keeping the first and this many newest')
        c.add_argument('--max-file-mb', type=int, default=20)
        c.add_argument('--max-files', type=int)
        c.add_argument('--db-row-limit', type=int)
        c.add_argument('--db-value-limit', type=int)
        c.add_argument('--php')
        c.add_argument('--fail-on', choices=['high', 'medium', 'review', 'info'])
        c.add_argument('--vuln-key-file', type=Path, help='File holding your Wordfence Intelligence API key, for the vulnerability check; or set WORDFENCE_API_KEY')
        c.add_argument('--no-vuln-check', action='store_true', help='Skip checking installed versions for known vulnerabilities')
    def search(c):
        c.add_argument('--start', action='append', help='Host folder to search; repeatable. Default: your home folder')
    c = sub.add_parser('scan', allow_abbrev=False, help='Run a scan on the host and bring the evidence back')
    connection(c)
    scanning(c)
    c.add_argument('--root', required=True, help='Absolute path of the WordPress site on the host')
    c.add_argument('--core-version', default='auto')
    c.add_argument('--database', action='store_true')
    c.add_argument('--db-credentials', help='Check the database without prompting, using this private JSON file on the host')
    c.add_argument('--reference', action='append', default=[], help='plugin:folder=LOCAL.zip or theme:folder=LOCAL.zip; uploaded for this run only')
    c = sub.add_parser('discover', allow_abbrev=False, help='List the WordPress installs on the account without scanning them')
    connection(c)
    search(c)
    c = sub.add_parser('scan-all', allow_abbrev=False, help='Find every WordPress install on the account and scan each one')
    connection(c)
    scanning(c)
    search(c)
    c.add_argument('--exclude', action='append', default=[], help='Absolute host path to leave out, with anything inside it; repeatable')
    c.add_argument('--max-sites', type=int, default=50, help='Scan at most this many installs; any others are reported as not scanned')
    c = sub.add_parser('verify', allow_abbrev=False, help='Check that saved evidence has not changed since it was sealed')
    c.add_argument('--evidence-dir', default='sentinel-evidence')
    c = sub.add_parser('prune', allow_abbrev=False, help='Preview or remove older runs, keeping the first and the newest')
    c.add_argument('--evidence-dir', default='sentinel-evidence')
    c.add_argument('--keep', type=int, required=True, help='How many of the newest runs to keep for each site')
    c.add_argument('--apply', action='store_true', help='Permanently remove the folders listed in the preview')
    c = sub.add_parser('checklist', allow_abbrev=False, help='Build a post-incident checklist from one run')
    c.add_argument('--run', type=Path, required=True, help='A run folder inside the evidence folder')
    c = sub.add_parser('alert-test', allow_abbrev=False, help='Send a test alert')
    c.add_argument('--alert-config', type=Path, required=True)
    c.add_argument('--site-name', default='test')
    return p

def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    if getattr(args, 'start', False) is None:
        args.start = ['~']
    try:
        return {'scan': scan, 'discover': discover, 'scan-all': scan_all, 'verify': verify, 'prune': prune, 'checklist': make_checklist, 'alert-test': alert_test}[args.action](args)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Interrupted. The temporary folder is removed when possible; evidence may be incomplete.', file=sys.stderr)
        return 130

if __name__ == '__main__':
    raise SystemExit(main())
