"""Read-only inventories of common WordPress startup files and account crontab."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

DROPINS = ('advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php',
           'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php',
           'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php')

def parse_crontab(text):
    jobs, malformed, environment = [], [], 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', stripped):
            environment += 1
            continue
        fields = stripped.split(None, 1 if stripped.startswith('@') else 5)
        valid = len(fields) == (2 if stripped.startswith('@') else 6)
        if not valid:
            malformed.append(number)
            continue
        jobs.append({'source': 'scheduled-task', 'location': f'account-crontab:line={number}',
                     'rule': 'account-scheduled-job', 'severity': 'review', 'line': number,
                     'sha256': hashlib.sha256(line.encode('utf-8')).hexdigest(), 'content_complete': True,
                     'reason': 'Account-level scheduled command exists. Review locally; command and environment values are deliberately omitted. It may be unrelated to this website.'})
    return jobs, {'job_count': len(jobs), 'environment_assignment_count': environment, 'unparsed_line_numbers': malformed}

def account_cron():
    executable = shutil.which('crontab')
    if not executable:
        return [], {'status': 'unavailable', 'reason': 'crontab command not found; hosting-panel jobs may still exist'}
    # Avoid including commands or credentials in terminal/report output.
    # Temporary streams also avoid unbounded in-memory command output.
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            run = subprocess.run([executable, '-l'], stdout=out, stderr=err, timeout=15,
                                 env=dict(os.environ, LC_ALL='C'), check=False)
            out.seek(0); err.seek(0)
            raw, errors = out.read(1048577), err.read(4096)
        if len(raw) > 1048576:
            return [], {'status': 'unchecked', 'reason': 'Crontab output exceeds 1 MiB limit'}
        if run.returncode:
            if run.returncode == 1 and b'no crontab for' in errors.lower():
                return [], {'status': 'no-account-crontab-reported', 'reason': 'This does not cover hosting-panel or system jobs'}
            return [], {'status': 'unavailable', 'exit_code': run.returncode, 'reason': 'Could not list account crontab; no raw error text retained'}
        text = raw.decode('utf-8')
        jobs, summary = parse_crontab(text)
        return jobs, dict(summary, status='listed', scope='Current SSH account only; commands were not executed or included in report')
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        return [], {'status': 'unavailable', 'reason': type(error).__name__}

def inspect(root, hashes, include_cron=False):
    findings, items, skipped = [], [], []
    candidates = {}
    mu = root / 'wp-content' / 'mu-plugins'
    def safe_path(path):
        return not any(p.is_symlink() for p in [path, *path.parents] if p == root or root in p.parents)
    if mu.exists() or mu.is_symlink():
        if not safe_path(mu) or not mu.is_dir():
            skipped.append({'path': 'wp-content/mu-plugins', 'reason': 'Symlink or non-directory; not traversed'})
        else:
            try:
                with os.scandir(mu) as entries:
                    for number, entry in enumerate(entries):
                        if number >= 1000:
                            skipped.append({'path': 'wp-content/mu-plugins', 'reason': 'Top-level inventory capped at 1000 entries'})
                            break
                        if entry.name.lower().endswith('.php'):
                            candidates['wp-content/mu-plugins/' + entry.name] = 'must-use-plugin-entry'
            except OSError:
                skipped.append({'path': 'wp-content/mu-plugins', 'reason': 'Cannot list directory'})
    for name in DROPINS:
        path = root / 'wp-content' / name
        if path.exists() or path.is_symlink():
            candidates['wp-content/' + name] = 'wordpress-drop-in'
    for name in hashes:
        if Path(name).name in {'.user.ini', 'php.ini', '.htaccess'}:
            candidates[name] = 'configuration-file'
    for name, kind in sorted(candidates.items()):
        path = root / name
        if not safe_path(path) or name not in hashes:
            skipped.append({'path': name, 'reason': 'Symlink or not hashed by bounded file scan'})
            continue
        try:
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
            with os.fdopen(os.open(path, flags), 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError('Not a regular file')
                data = stream.read(1048577)
            if len(data) > 1048576 or hashlib.md5(data).hexdigest() != hashes[name]:
                skipped.append({'path': name, 'reason': 'Over 1 MiB or changed since file scan'})
                continue
            digest = hashlib.sha256(data).hexdigest()
            items.append({'path': name, 'kind': kind, 'sha256': digest})
            if kind != 'configuration-file':
                reason = ('Top-level PHP file in the default must-use plugin directory; often a legitimate hosting integration.'
                          if kind == 'must-use-plugin-entry' else 'WordPress drop-in filename present; loading depends on configuration and conditions. Often legitimate caching or hosting code.')
                findings.append({'source': 'file', 'location': name, 'rule': kind, 'severity': 'review', 'line': None,
                                 'sha256': digest, 'content_complete': True, 'reason': reason})
            else:
                for number, line in enumerate(data.decode('utf-8', errors='replace').splitlines(), 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith(('#', ';')):
                        continue
                    match = re.search(r'\b(auto_prepend_file|auto_append_file|zend_extension|extension)\b\s*(?:=|\s)\s*(.*)', stripped, re.I)
                    if match:
                        value = match.group(2).strip().strip('"\'')
                        if value.lower() in {'', 'none', 'off'}:
                            continue
                        findings.append({'source': 'file', 'location': name, 'rule': 'php-startup-directive', 'severity': 'review', 'line': number,
                                         'sha256': digest, 'content_complete': True,
                                         'reason': f'{match.group(1).lower()} setting found. Verify its target locally; target text is omitted. Presence does not establish that this PHP handler applies the setting.'})
        except (OSError, ValueError):
            skipped.append({'path': name, 'reason': 'Unable to read bounded regular file'})
    cron_findings, cron = account_cron() if include_cron else ([], {'status': 'not requested'})
    findings.extend(cron_findings)
    limitations = [
        'Persistence inventory uses default wp-content/mu-plugins and drop-in paths only. wp-config.php is not executed or parsed; relocated content/MU directories can be missed.',
        'Configuration inspection is limited to inspected .user.ini, php.ini, and .htaccess files inside the selected root. Parent directories, system PHP configuration, environment settings, Apache/Nginx configuration, and actual handler behavior remain unchecked.',
        'Account crontab inventory, when requested, is read with crontab -l only. It excludes other users, system jobs, panel-managed schedules not exposed by crontab, and WordPress database cron hooks. No job command is executed.',
        'Startup file presence is a review observation, not a malware verdict. Indirect includes, opcode caches, running processes, and server-level persistence are not resolved by this inventory.'
    ]
    partial = bool(skipped) or (include_cron and (cron.get('status') not in {'listed', 'no-account-crontab-reported'} or cron.get('unparsed_line_numbers')))
    return findings, {'status': 'partial' if partial else 'completed-within-stated-scope', 'files': items, 'unchecked_entries': skipped, 'account_crontab': cron}, limitations
