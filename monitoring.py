"""Alerts for scheduled checks, and cleanup of old report folders. Uses only the Python standard library.

An alert goes out only for new or changed findings, new coverage gaps, or checks that stopped
working. Quiet does not mean clean. Nothing here changes website files or database records.
"""
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import json
import os
from pathlib import Path
import re
import shutil
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request

CONFIG_FORMAT = 'sentinel-alerts-1'
STATE_FORMAT = 'sentinel-alert-state-1'
SEVERITIES = ('high', 'medium', 'review', 'info')
# Recorded as info, but a change to these is worth telling someone about.
ALWAYS_ALERT_RULES = {'wp-site-url', 'wp-active-plugins'}
MAX_LISTED = 20
FAILURE_REPEAT = timedelta(hours=24)
EXIT_ALERT_FAILED = 5
REMINDER = 'Findings need review and are not malware verdicts. No alert does not mean the site is clean.'
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
UNSAFE_TEXT = re.compile('[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]')
HOSTED_FOLDER = re.compile(r'(report|file-changes|changes|summary)-\d{8}-\d{6}-[0-9a-f]{8}')

class AlertError(Exception):
    """A channel failed. The text never contains addresses, passwords or webhook URLs."""

def now():
    return datetime.now(timezone.utc)

def clean(value, limit=200):
    """Paths and rule names can come from a compromised host: keep them to one printable line."""
    return UNSAFE_TEXT.sub('?', str(value))[:limit]

def load_config(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 16384:
        raise ValueError('Alert settings must be a small regular file.')
    if os.name == 'posix' and path.stat().st_mode & 0o077:
        raise ValueError('Alert settings must have permissions 600.')
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(config, dict) or config.get('format') != CONFIG_FORMAT:
        raise ValueError('Alert settings need "format": "' + CONFIG_FORMAT + '".')
    if set(config) - {'format', 'site_name', 'min_priority', 'alert_on_file_changes', 'email', 'webhook'}:
        raise ValueError('Alert settings contain an unknown field.')
    if not config.get('email') and not config.get('webhook'):
        raise ValueError('Alert settings need "email" or "webhook".')
    if config.get('min_priority', 'review') not in SEVERITIES:
        raise ValueError('min_priority must be one of: ' + ', '.join(SEVERITIES))
    email = config.get('email')
    if email:
        if not isinstance(email, dict) or set(email) - {'smtp_host', 'port', 'security', 'username', 'password', 'from', 'to'}:
            raise ValueError('Email settings contain an unknown field.')
        if not all(isinstance(email.get(key), str) and email[key] for key in ('smtp_host', 'from')) or not isinstance(email.get('to'), list) or not email['to']:
            raise ValueError('Email settings need smtp_host, from and a list of to addresses.')
        security = email.get('security', 'starttls')
        if security not in ('starttls', 'ssl', 'none') or (security == 'none' and email['smtp_host'] not in LOCAL_HOSTS):
            raise ValueError('Email security must be starttls or ssl. "none" is only allowed for localhost.')
    webhook = config.get('webhook')
    if webhook:
        if not isinstance(webhook, dict) or set(webhook) != {'url'}:
            raise ValueError('Webhook settings need only "url".')
        parsed = urllib.parse.urlsplit(webhook['url'])
        if not (parsed.scheme == 'https' or (parsed.scheme == 'http' and parsed.hostname in LOCAL_HOSTS)):
            raise ValueError('A webhook must use https.')
    return config

def send_email(settings, subject, body):
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = settings['from']
    message['To'] = ', '.join(settings['to'])
    message.set_content(body)
    security = settings.get('security', 'starttls')
    port = settings.get('port', {'starttls': 587, 'ssl': 465, 'none': 25}[security])
    context = ssl.create_default_context()
    if security == 'ssl':
        client = smtplib.SMTP_SSL(settings['smtp_host'], port, timeout=30, context=context)
    else:
        client = smtplib.SMTP(settings['smtp_host'], port, timeout=30)
    with client:
        if security == 'starttls':
            client.starttls(context=context)
        if settings.get('username'):
            client.login(settings['username'], settings.get('password', ''))
        client.send_message(message)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def send_webhook(settings, subject, body):
    # "text" suits Slack and most services, "content" suits Discord.
    text = subject + '\n\n' + body
    if len(text) > 1900:
        text = text[:1860] + '\n...cut short. See the report.'
    data =json.dumps({'text': text, 'content': text, 'subject': subject}).encode()
    request = urllib.request.Request(settings['url'], data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'wp-sentinel'}, method='POST')
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as response:
        if not 200 <= response.status < 300:
            raise AlertError('webhook answered with status ' + str(response.status))

def send(config, subject, body):
    """Try every channel. Returns a list of failures, naming the channel and error type only."""
    failures = []
    for name, sender in (('email', send_email), ('webhook', send_webhook)):
        if config.get(name):
            try:
                sender(config[name], subject, body)
            except urllib.error.HTTPError as error:
                failures.append(f'{name}: status {error.code}')
            except (OSError, smtplib.SMTPException, AlertError, ValueError, ssl.SSLError) as error:
                failures.append(f'{name}: {type(error).__name__}')
    return failures

def read_state(path):
    empty = {'format': STATE_FORMAT, 'findings': {}, 'gaps': [], 'failure_active': False, 'failure_alerted_utc': None}
    try:
        state = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return empty, None
    except (OSError, ValueError):
        # Re-alerting on everything is the safe result when the record is damaged.
        return empty, 'The record of earlier alerts could not be read, so existing findings are listed again.'
    if not isinstance(state, dict) or state.get('format') != STATE_FORMAT or not isinstance(state.get('findings'), dict):
        return empty, 'The record of earlier alerts could not be read, so existing findings are listed again.'
    return dict(empty, **state), None

def write_state(path, state):
    path = Path(path)
    pending = path.with_name(path.name + '.tmp')
    pending.write_text(json.dumps(state, indent=1), encoding='utf-8')
    os.replace(pending, path)

def alertable(finding, minimum):
    severity = finding.get('severity')
    if finding.get('rule') in ALWAYS_ALERT_RULES:
        return True
    return severity in SEVERITIES and SEVERITIES.index(severity) <= SEVERITIES.index(minimum)

def finding_id(finding):
    return json.dumps([str(finding.get(key, '')) for key in ('source', 'location', 'rule')])

def failed_checks(report):
    gaps = []
    for name, value in report.get('checks', {}).items():
        if isinstance(value, str) and value.startswith('FAILED'):
            gaps.append(f'{name}: {value}')
        elif isinstance(value, dict) and value.get('status') in ('partial', 'failed'):
            gaps.append(f'{name}: {value["status"]}')
        elif isinstance(value, list):
            gaps.extend(f'{name}: {entry.get("target", "")} failed' for entry in value if isinstance(entry, dict) and entry.get('status') == 'FAILED')
    return sorted(clean(gap) for gap in gaps)

def assess(report, state, config, file_counts=None):
    """Work out what is new since the last alert that was actually delivered."""
    minimum = config.get('min_priority', 'review')
    current, new, changed = {}, [], []
    for finding in report.get('findings', []):
        if not isinstance(finding, dict) or not alertable(finding, minimum):
            continue
        key = finding_id(finding)
        digest = str(finding.get('sha256', ''))
        if key in current:
            continue
        current[key] = digest
        if key not in state['findings']:
            new.append(finding)
        elif state['findings'][key] != digest:
            changed.append(finding)
    gaps = failed_checks(report)
    file_changes = {key: file_counts[key] for key in ('added', 'changed', 'missing') if file_counts and file_counts.get(key)}
    return {'current': current, 'new': new, 'changed': changed, 'gaps': gaps, 'new_gaps': [gap for gap in gaps if gap not in state.get('gaps', [])],
            'recovered': bool(state.get('failure_active')), 'file_changes': file_changes,
            'notify_files': bool(config.get('alert_on_file_changes') and file_changes)}

def should_send(result):
    return bool(result['new'] or result['changed'] or result['new_gaps'] or result['recovered'] or result['notify_files'])

def describe(site, result, location, note=None):
    site = clean(site, 80)
    order =lambda item: SEVERITIES.index(item['severity']) if item.get('severity') in SEVERITIES else len(SEVERITIES)
    parts = []
    if result['new']:
        parts.append(f'{len(result["new"])} new')
    if result['changed']:
        parts.append(f'{len(result["changed"])} changed')
    if parts:
        headline = ' and '.join(parts) + ' finding' + ('s' if len(result['new']) + len(result['changed']) != 1 else '')
    elif result['new_gaps']:
        headline = 'part of the check could not run'
    elif result['notify_files']:
        headline = 'files changed'
    else:
        headline = 'checks are working again'
    lines = [f'WP Sentinel: {headline} on {site}.', '']
    if note:
        lines += [note, '']
    if result['recovered']:
        lines += ['Scheduled checks are working again after an earlier failure.', '']
    for title, items in (('New', result['new']), ('Changed since the last alert', result['changed'])):
        if items:
            lines.append(title + ':')
            ranked = sorted(items, key=order)
            lines += [f'  [{clean(f.get("severity"), 10)}] {clean(f.get("location"))} ({clean(f.get("rule"), 60)})' for f in ranked[:MAX_LISTED]]
            if len(ranked) > MAX_LISTED:
                lines.append(f'  ...and {len(ranked) - MAX_LISTED} more in the report.')
            lines.append('')
    if result['new_gaps']:
        lines += ['Could not be checked this time:'] + ['  ' + gap for gap in result['new_gaps']] + ['']
    if result['file_changes']:
        lines += ['File changes since the previous run: ' + ', '.join(f'{v} {k}' for k, v in result['file_changes'].items()), '']
    lines += ['Report: ' + clean(location, 500), '', REMINDER]
    return f'[Sentinel] {site}: {headline}', '\n'.join(lines) + '\n'

def prepare_report(config, state_path, site, report, location, file_counts=None):
    """Work out one site's alert without sending it. Call commit() only once it has been delivered."""
    state, note = read_state(state_path)
    result = assess(report, state, config, file_counts)
    due = should_send(result)
    subject, body = describe(site, result, location, note) if due else (None, None)
    def commit():
        state.update(findings=result['current'], gaps=result['gaps'], failure_active=False, failure_alerted_utc=None)
        write_state(state_path, state)
    return {'due': due, 'subject': subject, 'body': body, 'commit': commit, 'new': len(result['new']), 'changed': len(result['changed'])}

def process_report(config, state_path, site, report, location, file_counts=None):
    """Send an alert if one is due. Returns failures; the record only moves on after delivery."""
    prepared = prepare_report(config, state_path, site, report, location, file_counts)
    failures = send(config, prepared['subject'], prepared['body']) if prepared['due'] else []
    if not failures:
        prepared['commit']()
    return {'sent': prepared['due'] and not failures, 'failures': failures, 'new': prepared['new'], 'changed': prepared['changed']}

def prepare_failure(state_path, site, reason):
    """Tell someone the checks stopped working: once, then at most daily while it lasts."""
    state, _ = read_state(state_path)
    last = state.get('failure_alerted_utc')
    if last and now() - datetime.fromisoformat(last) < FAILURE_REPEAT:
        return {'due': False, 'subject': None, 'body': None, 'commit': lambda: None}
    subject = f'[Sentinel] {clean(site, 80)}: scheduled check failed'
    body = f'The scheduled WP Sentinel check for {clean(site, 80)} did not finish, so nothing was checked.\n\nReason: {clean(reason, 400)}\n\nYou will not hear again for 24 hours while this continues. Next run will say when checks are working again.\n'
    def commit():
        state.update(failure_active=True, failure_alerted_utc=now().isoformat())
        write_state(state_path, state)
    return {'due': True, 'subject': subject, 'body': body, 'commit': commit}

def process_failure(config, state_path, site, reason):
    prepared = prepare_failure(state_path, site, reason)
    failures = send(config, prepared['subject'], prepared['body']) if prepared['due'] else []
    if prepared['due'] and not failures:
        prepared['commit']()
    return {'sent': prepared['due'] and not failures, 'failures': failures}

def send_digest(config, label, prepared, site_count, location):
    """One message for a whole account. Nothing is recorded as told unless every channel delivers it."""
    due = [item for item in prepared if item['due']]
    failures = []
    if due:
        sites = sum(not item.get('account') for item in due)
        headline = f'attention needed on {sites} of {site_count} sites' if sites else 'changes on the account'
        sections = [item['body'].replace(REMINDER, '').strip() for item in sorted(due, key=lambda item: not item.get('account'))]
        body = ('\n\n' + '-' * 40 + '\n\n').join(sections) + '\n\nAccount summary: ' + clean(location, 500) + '\n\n' + REMINDER + '\n'
        failures = send(config, f'[Sentinel] {clean(label, 80)}: {headline}', body)
    if not failures:
        for item in prepared:
            item['commit']()
    return {'sent': bool(due) and not failures, 'failures': failures, 'items': len(due)}

def send_test(config, site):
    return send(config, f'[Sentinel] {clean(site, 80)}: test alert', 'This is a test from WP Sentinel. Alerts from scheduled checks will arrive here.\n')

def remove_folder(path, parent):
    """Remove one report folder after checking it is a real folder directly inside parent."""
    path = Path(path)
    if path.parent != Path(parent) or path.is_symlink() or not path.is_dir():
        raise ValueError('Refusing to remove ' + path.name)
    shutil.rmtree(path)

def prune_hosted(private, keep, apply=False):
    """Keep the first and newest report folders of each kind. Stores and review notes are never touched."""
    if keep < 1:
        raise ValueError('--keep must be at least 1.')
    private = Path(private)
    kinds = {}
    for path in private.iterdir():
        match = HOSTED_FOLDER.fullmatch(path.name)
        if match and path.is_dir() and not path.is_symlink():
            kinds.setdefault(match.group(1), []).append(path)
    remove = []
    for folders in kinds.values():
        # Names end with a 24-character UTC stamp and random suffix.
        folders.sort(key=lambda p: p.name[-24:])
        remove += folders[1:-keep]
    if apply:
        for path in remove:
            remove_folder(path, private)
    return {'status': 'removed' if apply else 'preview', 'keep': keep, 'folders': sorted(p.name for p in remove)}
