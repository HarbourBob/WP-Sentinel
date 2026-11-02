#!/usr/bin/env python3
"""Post-incident checklist built from a scan report, and optionally its vulnerability check and timeline. Offline."""
import argparse
import datetime
import functools
import html
import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('checklist_vulns', Path(__file__).with_name('vulns.py'))
vulns_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vulns_module)

SECTIONS = ('Before you change anything', 'Close the way in', 'Remove what was found', 'Rotate salts and passwords', 'End sessions', 'Clear caches',
            'Watch for reinfection', 'Afterwards')
CACHE_PLUGINS = {'wp-rocket': 'WP Rocket', 'w3-total-cache': 'W3 Total Cache', 'wp-super-cache': 'WP Super Cache', 'litespeed-cache': 'LiteSpeed Cache',
                 'sg-cachepress': 'SiteGround Speed Optimizer', 'wp-fastest-cache': 'WP Fastest Cache', 'autoptimize': 'Autoptimize',
                 'breeze': 'Breeze', 'cache-enabler': 'Cache Enabler', 'hummingbird-performance': 'Hummingbird', 'swift-performance-lite': 'Swift Performance',
                 'nitropack': 'NitroPack', 'redis-cache': 'Redis Object Cache', 'mbr-performance': 'MBR Performance', 'elementor': 'Elementor (CSS files)'}

def build(report, vulns=None, timeline=None, scan_command=None, monitor_command=None):
    items = []
    def add(section, key, title, detail=(), commands=(), status=None):
        items.append(dict(id=key, section=section, title=title, detail=list(detail), commands=list(commands), status=status))
    checks = report.get('checks', {})
    software = report.get('software') or {}
    plugins = {p['slug']: p.get('version') for p in software.get('plugins', [])}
    themes = [t['slug'] for t in software.get('themes', [])]
    findings = report.get('findings', [])
    serious = [f for f in findings if f.get('severity') in ('high', 'medium')]
    not_run = lambda name: not checks.get(name) or checks.get(name) == 'not requested' or str(checks.get(name)).startswith('FAILED')
    persistence = checks.get('persistence') if isinstance(checks.get('persistence'), dict) else {}
    startup = {f.get('path') for f in persistence.get('files', []) if isinstance(f, dict)}

    s = SECTIONS[0]
    add(s, 'backup', 'Take a full backup of the files and the database, and keep it off the server.',
        ['It is your way back if a fix breaks the site, and a copy of the infected state for later questions. Label it as infected.'])
    add(s, 'evidence', 'Keep this evidence folder unchanged.', ['sentinel-remote.py verify confirms nothing in it has changed.'])

    s = SECTIONS[1]
    if vulns is None:
        add(s, 'vuln-check', 'Check installed versions against the vulnerability feed.', ['Removing malware without closing the entry point usually means reinfection. See VULNERABILITIES.txt.'],
            status='not checked yet')
    else:
        grouped = {}
        for v in vulns.get('vulnerabilities', []):
            grouped.setdefault((v['type'], v['slug'], v['installed_version']), []).append(v)
        for (kind, slug, version), found in grouped.items():
            # The newest of the per-vulnerability fixes closes all of them.
            fixes = sorted({f for v in found for f in v.get('fixed_in', [])}, key=functools.cmp_to_key(vulns_module.compare_versions))
            worst = next((v['rating'] for v in found if v['rating']), 'unrated')
            action = ('Update ' if fixes else 'Remove or replace ') + f'{kind} {slug} {version}' + (' to ' + fixes[-1] + ' or newer.' if fixes else ': no fixed version is known.')
            add(s, f'vuln-{kind}-{slug}', action, [f'{len(found)} known vulnerabilities, worst {worst}: ' + '; '.join(v['title'] for v in found[:3]) + ('; …' if len(found) > 3 else '')],
                status='found by the vulnerability check')
        if not grouped:
            add(s, 'vuln-none', 'No installed version matched a known vulnerability.', ['Still update everything below: the feed only covers what has been disclosed.'],
                status='checked ' + str(vulns.get('feed_downloaded_utc', ''))[:10])
    add(s, 'update', 'Update WordPress core, every plugin and every theme.', [f'{len(plugins)} plugins and {len(themes)} themes are installed.' if software else ''])
    add(s, 'unused', 'Delete plugins and themes you do not use, including inactive ones.', ['Inactive code can still be reached and attacked. Keep one default theme.'] + (
        ['Themes installed: ' + ', '.join(themes)] if len(themes) > 2 else []))
    add(s, 'users', 'Check every administrator account, and delete any you do not recognise.', ['Look in Users, filtered by Administrator. Attackers often add one with an ordinary-looking name.'],
        status='not checked by this scan: add --database' if not_run('database') else 'see the database results in the report')
    add(s, 'leftovers', 'Remove backups, installers, old copies and logs from the website folder.', ['Files such as *.zip, *.sql, *.bak, old-* folders and error logs can be downloaded by anyone.'])

    s = SECTIONS[2]
    if serious:
        add(s, 'findings', f'Deal with the {len(serious)} high and medium findings in report.html.', [f.get('location', '') + ' — ' + f.get('rule', '') for f in serious[:8]] + (['…'] if len(serious) > 8 else []) + [
            'Quarantine, batch quarantine and clean replacement all preview first. See QUARANTINE.txt and CLEAN-REPLACEMENT.txt.'], status='found in this scan')
    else:
        add(s, 'findings', 'Review the findings in report.html.', ['No high or medium findings in this scan. That is not proof the site is clean.'])
    add(s, 'startup', 'Check must-use plugins, drop-ins, .htaccess, .user.ini and php.ini.', ['These load on every request and are a favourite hiding place.'] + (
        ['Present: ' + ', '.join(sorted(startup)[:12])] if startup else []), status='not checked by this scan: add --persistence' if not_run('persistence') else 'listed by this scan')
    cron = persistence.get('account_crontab') if isinstance(persistence.get('account_crontab'), dict) else {}
    add(s, 'cron', 'Check scheduled tasks: WordPress cron hooks and the account crontab.', ['Reinfection often comes back on a timer. Panel-managed jobs are only visible in the hosting panel.'],
        status='account crontab not checked: add --account-cron' if cron.get('status') in (None, 'not requested') else 'account crontab: ' + str(cron['status']))
    add(s, 'content', 'Check posts, pages, widgets and options for injected scripts or links.', [],
        status='not checked by this scan: add --database' if not_run('database') else 'see the database results in the report')

    s = SECTIONS[3]
    add(s, 'salts', 'Replace the eight keys and salts in wp-config.php with new ones.', ['Get a fresh set from https://api.wordpress.org/secret-key/1.1/salt/ and replace the AUTH_KEY … NONCE_SALT lines.',
        'This also logs everyone out, which ends the attacker\'s sessions.'])
    add(s, 'wp-passwords', 'Change the password of every administrator and editor.', ['Use new, unique passwords, and turn on two-factor sign-in.'])
    add(s, 'db-password', 'Change the database password, then update DB_PASSWORD in wp-config.php.', ['wp-config.php was readable to anything that ran on the site.'])
    add(s, 'hosting', 'Change the hosting panel, SFTP and FTP passwords, and remove SSH keys you do not recognise.', ['Check ~/.ssh/authorized_keys and the panel\'s SSH key list.'])
    add(s, 'api-keys', 'Replace API keys and application passwords that the site stores.', ['Users → Profile → Application Passwords, and keys for email (SMTP), payments, CDN and analytics in plugin settings.'] + (
        ['Google Site Kit is installed: disconnect and reconnect it.'] if 'google-site-kit' in plugins else []))
    add(s, 'email', 'Change the password of the email account behind each administrator.', ['Whoever controls that mailbox can reset the site password.'])

    s = SECTIONS[4]
    add(s, 'sessions', 'Make sure everyone is signed out.', ['Changing the salts does this. With WP-CLI you can also run it directly:'], commands=['wp user session destroy --all'])
    add(s, 'app-passwords', 'Revoke application passwords you did not create.', ['They keep working after a password change.'])
    add(s, 'connections', 'Review connected services and remove ones you do not recognise.', ['For example Jetpack, Google, payment and email integrations.'])

    s = SECTIONS[5]
    caches = [name for slug, name in CACHE_PLUGINS.items() if slug in plugins]
    add(s, 'plugin-cache', 'Purge every plugin cache.', (['Installed: ' + ', '.join(caches)] if caches else ['Look for a cache option in each performance plugin.']) + (
        ['advanced-cache.php is present: a page cache is active.'] if 'wp-content/advanced-cache.php' in startup else []))
    add(s, 'object-cache', 'Flush the object cache.', ['object-cache.php is present.'] if 'wp-content/object-cache.php' in startup else ['Redis or Memcached, if your host or a plugin uses one.'])
    add(s, 'host-cache', 'Flush your host\'s cache.', ['For example SiteGround Dynamic Cache and Memcached, in Site Tools → Speed.'])
    add(s, 'cdn', 'Purge the CDN cache, such as Cloudflare.', ['Otherwise infected pages can be served after the fix.'])
    add(s, 'check-live', 'Check the live site in a private window and on a phone.', ['Some infections only show to visitors arriving from search engines or on mobile.'])

    s = SECTIONS[6]
    add(s, 'rescan', 'Scan again within 24 hours, then again after a week, and compare.', ['Look at file changes and the timeline for files you did not change.'],
        commands=[scan_command] if scan_command else [])
    add(s, 'monitor', 'Set up a daily scan with alerts.', ['Alerts fire only on new or changed findings and failed runs. See MONITORING.txt.'], commands=[monitor_command] if monitor_command else [])
    if timeline is not None:
        bulk = timeline.get('bulk_status_changes', [])
        add(s, 'timeline', 'Check the timeline for flagged files and bulk changes you cannot explain.',
            [f'{len(timeline.get("flagged", []))} flagged entries and {len(bulk)} bulk changes in this run.'], status='from timeline.html')
    add(s, 'vuln-recheck', 'Re-check vulnerabilities every week.', ['New vulnerabilities are published daily. The feed is cached for 24 hours.'])
    add(s, 'blocklists', 'Check Google Search Console → Security issues, and request a review if the site is flagged.', ['Also check your email still delivers: spam blocklists follow infections.'])
    add(s, 'logs', 'Watch the access logs for requests to removed files.', ['Repeated requests to a file you deleted show the attacker is still trying, and from where.'])

    s = SECTIONS[7]
    add(s, 'record', 'Write down what happened, when, and what you changed.', ['Keep it with the evidence folder.'])
    add(s, 'notify', 'Decide whether you must report the breach.', ['If personal data may have been taken, you may have to report it. In the UK that is to the ICO within 72 hours of becoming aware.'])
    for item in items:
        item['detail'] = [d for d in item['detail'] if d]
    return dict(format='sentinel-checklist-1', site_root=report.get('site_root'), report_created_utc=report.get('created_utc'),
                created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), sections=list(SECTIONS), items=items,
                note='A starting point, not a complete incident response. Items marked with a status were tailored from this scan. Ticks are kept in this browser only.')

def render(result):
    e = lambda v: html.escape('' if v is None else str(v))
    # Escaped so a path holding </script> cannot end the script early.
    storage = json.dumps('sentinel-checklist:' + str(result.get('site_root')) + ':' + str(result.get('report_created_utc'))).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    page = ['<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Post-incident checklist</title>'
            '<style>body{font:15px system-ui;max-width:900px;margin:2em auto;padding:0 1em;line-height:1.45}li{list-style:none;margin:.6em 0}label{font-weight:600}'
            'ul{padding-left:0}.d{margin:.2em 0 0 1.8em;color:#444}.s{font-size:12px;background:#eef;border-radius:4px;padding:1px 6px;margin-left:6px;font-weight:400}'
            'code{background:#f3f3f3;padding:2px 4px;overflow-wrap:anywhere}input:checked+label{text-decoration:line-through;color:#777}#p{font-weight:600}</style>',
            '<h1>Post-incident checklist</h1><p>' + e(result['site_root']) + '<br>From the scan of ' + e(result['report_created_utc']) + '</p><p>' + e(result['note'])
            + '</p><p id="p"></p>']
    for section in result['sections']:
        rows = [i for i in result['items'] if i['section'] == section]
        page.append('<h2>' + e(section) + '</h2><ul>')
        for i in rows:
            page.append('<li><input type="checkbox" id="' + e(i['id']) + '"><label for="' + e(i['id']) + '">' + e(i['title']) + '</label>'
                        + ('<span class="s">' + e(i['status']) + '</span>' if i['status'] else '')
                        + ''.join('<div class="d">' + e(d) + '</div>' for d in i['detail'])
                        + ''.join('<div class="d"><code>' + e(c) + '</code></div>' for c in i['commands']) + '</li>')
        page.append('</ul>')
    page.append('<script>(function(){var k=' + storage + ',s={};try{s=JSON.parse(localStorage.getItem(k)||"{}")}catch(x){}'
                'var b=document.querySelectorAll("input[type=checkbox]");function p(){var n=0;b.forEach(function(c){if(c.checked)n++});'
                'document.getElementById("p").textContent=n+" of "+b.length+" done"}'
                'b.forEach(function(c){c.checked=!!s[c.id];c.addEventListener("change",function(){s[c.id]=c.checked;try{localStorage.setItem(k,JSON.stringify(s))}catch(x){}p()})});p()})()</script>')
    return ''.join(page)

def write(result, folder):
    (folder / 'checklist.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (folder / 'checklist.html').write_text(render(result), encoding='utf-8')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--vulns', type=Path, help='vulnerabilities.json from the vulnerability check')
    p.add_argument('--timeline', type=Path, help='timeline.json')
    p.add_argument('--scan-command', help='Command to show for scanning again')
    p.add_argument('--monitor-command', help='Command to show for daily scans')
    a = p.parse_args(); os.umask(0o077)
    try:
        load = lambda path: json.loads(path.read_text(encoding='utf-8')) if path else None
        result = build(load(a.report), load(a.vulns), load(a.timeline), a.scan_command, a.monitor_command)
        a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        write(result, a.output)
        print(json.dumps(dict(status='checklist-created', output=str(a.output), items=len(result['items'])), indent=2)); return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Stopped: ' + str(error)); return 2

if __name__ == '__main__':
    raise SystemExit(main())
