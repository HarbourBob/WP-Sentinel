#!/usr/bin/env python3
"""Build a file timeline, with permissions and owners, from one saved file inventory. Offline: the website is not read."""
import argparse
import bisect
import collections
import datetime
import html
import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('timeline_file_changes', Path(__file__).with_name('file_changes.py'))
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)

NOTE = ('Times come from the filesystem and are in UTC. Modified is when the content was last written; status changed (POSIX ctime) also moves '
        'on a chmod, chown or rename, and cannot be set back by ordinary tools. Anyone able to write a file can set its modified time, so '
        'a quiet timeline is not proof that nothing changed. Flags are prompts for review, not findings.')
FLAGS = {
    'world-writable': 'Any account on the server can change this.',
    'setuid-or-setgid': 'Runs with its owner\'s or group\'s rights. Rare and unexpected in a website.',
    'other-owner': 'Owned by a different account from most of the site, such as the web server writing files itself.',
    'ctime-after-mtime': 'Status changed more than a day after the content was dated, on its own rather than as part of a bulk change listed below. Often a chmod; it is also what setting a file\'s date back looks like.',
    'future-dated': 'Modified time is after the scan. The date was set by hand, or a clock is wrong.',
}
# More entries than this changing status within the window of each other are a bulk event, such as an update.
BULK = 20
BULK_WINDOW = datetime.timedelta(seconds=60)
# timeline.json keeps the newest entries; file-inventory.json still has every one.
MAX_ENTRIES = 5000

def parse_time(value):
    if not value:
        return None
    try:
        t = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)

def build(inventory, since=None):
    entries = inventory['entries']
    owners = collections.Counter(e['uid'] for e in entries.values() if type(e.get('uid')) is int)
    main_uid = owners.most_common(1)[0][0] if owners else None
    names = inventory.get('owner_names') if isinstance(inventory.get('owner_names'), dict) else {}
    finished = parse_time(inventory.get('finished_utc'))
    modified_days, changed_days = collections.Counter(), collections.Counter()
    rows, flagged = [], []
    for path, entry in entries.items():
        mtime, ctime = parse_time(entry.get('mtime_utc')), parse_time(entry.get('ctime_utc'))
        if mtime is None and ctime is None:
            continue
        if mtime:
            modified_days[mtime.date().isoformat()] += 1
        if ctime:
            changed_days[ctime.date().isoformat()] += 1
        mode = int(entry['mode'], 8) if 'mode' in entry else None
        flags = []
        if mode is not None and mode & 0o002:
            flags.append('world-writable')
        if mode is not None and mode & 0o6000:
            flags.append('setuid-or-setgid')
        if main_uid is not None and entry.get('uid', main_uid) != main_uid:
            flags.append('other-owner')
        if mtime and ctime and ctime - mtime > datetime.timedelta(days=1):
            flags.append('ctime-after-mtime')
        if mtime and finished and mtime > finished + datetime.timedelta(days=1):
            flags.append('future-dated')
        latest = max(t for t in (mtime, ctime) if t)
        row = dict(path=path, status=entry['status'], latest_utc=latest.isoformat(), mtime_utc=entry.get('mtime_utc'), ctime_utc=entry.get('ctime_utc'),
                   mode=entry.get('mode'), uid=entry.get('uid'), owner=names.get(str(entry.get('uid'))), bytes=entry.get('bytes'), flags=flags)
        if since is None or latest >= since:
            rows.append(row)
        if flags:
            flagged.append(row)
    # Updates, restores and migrations touch thousands of files within a minute. Only files changed
    # on their own are flagged; the bulk events are listed once each as part of the timeline.
    later = sorted(((parse_time(r['ctime_utc']), r) for r in flagged if 'ctime-after-mtime' in r['flags']), key=lambda pair: (pair[0], pair[1]['path']))
    times = [t for t, _ in later]
    bulk = []
    for t, r in later:
        if bisect.bisect_right(times, t + BULK_WINDOW) - bisect.bisect_left(times, t - BULK_WINDOW) <= BULK:
            continue
        r['flags'].remove('ctime-after-mtime')
        if bulk and t - parse_time(bulk[-1]['end_utc']) <= BULK_WINDOW:
            bulk[-1].update(end_utc=r['ctime_utc'], entries=bulk[-1]['entries'] + 1, example=min(bulk[-1]['example'], r['path']))
        else:
            bulk.append(dict(start_utc=r['ctime_utc'], end_utc=r['ctime_utc'], entries=1, example=r['path']))
    flagged = [r for r in flagged if r['flags']]
    rows.sort(key=lambda r: (r['latest_utc'], r['path']), reverse=True)
    flagged.sort(key=lambda r: (r['latest_utc'], r['path']), reverse=True)
    bulk.sort(key=lambda b: b['start_utc'], reverse=True)
    days = sorted(set(modified_days) | set(changed_days), reverse=True)
    limitations = [] if 'metadata_fields' in inventory else ['This inventory was made before permissions and dates were recorded. Run a new scan to build a timeline.']
    if 'ctime_utc' not in inventory.get('metadata_fields', ['ctime_utc']):
        limitations.append('Scanned on a system without POSIX permissions, owners or status-change times; only modified times are available.')
    return dict(format='sentinel-timeline-1', site_root=inventory['site_root'], created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                inventory_started_utc=inventory.get('started_utc'), inventory_finished_utc=inventory.get('finished_utc'),
                since_utc=since.isoformat() if since else None, note=NOTE, flag_meanings=FLAGS, limitations=limitations,
                main_owner=dict(uid=main_uid, name=names.get(str(main_uid))) if main_uid is not None else None,
                owner_counts={str(uid): dict(entries=count, name=names.get(str(uid))) for uid, count in owners.most_common()},
                flag_counts=dict(collections.Counter(f for r in flagged for f in r['flags'])), bulk_status_changes=bulk,
                by_day=[dict(day=d, modified=modified_days[d], status_changed=changed_days[d]) for d in days],
                flagged=flagged, entries_total=len(rows), entries=rows[:MAX_ENTRIES])

def render(result, limit=500):
    e = lambda v: html.escape('' if v is None else str(v))
    def table(rows, total=None):
        total = len(rows) if total is None else total
        out = ['<table><tr><th>Latest</th><th>Path</th><th>Modified</th><th>Status changed</th><th>Mode</th><th>Owner</th><th>Flags</th></tr>']
        for r in rows[:limit]:
            owner = r['owner'] or r['uid']
            out.append('<tr><td>' + e(r['latest_utc'][:19].replace('T', ' ')) + '</td><td class="p">' + e(r['path']) + ('/' if r['status'] == 'directory' else '')
                       + '</td><td>' + e((r['mtime_utc'] or '')[:19].replace('T', ' ')) + '</td><td>' + e((r['ctime_utc'] or '')[:19].replace('T', ' '))
                       + '</td><td>' + e(r['mode']) + '</td><td>' + e(owner) + '</td><td>' + e(', '.join(r['flags'])) + '</td></tr>')
        out.append('</table>')
        if total > min(limit, len(rows)):
            out.append('<p>Showing ' + str(min(limit, len(rows))) + ' of ' + str(total) + '. file-inventory.json has every entry.</p>')
        return ''.join(out)
    peak = max([d['modified'] for d in result['by_day']] + [1])
    page = ['<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel timeline</title>'
            '<style>body{font:15px system-ui;max-width:1200px;margin:2em auto;padding:0 1em}table{border-collapse:collapse;width:100%;font-size:13px}'
            'td,th{border-bottom:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top;white-space:nowrap}td.p{white-space:normal;overflow-wrap:anywhere}'
            '.bar{background:#4a7bd0;height:10px}.scroll{overflow-x:auto}</style>',
            '<h1>File timeline</h1><p>' + e(result['site_root']) + '<br>Inventory taken ' + e(result['inventory_started_utc']) + '</p><p>' + e(result['note']) + '</p>']
    for item in result['limitations']:
        page.append('<p><strong>' + e(item) + '</strong></p>')
    owners = ', '.join(e(v['name'] or uid) + ': ' + e(v['entries']) for uid, v in result['owner_counts'].items())
    page.append('<h2>Summary</h2><p>Entries with dates: ' + e(sum(d['modified'] for d in result['by_day'])) + (' (listed since ' + e(result['since_utc']) + ': ' + e(result['entries_total']) + ')' if result['since_utc'] else '')
                + '<br>Owners: ' + (owners or 'not recorded') + '</p><ul>')
    for flag, meaning in result['flag_meanings'].items():
        page.append('<li><strong>' + e(flag) + '</strong> (' + e(result['flag_counts'].get(flag, 0)) + '): ' + e(meaning) + '</li>')
    page.append('</ul><h2>Flagged (' + e(len(result['flagged'])) + ')</h2><div class="scroll">' + table(result['flagged']) + '</div>')
    page.append('<h2>Bulk changes (' + e(len(result['bulk_status_changes'])) + ')</h2><p>Times when more than ' + e(BULK) + ' older files had their status changed within a minute '
                'of each other, such as an update, restore, migration or bulk chmod. Check each one matches something you or your host did.</p><div class="scroll"><table>'
                '<tr><th>From</th><th>To</th><th>Entries</th><th>Example</th></tr>')
    for b in result['bulk_status_changes'][:limit]:
        page.append('<tr><td>' + e(b['start_utc'][:19].replace('T', ' ')) + '</td><td>' + e(b['end_utc'][:19].replace('T', ' ')) + '</td><td>' + e(b['entries'])
                    + '</td><td class="p">' + e(b['example']) + '</td></tr>')
    page.append('</table></div>')
    page.append('<h2>Activity by day</h2><p>Files whose content was last written each day, newest first. A burst on one day stands out here.</p><details open><summary>'
                + e(len(result['by_day'])) + ' days</summary><div class="scroll"><table><tr><th>Day</th><th>Modified</th><th>Status changed</th><th></th></tr>')
    for d in result['by_day'][:limit]:
        page.append('<tr><td>' + e(d['day']) + '</td><td>' + e(d['modified']) + '</td><td>' + e(d['status_changed']) + '</td><td style="width:40%"><div class="bar" style="width:'
                    + str(round(100 * d['modified'] / peak, 1)) + '%"></div></td></tr>')
    page.append('</table></div></details><h2>Most recent</h2><div class="scroll">' + table(result['entries'], result['entries_total']) + '</div>')
    return ''.join(page)

def write(result, folder, limit=500):
    (folder / 'timeline.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (folder / 'timeline.html').write_text(render(result, limit), encoding='utf-8')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'inventory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--since', help='List only entries modified or changed on or after this UTC date, such as 2026-10-01')
    p.add_argument('--limit', type=int, default=500, help='Rows per table in the HTML page; the JSON has every row')
    a = p.parse_args(); os.umask(0o077)
    try:
        root = a.root.resolve()
        since = parse_time(a.since) if a.since else None
        if a.since and since is None:
            raise ValueError('--since must be a date such as 2026-10-01')
        if a.limit < 1:
            raise ValueError('--limit must be at least 1')
        result = build(fc.read(a.inventory, root), since)
        result['inventory'] = str(a.inventory)
        out = fc.m.private_path(a.output, root); out.mkdir(mode=0o700, parents=True, exist_ok=False)
        write(result, out, a.limit)
        print(json.dumps(dict(status='timeline-created', output=str(out), entries=result['entries_total'], flag_counts=result['flag_counts'], limitations=result['limitations']), indent=2)); return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print('Stopped: ' + str(error)); return 2

if __name__ == '__main__':
    raise SystemExit(main())
