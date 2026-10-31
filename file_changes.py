#!/usr/bin/env python3
"""Compare optional file inventories without accessing live website files."""
import argparse
import datetime
import html
import importlib.util
import json
import os
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('inventory_paths', Path(__file__).with_name('manage.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def validate(value, root):
    if value.get('format') != 'sentinel-file-inventory-1' or value.get('site_root') != str(root):
        raise ValueError('Inventory format or website root mismatch')
    if value.get('status') != 'finished' or type(value.get('traversal_complete')) is not bool:
        raise ValueError('Inventory is unfinished or lacks traversal status')
    for key in ('started_utc', 'finished_utc'):
        t = datetime.datetime.fromisoformat(value[key])
        if t.tzinfo is None:
            raise ValueError('Inventory times must include timezone')
    if datetime.datetime.fromisoformat(value['finished_utc']) < datetime.datetime.fromisoformat(value['started_utc']):
        raise ValueError('Inventory time interval is invalid')
    entries = value.get('entries')
    if not isinstance(entries, dict) or len(entries) > 2000000:
        raise ValueError('Invalid or oversized entry collection')
    for path, entry in entries.items():
        if not path or '\\' in path or path.startswith('/') or any(x in ('', '.', '..') for x in path.split('/')):
            raise ValueError('Invalid relative inventory path')
        if not isinstance(entry, dict) or entry.get('status') not in {'hashed','directory','symlink-directory','symlink','nonregular','excluded-configuration','oversized','changed-during-read','unreadable-or-changed'}:
            raise ValueError('Invalid entry status')
        if entry['status'] == 'hashed':
            if not re.fullmatch('[a-f0-9]{64}', str(entry.get('sha256', ''))) or type(entry.get('bytes')) is not int or entry['bytes'] < 0:
                raise ValueError('Invalid file digest or size')
    return value

def read(path, root):
    path = m.private_path(path, root)
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('Inventory exceeds 256 MiB')
    return validate(json.loads(path.read_text(encoding='utf-8-sig')), root)

def inspected(inventory, path):
    """Whether this inventory would have seen path. Older inventories only say all-or-nothing."""
    gaps = inventory.get('uninspected_directories')
    if not isinstance(gaps, list) or inventory.get('file_limit_reached') is not False or inventory.get('traversal_scope_known') is not True:
        return inventory['traversal_complete']
    return not any(path == gap or path.startswith(gap + '/') for gap in gaps)

def compare(before, after, root):
    validate(before, root); validate(after, root)
    if datetime.datetime.fromisoformat(after['started_utc']) < datetime.datetime.fromisoformat(before['finished_utc']):
        raise ValueError('Inventories overlap or are reversed; use two sequential scans')
    groups = {k: [] for k in ('added','changed','missing','unchanged','directories_added','directories_missing','unknown')}
    old, new = before['entries'], after['entries']
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path), new.get(path)
        ah, bh = bool(a and a['status'] == 'hashed'), bool(b and b['status'] == 'hashed')
        if a and b and a['status'] == b['status'] == 'directory':
            continue
        reason = ''
        if ah and bh:
            category = 'unchanged' if (a['sha256'], a['bytes']) == (b['sha256'], b['bytes']) else 'changed'
        elif a is None and bh and inspected(before, path):
            category = 'added'
        elif ah and b is None and inspected(after, path):
            category = 'missing'
        elif a is None and b and b['status'] == 'directory' and inspected(before, path):
            category = 'directories_added'
            reason = 'Newly observed directory; directory contents are compared as separate entries.'
        elif a and a['status'] == 'directory' and b is None and inspected(after, path):
            category = 'directories_missing'
            reason = 'Previously observed directory absent from the later completed traversal.'
        else:
            category = 'unknown'
            reason = 'Skipped, excluded, changed type, or absent from an incomplete traversal; content comparison unavailable.'
        groups[category].append(dict(path=path, before=a, after=b, reason=reason))
    coverage = lambda v: {k: v.get(k) for k in ('started_utc','finished_utc','traversal_complete','uninspected_directories','file_limit_reached','max_bytes','max_files','skipped_counts','limitations')}
    return dict(format='sentinel-file-changes-1', site_root=str(root), created_utc=m.now(),
                note='Read-only comparison of saved file observations, not a clean baseline or malware verdict. Added/missing reflect directory observations during sequential live scans, not atomic snapshots. Added and missing require that the relevant scan could see that path; skipped directories only affect paths inside them. No files are modified. Reviews of findings are not applied to this inventory.',
                before=coverage(before), after=coverage(after), counts={k:len(v) for k,v in groups.items()}, groups=groups)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root','before','after','output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); os.umask(0o077)
    try:
        root = a.root.resolve()
        result = compare(read(a.before,root),read(a.after,root),root)
        result['before']['inventory'] = str(a.before)
        result['after']['inventory'] = str(a.after)
        out = m.private_path(a.output,root); out.mkdir(mode=0o700,parents=True,exist_ok=False)
        (out/'file-changes.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        page = '<!doctype html><meta charset="utf-8"><title>Sentinel file changes</title><style>body{font:16px system-ui;max-width:1100px;margin:2em auto;padding:1em}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>File changes</h1><p>'+html.escape(result['note'])+'</p>'
        for name in ('added','changed','missing','directories_added','directories_missing','unknown','unchanged'):
            page += '<h2>'+name.replace('_', ' ').capitalize()+' ('+str(result['counts'][name])+')</h2><details><summary>Show entries</summary><pre>'+html.escape(json.dumps(result['groups'][name],indent=2))+'</pre></details>'
        for name in ('before','after'):
            page += '<h2>'+name.capitalize()+' coverage</h2><pre>'+html.escape(json.dumps(result[name],indent=2))+'</pre>'
        (out/'file-changes.html').write_text(page,encoding='utf-8')
        print(json.dumps(dict(status='file-changes-created',output=str(out),counts=result['counts']),indent=2)); return 0
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as error:
        print('Stopped: '+str(error)); return 2

if __name__ == '__main__':
    raise SystemExit(main())
