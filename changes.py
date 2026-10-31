#!/usr/bin/env python3
"""Compare two saved scan snapshots; never infer resolution from absence."""
import argparse
import importlib.util
import json
import html
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('sentinel_management', Path(__file__).with_name('manage.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def compare(before, after, root, reviews):
    for report in (before, after):
        if report.get('site_root') != str(root):
            raise ValueError('Both reports must explicitly identify this site; legacy reports are not comparable here')
    if after['_time'] <= before['_time']:
        raise ValueError('After report must be newer than before report')
    def index(report):
        result = {}
        for f in report['findings']:
            key = m.finding_key(f)
            # One file can match a rule on several lines; those compare as one finding.
            if key in result:
                result[key]['occurrences'] = result[key].get('occurrences', 1) + 1
            else:
                result[key] = dict(f)
        return result
    old, new = index(before), index(after)
    groups = {k: [] for k in ('newly_observed', 'changed_content', 'same_content', 'content_comparison_unavailable', 'not_observed_in_after')}
    for key, f in new.items():
        previous = old.get(key)
        if previous is None:
            category = 'newly_observed'
        elif not m.reviewable(f) or not m.reviewable(previous):
            category = 'content_comparison_unavailable'
        elif f['sha256'].lower() == previous['sha256'].lower():
            category = 'same_content'
        else:
            category = 'changed_content'
        groups[category].append({'finding': f, 'previous_finding': previous,
                                 'review': m.review_status(f, reviews)})
    for key, f in old.items():
        if key not in new:
            groups['not_observed_in_after'].append({'finding': f,
                'note': 'Not observed in the selected later report. May be outside its scope, skipped, removed or no longer detected; not proof of resolution.'})
    return {'format': 'sentinel-changes-1', 'site_root': str(root), 'created_utc': m.now(),
            'note': 'Comparison of saved findings, not all site files or a fresh scan. Newly observed can reflect broader coverage. Same content does not imply benign. Missing findings are never automatically resolved.',
            'before': {'created_utc': before['created_utc'], 'checks': before['checks'], 'limitations': before.get('limitations', [])},
            'after': {'created_utc': after['created_utc'], 'checks': after['checks'], 'limitations': after.get('limitations', [])},
            'counts': {k: len(v) for k, v in groups.items()}, 'groups': groups}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('root','before','after','output'):
        p.add_argument('--'+key, required=True, type=Path)
    p.add_argument('--reviews', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    try:
        root = a.root.resolve()
        before = m.report_load(m.private_path(a.before,root),root)
        after = m.report_load(m.private_path(a.after,root),root)
        reviews = m.read_reviews(m.private_path(a.reviews,root),root) if a.reviews else []
        result = compare(before,after,root,reviews)
        result['before']['report'] = str(a.before)
        result['after']['report'] = str(a.after)
        out = m.private_path(a.output,root)
        out.mkdir(mode=0o700,parents=True,exist_ok=False)
        (out/'changes.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        page = '<!doctype html><meta charset="utf-8"><title>Sentinel changes</title><style>body{font:16px system-ui;max-width:1100px;margin:2em auto;padding:1em}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}</style><h1>Changes between scans</h1><p>'+html.escape(result['note'])+'</p>'
        for k,v in result['groups'].items():
            page += '<h2>'+html.escape(k.replace('_',' ').capitalize())+' ('+str(len(v))+')</h2><details><summary>Show findings</summary><pre>'+html.escape(json.dumps(v,indent=2))+'</pre></details>'
        for k in ('before','after'):
            page += '<h2>'+k.capitalize()+' coverage and limitations</h2><pre>'+html.escape(json.dumps(result[k],indent=2))+'</pre>'
        (out/'changes.html').write_text(page,encoding='utf-8')
        print(json.dumps({'status':'changes-created','output':str(out),'counts':result['counts']},indent=2))
        return 0
    except (OSError,ValueError,KeyError,TypeError) as e:
        print('Stopped: '+str(e))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
