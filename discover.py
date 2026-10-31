#!/usr/bin/env python3
"""List the WordPress installs under the given folders, as JSON. Reads only; never runs site code.

An install is a folder holding wp-settings.php and wp-includes/version.php. Usage:
python3 -I -S discover.py [FOLDER ...]    (default: your home folder)
"""
import json
import os
import re
import sys

# Not website content, and often huge or unreadable.
SKIP_NAMES = {'.cache', '.cagefs', '.composer', '.git', '.npm', '.trash', 'mail', 'node_modules'}
# Core folders of an install cannot hold another install worth finding.
SKIP_IN_INSTALL = {'wp-admin', 'wp-includes'}
MAX_DIRECTORIES = 500000
MAX_DEPTH = 15
MAX_LISTED = 200

def wp_version(path):
    try:
        with open(os.path.join(path, 'wp-includes', 'version.php'), 'rb') as stream:
            found = re.search(rb"\$wp_version\s*=\s*['\"]([0-9A-Za-z.+-]{1,40})['\"]", stream.read(65536))
    except OSError:
        return None
    return found.group(1).decode('ascii') if found else None

def is_install(path):
    return os.path.isfile(os.path.join(path, 'wp-settings.php')) and os.path.isfile(os.path.join(path, 'wp-includes', 'version.php'))

def discover(starts):
    result = {'format': 'sentinel-discovery-1', 'starts': [], 'installs': [], 'config_without_core': [], 'unreadable': [],
              'symlinks_skipped': 0, 'directories_visited': 0, 'truncated': False}
    pending, seen = [], set()
    for start in starts:
        path = os.path.realpath(os.path.expanduser(start))
        result['starts'].append(path.replace(os.sep, '/'))
        if os.path.isdir(path):
            pending.append((path, 0))
        else:
            result['unreadable'].append(path.replace(os.sep, '/'))
    while pending:
        path, depth = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        result['directories_visited'] += 1
        if result['directories_visited'] > MAX_DIRECTORIES:
            result['truncated'] = True
            break
        shown = path.replace(os.sep, '/')
        install = is_install(path)
        if install:
            result['installs'].append({'path': shown, 'version': wp_version(path), 'has_config': os.path.isfile(os.path.join(path, 'wp-config.php')),
                                       'inside_wp_content': 'wp-content' in shown.split('/')})
        elif os.path.isfile(os.path.join(path, 'wp-config.php')) and len(result['config_without_core']) < MAX_LISTED:
            result['config_without_core'].append(shown)
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.name in SKIP_NAMES or entry.name.startswith('.sentinel-run-') or (install and entry.name in SKIP_IN_INSTALL):
                        continue
                    if entry.is_symlink():
                        result['symlinks_skipped'] += 1
                    elif entry.is_dir(follow_symlinks=False):
                        if depth >= MAX_DEPTH:
                            result['truncated'] = True
                        else:
                            pending.append((entry.path, depth + 1))
        except OSError:
            if len(result['unreadable']) < MAX_LISTED:
                result['unreadable'].append(shown)
    result['installs'].sort(key=lambda item: item['path'])
    result['config_without_core'].sort()
    result['unreadable'].sort()
    return result

if __name__ == '__main__':
    print(json.dumps(discover(sys.argv[1:] or ['~'])))
