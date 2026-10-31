#!/usr/bin/env python3
"""Explicit, reversible file quarantine for an offline/paused WordPress site.

This is not a security boundary against another process running as this account.
Preview is the default. No automatic malware decisions are made.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from contextlib import contextmanager

MAX_BYTES = 50 * 1024 * 1024

def no_links(path):
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError('Symlink paths are not supported.')
    return path

def setup(root, store):
    root, store = no_links(root), no_links(store)
    if not root.is_dir() or not (root / 'wp-includes').is_dir():
        raise ValueError('Root must identify a WordPress installation.')
    if store == root or root in store.parents or store in root.parents:
        raise ValueError('Store must be separate from and outside the website root.')
    return root, store

def target_path(root, relative):
    if not isinstance(relative, str) or '\\' in relative or ':' in relative or relative.startswith('/'):
        raise ValueError('Use a forward-slash relative file path inside the website.')
    if any(part in {'', '.', '..'} for part in relative.split('/')):
        raise ValueError('Invalid relative path.')
    return no_links(root.joinpath(*relative.split('/')))

def read_regular(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise ValueError('Only regular files up to 50 MiB are supported.')
        if before.st_nlink != 1:
            raise ValueError('Hard-linked files are not supported.')
        data = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(data) > MAX_BYTES or fingerprint(before) != fingerprint(after):
        raise ValueError('File changed while being read, or exceeded the size limit.')
    return data, before

def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_exclusive(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(path, flags, mode), 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def record_write(folder, record):
    pending = folder / ('record-' + uuid.uuid4().hex + '.tmp')
    write_exclusive(pending, json.dumps(record, indent=2).encode())
    os.replace(pending, folder / 'record.json')

@contextmanager
def store_lock(store):
    no_links(store)
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'posix' and (store.stat().st_mode & 0o077):
        raise ValueError('Existing store must have private permissions (chmod 700).')
    lock = store / '.operation-lock'
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError('Store is locked. ' + lock_description(lock) + ' Investigate before removing a stale .operation-lock directory.')
    details = lock / 'owner.json'
    try:
        write_exclusive(details, json.dumps({'pid': os.getpid(), 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}).encode())
        yield
    finally:
        if details.exists():
            details.unlink()
        lock.rmdir()

def lock_description(lock):
    """Say what is known about a lock. Reporting only; a lock is never removed automatically."""
    try:
        raw, _ = read_regular(lock / 'owner.json')
        owner = json.loads(raw)
        pid, started = int(owner['pid']), str(owner['started_utc'])
    except (OSError, ValueError, KeyError, TypeError):
        return 'Another operation may be running; no owner details are available.'
    text = f'It was taken by process {pid} at {started}.'
    if os.name == 'posix':
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            text += ' That process no longer exists on this machine, so the lock is probably stale.'
        except OSError:
            pass
        else:
            text += ' That process is still running.'
    return text

def quarantine(root, store, relative, apply=False, expected=None):
    root, store = setup(root, store)
    path = target_path(root, relative)
    data, info = read_regular(path)
    if stat.S_IMODE(info.st_mode) & 0o7000:
        raise ValueError('Files with special permission bits are not supported.')
    if os.name == 'posix' and info.st_uid != os.geteuid():
        raise ValueError('File owner differs from this SSH user; hosting support is needed.')
    digest = sha(data)
    if expected and expected.lower() != digest:
        raise ValueError('SHA-256 differs from the reviewed file. No action taken.')
    preview = {'action': 'quarantine', 'file': relative, 'bytes': len(data), 'sha256': digest,
               'status': 'preview', 'warning': 'Removing this file may break the site. Same-account attackers can access the store.'}
    if not apply:
        return preview
    if not expected:
        raise ValueError('--apply requires --sha256 from the reviewed preview or scan report.')
    with store_lock(store):
        # Recheck after taking the tool lock; it does not lock out WordPress/PHP.
        current, current_info = read_regular(target_path(root, relative))
        if sha(current) != digest or fingerprint(current_info) != fingerprint(info):
            raise ValueError('Source changed since preview; no file removed.')
        item_id = uuid.uuid4().hex
        folder = store / item_id
        folder.mkdir(mode=0o700)
        record = {'format': 1, 'id': item_id, 'root': str(root), 'relative_path': relative,
                  'sha256': digest, 'bytes': len(data), 'mode': stat.S_IMODE(info.st_mode) & 0o777,
                  'mtime_ns': info.st_mtime_ns, 'uid': getattr(info, 'st_uid', None),
                  'gid': getattr(info, 'st_gid', None),
                  'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'preparing'}
        record_write(folder, record)
        write_exclusive(folder / 'payload.bin', data)
        saved, _ = read_regular(folder / 'payload.bin')
        if sha(saved) != digest:
            raise ValueError('Backup verification failed; original remains in place.')
        record['status'] = 'backed-up'
        record_write(folder, record)
        current, current_info = read_regular(target_path(root, relative))
        if sha(current) != digest or fingerprint(current_info) != fingerprint(info):
            raise ValueError('Source changed; preserved backup but did not remove original.')
        os.unlink(path)
        record['status'] = 'quarantined'
        record_write(folder, record)
        return dict(preview, status='quarantined', id=item_id)

def restore(root, store, item_id, apply=False, expected=None):
    root, store = setup(root, store)
    if not re.fullmatch('[a-f0-9]{32}', item_id):
        raise ValueError('Invalid quarantine ID.')
    folder = no_links(store / item_id)
    raw, _ = read_regular(no_links(folder / 'record.json'))
    record = json.loads(raw)
    if record.get('format') != 1 or record.get('id') != item_id or record.get('root') != str(root):
        raise ValueError('Record does not match this quarantine ID and website root.')
    path = target_path(root, record['relative_path'])
    if path.exists() or path.is_symlink():
        raise ValueError('Restore destination already exists. It will not be overwritten.')
    if not path.parent.is_dir():
        raise ValueError('Original parent directory is missing; restore it separately after review.')
    data, _ = read_regular(no_links(folder / 'payload.bin'))
    if sha(data) != record.get('sha256') or len(data) != record.get('bytes'):
        raise ValueError('Stored file failed integrity verification.')
    if expected and expected.lower() != sha(data):
        raise ValueError('SHA-256 differs from the stored file. No action taken.')
    mode = record.get('mode')
    if type(mode) is not int or not 0 <= mode <= 0o777:
        raise ValueError('Invalid stored permissions.')
    if os.name == 'posix' and record.get('uid') != os.geteuid():
        raise ValueError('Original owner differs from this SSH user; hosting support is needed for a faithful restore.')
    preview = {'action': 'restore', 'file': record['relative_path'], 'sha256': sha(data), 'status': 'preview', 'id': item_id,
               'warning': 'Restore reactivates this file. Restore only after review. Backup remains in the store.'}
    if not apply:
        return preview
    with store_lock(store):
        target_path(root, record['relative_path'])
        pending = path.parent / ('.sentinel-restore-' + uuid.uuid4().hex + '.tmp')
        try:
            write_exclusive(pending, data)
            if os.name == 'posix' and record.get('gid') != pending.stat().st_gid:
                os.chown(pending, -1, record['gid'])
            os.chmod(pending, mode)
            os.utime(pending, ns=(record['mtime_ns'], record['mtime_ns']))
            # Atomic no-overwrite publication on supported filesystems.
            # No fallback to a potentially destructive rename.
            os.link(pending, path)
        finally:
            if pending.exists():
                pending.unlink()
        record['status'] = 'restored'
        record['restored_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record_write(folder, record)
        return dict(preview, status='restored')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['quarantine', 'restore'])
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--store', required=True, type=Path)
    parser.add_argument('--file', help='Relative path inside the website, for quarantine')
    parser.add_argument('--id', help='Quarantine item ID, for restore')
    parser.add_argument('--sha256', help='Reviewed SHA-256: required when applying quarantine, checked when given for restore')
    parser.add_argument('--apply', action='store_true', help='Perform the explicitly selected action; otherwise preview only')
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'quarantine' and not args.file:
        parser.error('quarantine requires --file')
    if args.action == 'restore' and not args.id:
        parser.error('restore requires --id')
    try:
        result = quarantine(args.root, args.store, args.file, args.apply, args.sha256) if args.action == 'quarantine' else restore(args.root, args.store, args.id, args.apply, args.sha256)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Operation stopped: ' + str(exc), file=sys.stderr)
        print('If applying an operation, inspect its store record and source path before retrying; an interruption can occur after a file change.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
