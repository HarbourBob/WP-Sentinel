#!/usr/bin/env python3
"""A window for running sentinel-remote.py scans without typing commands.

It fills in the same options you would type, runs sentinel-remote.py, shows its output and
opens the pages it makes. Everything still happens over SSH from this computer, and evidence
stays here. See documentation/APP.txt.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import webbrowser

HERE = Path(__file__).resolve().parent
REMOTE = HERE / 'sentinel-remote.py'
SETTINGS = Path.home() / '.wp-sentinel-app.json'
USER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]{0,63}')
SERVER = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}')
CONTROL_TEXT = re.compile('[\x00-\x08\x0b-\x1f\x7f]')
OPTIONS = (('core', 'Compare WordPress core files with official copies', '--core'),
           ('plugins', 'Compare plugins with official copies', '--plugins'),
           ('themes', 'Compare themes with official copies', '--themes'),
           ('persistence', 'Check startup files', '--persistence'),
           ('database', 'Check the database (reads its details from wp-config.php)', '--db-from-wp-config'))
# No console windows flash up for the programs run in the background.
QUIET = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

spec = importlib.util.spec_from_file_location('sentinel_app_remote', REMOTE)
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)

def console_python():
    """python.exe rather than pythonw.exe, so a console window can show prompts."""
    path = Path(sys.executable)
    return str(path.with_name('python.exe')) if path.name.lower() == 'pythonw.exe' else str(path)

# Runs one command in its own console window and keeps the window open, so its prompts can be answered.
CONSOLE_STEP = "import subprocess,sys;print(sys.argv[1]+'\\n');r=subprocess.call(sys.argv[2:]);print('\\nFinished.' if r==0 else '\\nDid not finish (exit '+str(r)+').');input('Press Enter to close this window.')"

class App:
    def __init__(self, root):
        self.root = root
        self.process = None
        self.lines = queue.Queue()
        # Where the running command's output goes: this window, or a quarantine or clean copies window.
        self.view = self
        self.windows = {}
        root.title('WP Sentinel')
        root.minsize(840, 640)
        saved = self.load_settings()
        self.v = {name: tk.StringVar(value=saved.get(name, default)) for name, default in (
            ('user', ''), ('server', ''), ('port', '22'), ('key', ''), ('root', ''),
            ('evidence', str(HERE / 'sentinel-evidence')), ('vuln_key', ''))}
        self.o = {name: tk.BooleanVar(value=saved.get('options', {}).get(name, name != 'database')) for name, _, _ in OPTIONS}

        frame = ttk.Frame(root, padding=12)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        row = 0
        def field(label, name, hint='', browse=None):
            nonlocal row
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', pady=2)
            ttk.Entry(frame, textvariable=self.v[name]).grid(row=row, column=1, sticky='ew', pady=2)
            if browse:
                ttk.Button(frame, text='Browse…', command=browse).grid(row=row, column=2, padx=(6, 0))
            row += 1
            if hint:
                ttk.Label(frame, text=hint, foreground='#666').grid(row=row, column=1, columnspan=2, sticky='w')
                row += 1

        ttk.Label(frame, text='Connection', font=('Segoe UI', 11, 'bold')).grid(row=row, column=0, sticky='w'); row += 1
        field('SSH username', 'user', 'From your host\'s SSH page, such as u1234-abcd')
        field('Server', 'server', 'Such as uk80.siteground.eu')
        field('Port', 'port', 'SSH port, not FTP. SiteGround uses 18765; many hosts use 22')
        field('Private key file', 'key', 'The key file you downloaded or created for SSH', self.pick_key)
        field('Site folder on server', 'root', 'Such as /home/customer/www/example.com/public_html')

        ttk.Label(frame, text='Scan', font=('Segoe UI', 11, 'bold')).grid(row=row, column=0, sticky='w', pady=(10, 0)); row += 1
        for name, label, _ in OPTIONS:
            ttk.Checkbutton(frame, text=label, variable=self.o[name]).grid(row=row, column=0, columnspan=3, sticky='w'); row += 1
        field('Wordfence key file', 'vuln_key', 'Optional: checks versions for known vulnerabilities. See VULNERABILITIES.txt', self.pick_vuln_key)
        field('Evidence folder', 'evidence', 'On this computer. Each scan is saved and sealed here', self.pick_evidence)

        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=3, sticky='w', pady=(10, 4)); row += 1
        self.busy_buttons = []
        for text, command in (('Unlock key', self.unlock_key), ('Test connection', self.test), ('Scan', self.scan), ('Check saved evidence', self.verify)):
            b = ttk.Button(buttons, text=text, command=command)
            b.pack(side='left', padx=(0, 6))
            self.busy_buttons.append(b)
        self.stop_button = ttk.Button(buttons, text='Stop', command=self.stop, state='disabled')
        self.stop_button.pack(side='left')

        pages = ttk.Frame(frame)
        pages.grid(row=row, column=0, columnspan=3, sticky='w', pady=(0, 6)); row += 1
        ttk.Label(pages, text='Latest scan:').pack(side='left', padx=(0, 6))
        for text, name in (('Report', 'report.html'), ('Timeline', 'timeline.html'), ('Vulnerabilities', 'vulnerabilities.html')):
            b = ttk.Button(pages, text=text, command=lambda n=name: self.open_page(n))
            b.pack(side='left', padx=(0, 6))
            self.busy_buttons.append(b)
        for text, command in (('Reviews', lambda: self.open_window('reviews')), ('Checklist', self.checklist), ('Quarantine', lambda: self.open_window('quarantine')),
                              ('Clean copies', lambda: self.open_window('replace'))):
            b = ttk.Button(pages, text=text, command=command)
            b.pack(side='left', padx=(0, 6))
            self.busy_buttons.append(b)
        ttk.Button(pages, text='Evidence folder', command=self.open_evidence).pack(side='left')

        self.status = tk.StringVar(value='Fill in the connection, then press Test connection.')
        ttk.Label(frame, textvariable=self.status, font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, columnspan=3, sticky='w'); row += 1
        self.output = tk.Text(frame, height=14, wrap='word', font=('Consolas', 9), state='disabled')
        self.output.grid(row=row, column=0, columnspan=3, sticky='nsew')
        frame.rowconfigure(row, weight=1)
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.pump)

    # Settings hold paths and names only, never keys or passwords.
    def load_settings(self):
        try:
            value = json.loads(SETTINGS.read_text(encoding='utf-8'))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def save_settings(self):
        value = {name: var.get().strip() for name, var in self.v.items()}
        value['options'] = {name: var.get() for name, var in self.o.items()}
        try:
            SETTINGS.write_text(json.dumps(value, indent=2), encoding='utf-8')
        except OSError:
            pass

    def pick_key(self):
        path = filedialog.askopenfilename(title='Choose your SSH private key', initialdir=Path.home() / '.ssh')
        if path:
            self.v['key'].set(path)

    def pick_vuln_key(self):
        path = filedialog.askopenfilename(title='Choose the file holding your Wordfence key', initialdir=Path.home() / '.ssh')
        if path:
            self.v['vuln_key'].set(path)

    def pick_evidence(self):
        path = filedialog.askdirectory(title='Choose the evidence folder', initialdir=self.v['evidence'].get() or HERE)
        if path:
            self.v['evidence'].set(path)

    def settings(self):
        """The checked connection details, or None after telling the user what to fix."""
        user, server, root = (self.v[n].get().strip() for n in ('user', 'server', 'root'))
        key = self.v['key'].get().strip()
        problem = None
        if not USER.fullmatch(user):
            problem = 'Enter the SSH username from your host, such as u1234-abcd.'
        elif not SERVER.fullmatch(server):
            problem = 'Enter the server name, such as uk80.siteground.eu, without https:// or a folder.'
        elif not self.v['port'].get().strip().isdigit() or not 0 < int(self.v['port'].get()) < 65536:
            problem = 'Enter the SSH port number, such as 18765 or 22.'
        elif key and not Path(key).is_file():
            problem = 'The private key file was not found.'
        elif not root.startswith('/') or not remote.valid_remote_root(root):
            problem = 'Enter the site folder on the server as a full path starting with /.'
        if problem:
            messagebox.showwarning('WP Sentinel', problem)
            return None
        self.save_settings()
        return dict(target=user + '@' + server, port=str(int(self.v['port'].get())), key=key, root=root)

    def ssh_base(self, s):
        return ['ssh', '-p', s['port']] + (['-i', s['key']] if s['key'] else [])

    def connection_args(self, s):
        return ['--host', s['target'], '--port', s['port']] + (['--identity', s['key']] if s['key'] else [])

    def evidence(self):
        return Path(os.path.abspath(self.v['evidence'].get().strip() or HERE / 'sentinel-evidence'))

    # Output -----------------------------------------------------------------------------------
    def write(self, text):
        output = self.view.output
        output.configure(state='normal')
        output.insert('end', text)
        output.see('end')
        output.configure(state='disabled')

    def views(self):
        return [self] + list(self.windows.values())

    def pump(self):
        try:
            while True:
                kind, value = self.lines.get_nowait()
                if kind == 'line':
                    self.write(value)
                else:
                    self.finished(value)
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def run(self, argv, title, done=None, view=None):
        """Run a command in the background, showing its output in view: this window unless another is given.
        Only one runs at a time, since scans, quarantine and clean copies for a site must not overlap."""
        if self.process:
            messagebox.showinfo('WP Sentinel', 'Something is already running. Wait for it to finish, or press Stop.')
            return
        self.view = view or self
        self.view.output.configure(state='normal')
        self.view.output.delete('1.0', 'end')
        self.view.output.configure(state='disabled')
        self.view.status.set(title + '…')
        self.done = done
        for window in self.views():
            for b in window.busy_buttons:
                b.configure(state='disabled')
        self.view.stop_button.configure(state='normal')
        env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1')
        try:
            self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                            cwd=HERE, env=env, creationflags=QUIET)
        except OSError as error:
            self.lines.put(('line', 'Could not start: ' + str(error) + '\n'))
            self.lines.put(('done', -1))
            return
        def reader(process):
            for raw in process.stdout:
                # Part of this comes from the host, so control characters are not passed on.
                self.lines.put(('line', CONTROL_TEXT.sub('?', raw.decode('utf-8', 'replace').replace('\r\n', '\n'))))
            self.lines.put(('done', process.wait()))
        threading.Thread(target=reader, args=(self.process,), daemon=True).start()

    def finished(self, code):
        self.process = None
        for window in self.views():
            for b in window.busy_buttons:
                b.configure(state='normal')
        self.view.stop_button.configure(state='disabled')
        for window in self.windows.values():
            window.refresh()
        done, self.done = self.done, None
        if done:
            done(code)
        else:
            self.view.status.set('Finished.' if code == 0 else 'Stopped with a problem (exit ' + str(code) + '). See the messages below.')

    def stop(self, question=None):
        if self.process and messagebox.askyesno('WP Sentinel', question or 'Stop now? A scan stopped part way can leave its temporary folder on the server. '
                                                'Its name starts with .sentinel-run- in your home folder there; you can delete it.'):
            self.process.terminate()

    def close(self):
        if self.process and not messagebox.askyesno('WP Sentinel', 'Something is still running. Stop it and close?'):
            return
        if self.process:
            self.process.terminate()
        self.root.destroy()

    def console(self, title, argv):
        """Open a console window for steps that ask questions: a passphrase, or a first-time server check."""
        if os.name == 'nt':
            subprocess.Popen([console_python(), '-I', '-c', CONSOLE_STEP, title] + argv, creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            messagebox.showinfo('WP Sentinel', 'Run this in a terminal:\n\n' + ' '.join(argv))

    # Actions ----------------------------------------------------------------------------------
    def unlock_key(self):
        key = self.v['key'].get().strip()
        if not key or not Path(key).is_file():
            messagebox.showwarning('WP Sentinel', 'Choose your private key file first.')
            return
        try:
            state = subprocess.run(['ssh-add', '-l'], capture_output=True, timeout=20, creationflags=QUIET).returncode
        except (OSError, subprocess.TimeoutExpired):
            state = 2
        if state == 2:
            messagebox.showwarning('WP Sentinel', 'The OpenSSH Authentication Agent is not running, so a key with a passphrase cannot be unlocked for scans.\n\n'
                                   'Ask whoever looks after this computer to set the "OpenSSH Authentication Agent" service to start automatically, '
                                   'or see "UNLOCKING YOUR KEY" in documentation/APP.txt. A key without a passphrase does not need this.')
            return
        self.console('Unlock your SSH key. Type its passphrase when asked; nothing shows as you type.', ['ssh-add', key])
        self.status.set('Type your passphrase in the window that opened, then press Test connection.')

    def test(self):
        s = self.settings()
        if not s:
            return
        argv = self.ssh_base(s) + ['-o', 'BatchMode=yes', '-T', s['target'], "python3 -c \"print('Python found on the server')\""]
        def done(code):
            text = self.output.get('1.0', 'end')
            if code == 0:
                self.status.set('Connected. Ready to scan.')
            elif 'Host key verification failed' in text or 'host key' in text.lower():
                self.status.set('This computer has not met this server before.')
                if messagebox.askyesno('WP Sentinel', 'This computer has not connected to this server before, so SSH needs you to confirm it once.\n\n'
                                       'Open a window to do that? It shows the server\'s fingerprint. If your host publishes its fingerprint, '
                                       'check they match, then type yes.'):
                    self.console('Confirm the server. Type yes if the fingerprint is right; then this window can be closed.',
                                 self.ssh_base(s) + ['-T', s['target'], 'exit'])
            elif 'Permission denied' in text:
                self.status.set('The server refused the login. Check the username and key, or press Unlock key first.')
            elif code == -1:
                self.status.set('SSH is not installed or could not start.')
            else:
                self.status.set('Could not connect. Check the server name and port (SSH, not FTP). See the messages below.')
        self.run(argv, 'Connecting', done)
        # Windows ssh has no quick connect timeout, so a wrong port is caught here instead.
        self.root.after(60000, lambda p=self.process: p and p.poll() is None and p is self.process and (p.terminate(), self.lines.put(('line', 'No answer after 60 seconds: check the port.\n'))))

    def scan(self):
        s = self.settings()
        if not s:
            return
        argv = [sys.executable, '-u', str(REMOTE), 'scan'] + self.connection_args(s) + ['--root', s['root'], '--evidence-dir', str(self.evidence()), '--unattended']
        argv += [flag for name, _, flag in OPTIONS if self.o[name].get()]
        vuln_key = self.v['vuln_key'].get().strip()
        if vuln_key:
            if not Path(vuln_key).is_file():
                messagebox.showwarning('WP Sentinel', 'The Wordfence key file was not found.')
                return
            argv += ['--vuln-key-file', vuln_key]
        def done(code):
            if code == 0:
                self.status.set('Scan finished and sealed. Opening the report.')
                self.open_page('report.html')
            else:
                self.status.set('The scan did not finish (exit ' + str(code) + '). See the messages below.')
        self.run(argv, 'Scanning (this can take several minutes)', done)

    def verify(self):
        self.run([sys.executable, '-u', str(REMOTE), 'verify', '--evidence-dir', str(self.evidence())], 'Checking saved evidence')

    def latest_run(self):
        """Newest run folder with a report for this site. Found on disk, not read from the scan's output."""
        s = self.settings()
        if not s:
            return None
        site_dir = remote.site_directory(self.evidence(), s['target'], s['root'])
        runs = sorted(p for p in site_dir.glob('*') if p.is_dir() and remote.RUN_FOLDER.fullmatch(p.name) and (p / 'report.html').is_file()) if site_dir.is_dir() else []
        if not runs:
            messagebox.showinfo('WP Sentinel', 'No finished scan of this site was found in the evidence folder.')
            return None
        return runs[-1]

    def open_page(self, name):
        run_dir = self.latest_run()
        if not run_dir:
            return
        # The report page is built here from the sealed report, with your reviews applied.
        page = remote.render_view(run_dir) if name == 'report.html' else run_dir / name
        if not page.is_file():
            messagebox.showinfo('WP Sentinel', {'timeline.html': 'The latest scan has no timeline.',
                                                'vulnerabilities.html': 'The latest scan has no vulnerability check. Add a Wordfence key file and scan again.'}.get(name, name + ' was not found.'))
            return
        webbrowser.open(page.as_uri())

    def checklist(self):
        run_dir = self.latest_run()
        if not run_dir:
            return
        page = run_dir.parent / ('checklist-' + run_dir.name) / 'checklist.html'
        if page.is_file():
            webbrowser.open(page.as_uri())
            return
        def done(code):
            if code == 0 and page.is_file():
                self.status.set('Checklist made.')
                webbrowser.open(page.as_uri())
            else:
                self.status.set('Could not make the checklist. See the messages below.')
        self.run([sys.executable, '-u', str(REMOTE), 'checklist', '--run', str(run_dir)], 'Making the checklist', done)

    def open_window(self, kind):
        """The reviews, quarantine or clean copies window for the latest scan."""
        if kind in self.windows:
            self.windows[kind].top.lift()
            return
        s = self.settings()
        run_dir = self.latest_run() if s else None
        if not run_dir:
            return
        if not (run_dir / 'EVIDENCE.json').is_file():
            messagebox.showinfo('WP Sentinel', 'The latest scan was not sealed, so it cannot be used for this. Scan again.')
            return
        self.windows[kind] = ReviewWindow(self, run_dir) if kind == 'reviews' else ListWindow(self, s, run_dir, kind)

    def open_evidence(self):
        folder = self.evidence()
        if not folder.is_dir():
            messagebox.showinfo('WP Sentinel', 'The evidence folder does not exist yet. It is made by the first scan.')
        elif os.name == 'nt':
            os.startfile(folder)
        else:
            webbrowser.open(folder.as_uri())

TICKED, UNTICKED = '☑', '☐'
PRIORITIES = (('high', 'High priority only'), ('medium', 'High and medium'), ('review', 'Everything that needs review'))
# The words each window uses. The steps behind them are the same: make a list, check it, apply it, undo it.
WORDS = {
    'quarantine': dict(
        title='WP Sentinel: quarantine', name='quarantine',
        intro='Quarantine moves files out of your website into a private folder on your hosting account, outside the website. Nothing is deleted, '
              'and you can put files back. Back up your site first: removing a file that a plugin or theme needs can break the site.',
        do_tab='Move files out', do_tick='Move', do_button='Move the ticked files', doing='Moving files out of the website', ready='{} files are ready to move. Press Move the ticked files.',
        confirm='Move {} files out of the website?\n\nHave you backed up the site? Removing a file that a plugin or theme needs can break the site. '
                'You can put files back from the Put files back tab.\n\nCheck your site straight afterwards.',
        skip='Leave files that have changed since the scan, and move the rest', done='Done. Check your site now, then run a new scan from the main window. '
             'Moving files does not clear caches, end logins or close the way in.', none_ready='No files are ready to move. Ones already moved are listed under Put files back.',
        undo_tab='Put files back', undo_tick='Put back', undo_when='Moved (UTC)', undo_button='Put back the ticked files', undoing='Putting files back',
        undo_intro='Files this list has moved. Putting a file back makes it active again, including any malware in it.',
        undo_ready='{} files are ready to put back. Press Put back the ticked files.', undo_confirm='Put back {} files?\n\nThey become active on your website again, including any malware in them.',
        undone='Files put back. Check your site.', counted='moved out now', stop='Stop now? Files already moved stay moved. Check the list again afterwards: it carries on safely from where it stopped.'),
    'replace': dict(
        title='WP Sentinel: clean copies', name='clean copies',
        intro='Clean copies swap changed WordPress, plugin and theme files for verified copies from WordPress.org, in your site\'s language. Each original is kept '
              'in a private folder on your hosting account, so you can change it back. A clean copy overwrites any edits made to that file on purpose. Back up your site first.',
        do_tab='Swap in clean copies', do_tick='Swap', do_button='Swap the ticked files', doing='Swapping in clean copies', ready='{} files are ready to swap. Press Swap the ticked files.',
        confirm='Swap {} files for clean copies?\n\nHave you backed up the site? Any edits made to these files on purpose will be replaced. '
                'You can change them back from the Change back tab.\n\nCheck your site straight afterwards.',
        skip='Leave files that have changed since the scan, and swap the rest', done='Done. Check your site now, then run a new scan from the main window. '
             'Clean copies do not clear caches, end logins or close the way in.', none_ready='No files are ready to swap. Ones already swapped are listed under Change back.',
        undo_tab='Change back', undo_tick='Change back', undo_when='Swapped (UTC)', undo_button='Change back the ticked files', undoing='Changing files back to the originals',
        undo_intro='Files this list has swapped. Changing a file back brings back the original, including any malware in it.',
        undo_ready='{} files are ready to change back. Press Change back the ticked files.',
        undo_confirm='Change {} files back to the originals?\n\nThe originals become active on your website again, including any malware in them.',
        undone='Files changed back. Check your site.', counted='swapped now', stop='Stop now? Files already swapped stay swapped. Check the list again afterwards: it carries on safely from where it stopped.'),
}

def source_text(label):
    """replace.py's label for a clean copy, such as wordpress.org-plugin-hello-dolly-1.7.2, in plain words."""
    match = re.fullmatch(r'wordpress\.org-core-(.+)', label)
    if match:
        return 'WordPress.org: WordPress ' + match[1]
    match = re.fullmatch(r'wordpress\.org-(?:plugin|theme)-(.+)-([^-]+)', label)
    if match:
        return f'WordPress.org: {match[1]} {match[2]}'
    match = re.fullmatch(r'your-zip-(?:plugin|theme)-(.+)', label)
    return 'Your own ZIP: ' + match[1] if match else label

def stamp_text(name):
    """batch-20261105T100000Z-abcdef or 20261105T100000Z-abcdef as 05 Nov 2026 10:00 UTC."""
    match = re.search(r'(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})', name)
    months = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
    return f'{match[3]} {months[int(match[2]) - 1]} {match[1]} {match[4]}:{match[5]} UTC' if match else name

class ListWindow:
    """Quarantine or clean copies for the files a scan found, and undoing either. Every step runs sentinel-remote.py,
    and the buttons that change the website only unlock after checking that exact list. See documentation/APP.txt."""
    def __init__(self, app, s, run_dir, kind):
        self.app, self.s, self.run_dir, self.kind = app, s, run_dir, kind
        self.words = w = WORDS[kind]
        self.steps = remote.KINDS[kind]
        self.lists = run_dir.parent / self.steps['folder']
        self.folder = None
        self.back_chosen, self.back_seen = set(), set()
        self.top = top = tk.Toplevel(app.root)
        top.title(w['title'])
        top.minsize(860, 720)
        # Big enough rows for the tick boxes to be easy to see and click.
        ttk.Style(top).configure('Treeview', rowheight=24, font=('Segoe UI', 10))
        frame = ttk.Frame(top, padding=12)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(0, weight=1)
        self.busy_buttons = []
        def button(parent, text, command):
            b = ttk.Button(parent, text=text, command=command)
            b.pack(side='left', padx=(0, 6))
            self.busy_buttons.append(b)
            return b

        ttk.Label(frame, text=s['target'] + '   ' + s['root'], foreground='#666').grid(row=0, column=0, sticky='w')
        ttk.Label(frame, wraplength=820, justify='left', text=w['intro']).grid(row=1, column=0, sticky='w', pady=(4, 8))

        make = ttk.LabelFrame(frame, text='Make a list from the latest scan, ' + stamp_text(run_dir.name), padding=8)
        make.grid(row=2, column=0, sticky='ew')
        self.priority = tk.StringVar(value='high')
        self.critical = tk.BooleanVar(value=False)
        if kind == 'quarantine':
            for value, text in PRIORITIES:
                ttk.Radiobutton(make, text=text, value=value, variable=self.priority).pack(side='left', padx=(0, 12))
            ttk.Checkbutton(make, text='Include files WordPress needs to run (not advised)', variable=self.critical).pack(side='left', padx=(0, 12))
        else:
            ttk.Label(make, wraplength=640, justify='left', text='For the best list, the scan should compare WordPress core files, plugins and themes with '
                      'official copies. Premium plugins and themes have no public copy, so they are left out.').pack(side='left', padx=(0, 12))
        button(make, 'Make a list', self.make_list)

        chooser = ttk.Frame(frame)
        chooser.grid(row=3, column=0, sticky='ew', pady=(8, 0))
        ttk.Label(chooser, text='List:').pack(side='left', padx=(0, 6))
        self.choice = ttk.Combobox(chooser, state='readonly', width=70)
        self.choice.pack(side='left')
        self.choice.bind('<<ComboboxSelected>>', lambda event: self.load(self.choices[self.choice.current()]))
        self.busy_buttons.append(self.choice)
        self.sources = tk.StringVar()
        ttk.Label(frame, textvariable=self.sources, wraplength=820, justify='left', foreground='#444').grid(row=4, column=0, sticky='w', pady=(4, 6))

        self.tabs = ttk.Notebook(frame)
        self.tabs.grid(row=5, column=0, sticky='nsew')
        frame.rowconfigure(5, weight=1)

        move = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(move, text=w['do_tab'])
        second = ('priority', 'Priority', 70) if kind == 'quarantine' else ('source', 'Clean copy from', 230)
        self.move_tree = self.tree(move, (('tick', w['do_tick'], 55), second, ('path', 'File', 380), ('rules', 'Found by', 160), ('state', 'Done', 90)), self.toggle_move)
        row = ttk.Frame(move)
        row.pack(fill='x', pady=(6, 0))
        button(row, 'Tick all', lambda: self.set_moves(True))
        button(row, 'Untick all', lambda: self.set_moves(False))
        button(row, 'What was left out', self.show_skipped)
        self.move_count = tk.StringVar()
        ttk.Label(row, textvariable=self.move_count).pack(side='left', padx=6)
        row = ttk.Frame(move)
        row.pack(fill='x', pady=(6, 0))
        ttk.Label(row, text='How many at once:').pack(side='left', padx=(0, 6))
        self.limit = ttk.Combobox(row, state='readonly', width=6, values=('All', '10', '50', '100'))
        self.limit.current(0)
        self.limit.pack(side='left', padx=(0, 12))
        self.skip = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text=w['skip'], variable=self.skip, command=self.refresh).pack(side='left')
        row = ttk.Frame(move)
        row.pack(fill='x', pady=(6, 0))
        button(row, 'Check the list', self.check_move)
        self.move_button = button(row, w['do_button'], self.move)

        back = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(back, text=w['undo_tab'])
        ttk.Label(back, wraplength=800, text=w['undo_intro']).pack(anchor='w', pady=(0, 6))
        self.back_tree = self.tree(back, (('tick', w['undo_tick'], 80), ('path', 'File', 500), ('moved', w['undo_when'], 170)), self.toggle_back)
        row = ttk.Frame(back)
        row.pack(fill='x', pady=(6, 0))
        button(row, 'Tick all', lambda: self.set_backs(True))
        button(row, 'Untick all', lambda: self.set_backs(False))
        self.back_count = tk.StringVar()
        ttk.Label(row, textvariable=self.back_count).pack(side='left', padx=6)
        row = ttk.Frame(back)
        row.pack(fill='x', pady=(6, 0))
        button(row, 'Check', self.check_back)
        self.back_button = button(row, w['undo_button'], self.put_back)

        self.status = tk.StringVar(value='Make a list, or choose one you made before.')
        ttk.Label(frame, textvariable=self.status, font=('Segoe UI', 10, 'bold'), wraplength=820, justify='left').grid(row=6, column=0, sticky='w', pady=(8, 2))
        self.output = tk.Text(frame, height=9, wrap='word', font=('Consolas', 9), state='disabled')
        self.output.grid(row=7, column=0, sticky='nsew')
        row = ttk.Frame(frame)
        row.grid(row=8, column=0, sticky='e', pady=(8, 0))
        self.stop_button = ttk.Button(row, text='Stop', state='disabled', command=lambda: app.stop(w['stop']))
        self.stop_button.pack(side='left', padx=(0, 6))
        ttk.Button(row, text='Close', command=self.close).pack(side='left')
        top.protocol('WM_DELETE_WINDOW', self.close)
        self.fill_choices()
        if self.choices:
            self.load(self.choices[0])
        self.refresh()

    def tree(self, parent, columns, toggle):
        box = ttk.Frame(parent)
        box.pack(fill='both', expand=True)
        tree = ttk.Treeview(box, columns=[c[0] for c in columns], show='headings', height=10, selectmode='none')
        for name, heading, width in columns:
            tree.heading(name, text=heading, anchor='w')
            tree.column(name, width=width, stretch=name == 'path', anchor='w')
        scroll = ttk.Scrollbar(box, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='left', fill='y')
        tree.bind('<Button-1>', lambda event: tree.identify_region(event.x, event.y) == 'cell' and toggle(tree.identify_row(event.y)))
        return tree

    def close(self):
        if self.app.process and self.app.view is self:
            messagebox.showinfo('WP Sentinel', 'A step is still running. Wait for it to finish, or press Stop first.', parent=self.top)
            return
        self.app.windows.pop(self.kind, None)
        self.top.destroy()

    def command(self, action, *more):
        return [sys.executable, '-u', str(REMOTE), action] + self.app.connection_args(self.s) + ['--root', self.s['root'], '--unattended', *more]

    # Lists ----------------------------------------------------------------------------------------
    def fill_choices(self):
        prefix = self.steps['prefix'] + '-'
        self.choices = sorted((p for p in self.lists.glob(prefix + '*') if remote.LIST_NAME.fullmatch(p.name) and (p / 'batch.json').is_file()), reverse=True) if self.lists.is_dir() else []
        labels = []
        for folder in self.choices:
            try:
                plan = (folder / 'plan.txt').read_text(encoding='utf-8', errors='replace')
                receipt = (folder / 'receipt.jsonl').read_text(encoding='utf-8', errors='replace') if (folder / 'receipt.jsonl').is_file() else ''
                labels.append(f'{stamp_text(folder.name)}: {len(remote.plan_entries(plan))} files, {len(remote.active_files(remote.receipt_events(receipt)))} {self.words["counted"]}')
            except OSError:
                labels.append(stamp_text(folder.name) + ': could not be read')
        self.choice.configure(values=labels)
        if self.folder in self.choices:
            self.choice.current(self.choices.index(self.folder))

    def load(self, folder):
        self.folder = folder
        self.back_chosen, self.back_seen = set(), set()
        self.fill_choices()
        self.refresh()

    def read(self):
        """The list's entries, receipt events and the text of its plan."""
        plan = (self.folder / 'plan.txt').read_text(encoding='utf-8', errors='replace')
        receipt = (self.folder / 'receipt.jsonl').read_text(encoding='utf-8', errors='replace') if (self.folder / 'receipt.jsonl').is_file() else ''
        return remote.plan_entries(plan), remote.receipt_events(receipt), plan

    def last_check(self, action, only=()):
        """The last check of this exact list, if nothing has changed since. The buttons that change the website depend on it."""
        try:
            last = json.loads((self.folder / 'last-check.json').read_text(encoding='utf-8'))
            _, _, plan_sha, receipt_sha = remote.batch_files(self.folder)
        except (OSError, ValueError):
            return None
        same = last.get('action') == action and last.get('plan_sha256') == plan_sha and last.get('receipt_sha256') == receipt_sha and last.get('only') == sorted(only)
        return last if same else None

    def refresh(self):
        """Redraw both lists and decide which buttons may be pressed."""
        running = bool(self.app.process)
        self.choice.configure(state='disabled' if running else 'readonly')
        for tree in (self.move_tree, self.back_tree):
            tree.delete(*tree.get_children())
        self.move_button.configure(state='disabled')
        self.back_button.configure(state='disabled')
        self.sources.set('')
        if not self.folder:
            self.move_count.set('')
            self.back_count.set('')
            return
        try:
            entries, events, plan = self.read()
        except OSError as error:
            self.status.set('This list could not be read: ' + str(error))
            return
        if self.kind == 'replace':
            # Where the clean copies come from is the thing to check before swapping anything.
            self.sources.set('Clean copies from: ' + '; '.join(remote.clean(source.split(': ', 1)[-1], 200) for source in remote.plan_sources(plan)) if entries else '')
        states = remote.file_states(events)
        for number, entry in enumerate(entries):
            second = remote.clean(entry['priority'], 20) if self.kind == 'quarantine' else source_text(remote.clean(entry['source'], 80))
            rules = remote.clean(entry['rules'], 120).replace(',', ', ') + (' (missing: put back)' if entry['sha256'] == 'missing' else '')
            self.move_tree.insert('', 'end', iid=str(number), values=(TICKED if entry['ticked'] else UNTICKED, second, remote.clean(entry['path']), rules, states.get(entry['path'], '')))
        ticked = sum(entry['ticked'] for entry in entries)
        self.move_count.set(f'{ticked} of {len(entries)} ticked')
        moved = remote.active_files(events)
        paths = [event['path'] for event in moved]
        # Newly changed files start ticked; choices already made are kept.
        self.back_chosen = (self.back_chosen & set(paths)) | (set(paths) - self.back_seen)
        self.back_seen = set(paths)
        for number, event in enumerate(moved):
            self.back_tree.insert('', 'end', iid=str(number), values=(TICKED if event['path'] in self.back_chosen else UNTICKED, remote.clean(event['path']),
                                  remote.clean(event.get('utc', ''), 19).replace('T', ' ')))
        self.back_count.set(f'{len(self.back_chosen)} of {len(paths)} ticked')
        if running:
            return
        last = self.last_check(self.steps['apply'])
        if last and last.get('ready') and (not last.get('problem_count') or self.skip.get()):
            self.move_button.configure(state='normal')
        last = self.last_check(self.steps['undo'], self.only())
        if last and last.get('ready'):
            self.back_button.configure(state='normal')

    def only(self):
        """Files to undo, or none to mean every file the list has changed."""
        return [] if self.back_chosen == self.back_seen else sorted(self.back_chosen)

    def make_list(self):
        def done(code):
            self.fill_choices()
            if code == 0 and self.choices:
                self.load(self.choices[0])
                self.tabs.select(0)
                entries = self.read()[0]
                left = self.skipped_rows()
                database = sum(reason.startswith('database') for reason, _ in left)
                note = (f' {len(left)} findings were left out' + (f', {database} of them in the database, which this cannot change' if database else '')
                        + ': see What was left out.') if left else ''
                first = 'Check where the clean copies come from and untick' if self.kind == 'replace' else 'Untick'
                self.status.set((f'List made: {len(entries)} files. {first} any you want to keep, then press Check the list.' if entries else
                                 'No files qualify for a list.') + note)
            else:
                self.status.set('The list was not made. See the messages below.')
        argv = self.command(self.steps['make'], '--run', str(self.run_dir))
        if self.kind == 'quarantine':
            argv += ['--priority', self.priority.get()] + (['--include-critical'] if self.critical.get() else [])
        self.app.run(argv, 'Making a list. Nothing on the website changes' + (' (clean copies are downloaded on the server, which can take a minute)' if self.kind == 'replace' else ''),
                     done, view=self)

    def skipped_rows(self):
        """(reason, what) for each finding left out of the list."""
        try:
            lines = (self.folder / 'skipped.txt').read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            lines = []
        return [line.split('\t', 1) for line in lines if '\t' in line and not line.startswith('#')]

    def show_skipped(self):
        if not self.folder:
            return
        rows = self.skipped_rows()
        window = tk.Toplevel(self.top)
        window.title('Left out of this list')
        text = tk.Text(window, width=110, height=24, wrap='word', font=('Consolas', 9))
        text.pack(fill='both', expand=True, padx=8, pady=8)
        text.insert('end', 'These findings are not in the list. They may still need dealing with.\n\n' if rows else 'Nothing was left out.\n')
        for reason, path in rows:
            text.insert('end', remote.clean(path) + '\n    ' + remote.clean(reason) + '\n')
        text.configure(state='disabled')

    # Applying the list ------------------------------------------------------------------------------
    def write_ticks(self, chosen):
        _, _, plan = self.read()
        (self.folder / 'plan.txt').write_bytes(remote.tick(plan, chosen).encode('utf-8'))
        self.status.set('List changed. Press Check the list before going ahead.')
        self.refresh()

    def toggle_move(self, item):
        if not item or self.app.process or not self.folder:
            return
        entries = self.read()[0]
        entry = entries[int(item)]
        self.write_ticks({e['path'] for e in entries if e['ticked'] != (e is entry)})

    def set_moves(self, ticked):
        if self.folder and not self.app.process:
            self.write_ticks({e['path'] for e in self.read()[0]} if ticked else set())

    def check_move(self):
        if not self.folder:
            return
        action = self.steps['apply']
        def done(code):
            last = self.last_check(action)
            if code != 0 or not last:
                self.status.set('The list could not be checked. See the messages below.')
            elif last.get('problem_count') and not self.skip.get():
                self.status.set(f'{last["problem_count"]} files have changed since the scan, which needs a look. Untick them, or tick "Leave files that have changed", then go ahead.')
            elif last.get('ready'):
                self.status.set(self.words['ready'].format(last['ready']))
            else:
                self.status.set(self.words['none_ready'])
        self.app.run(self.command(action, '--plan', str(self.folder)), 'Checking the list. Nothing on the website changes', done, view=self)

    def move(self):
        action = self.steps['apply']
        last = self.last_check(action)
        if not last:
            return
        limit = self.limit.get()
        count = min(last['ready'], int(limit)) if limit != 'All' else last['ready']
        if not messagebox.askyesno('WP Sentinel', self.words['confirm'].format(count), icon='warning', default='no', parent=self.top):
            return
        argv = self.command(action, '--plan', str(self.folder), '--apply', '--plan-sha256', last['plan_sha256'])
        argv += (['--limit', limit] if limit != 'All' else []) + (['--skip-problems'] if self.skip.get() else [])
        def done(code):
            self.fill_choices()
            text = self.output.get('1.0', 'end')
            if code == 0 and 'still to do' in text:
                self.status.set('Done for now. Check your site, then press Check the list and go ahead again for the next ones.')
            elif code == 0:
                self.status.set(self.words['done'])
            else:
                self.status.set('Some files were not changed. See the messages below.')
        self.app.run(argv, self.words['doing'], done, view=self)

    # Undoing --------------------------------------------------------------------------------------
    def toggle_back(self, item):
        if not item or self.app.process:
            return
        path = remote.active_files(self.read()[1])[int(item)]['path']
        self.back_chosen ^= {path}
        self.refresh()

    def set_backs(self, ticked):
        if self.folder and not self.app.process:
            self.back_chosen = set(self.back_seen) if ticked else set()
            self.refresh()

    def check_back(self):
        if not self.folder:
            return
        only = self.only()
        if not self.back_chosen:
            self.status.set('Tick the files first.')
            return
        if len(only) > remote.MAX_ONLY:
            self.status.set(f'Choose at most {remote.MAX_ONLY} files at a time, or tick them all.')
            return
        action = self.steps['undo']
        def done(code):
            last = self.last_check(action, only)
            if code != 0 or not last:
                self.status.set('Could not check. See the messages below.')
            elif last.get('ready'):
                self.status.set(self.words['undo_ready'].format(last['ready']))
            else:
                self.status.set('No files are ready. See the messages below.')
        argv = self.command(action, '--plan', str(self.folder), *[item for path in only for item in ('--only', path)])
        self.app.run(argv, 'Checking. Nothing on the website changes', done, view=self)

    def put_back(self):
        only = self.only()
        action = self.steps['undo']
        last = self.last_check(action, only)
        if not last or not messagebox.askyesno('WP Sentinel', self.words['undo_confirm'].format(last['ready']), icon='warning', default='no', parent=self.top):
            return
        argv = self.command(action, '--plan', str(self.folder), *[item for path in only for item in ('--only', path)], '--apply', '--plan-sha256', last['plan_sha256'])
        def done(code):
            self.fill_choices()
            self.status.set(self.words['undone'] if code == 0 else 'Some files were not changed back. See the messages below.')
        self.app.run(argv, self.words['undoing'], done, view=self)

class ReviewWindow:
    """Mark findings in the latest scan that you checked and found harmless, or withdraw that.
    Reviews are kept on this computer and cover each file exactly as scanned. See documentation/APP.txt."""
    def __init__(self, app, run_dir):
        self.app, self.run_dir = app, run_dir
        self.top = top = tk.Toplevel(app.root)
        top.title('WP Sentinel: reviews')
        top.minsize(860, 520)
        ttk.Style(top).configure('Treeview', rowheight=24, font=('Segoe UI', 10))
        frame = ttk.Frame(top, padding=12)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, wraplength=820, justify='left', text='Mark a finding as reviewed once you have checked it and know it is harmless, such as a '
                  'security file your host added. It is then counted apart in the report and left out of Quarantine and Clean copies lists. '
                  'A review covers the file exactly as it is in this scan: if the file changes, it counts as a finding again. '
                  'Reviews are kept on this computer.').pack(anchor='w', pady=(0, 4))
        ttk.Label(frame, text='Latest scan, ' + stamp_text(run_dir.name) + '. Click a finding, then a button.', foreground='#666').pack(anchor='w', pady=(0, 6))
        box = ttk.Frame(frame)
        box.pack(fill='both', expand=True)
        columns = (('number', '#', 40), ('priority', 'Priority', 70), ('path', 'File', 360), ('rule', 'Found by', 170), ('status', 'Review', 240))
        self.tree = ttk.Treeview(box, columns=[c[0] for c in columns], show='headings', height=12, selectmode='browse')
        for name, heading, width in columns:
            self.tree.heading(name, text=heading, anchor='w')
            self.tree.column(name, width=width, stretch=name in ('path', 'status'), anchor='w')
        scroll = ttk.Scrollbar(box, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='left', fill='y')
        self.tree.bind('<<TreeviewSelect>>', lambda event: self.refresh_buttons())
        row = ttk.Frame(frame)
        row.pack(fill='x', pady=(8, 0))
        self.busy_buttons = []
        self.mark_button = ttk.Button(row, text='Mark as reviewed…', command=self.mark)
        self.withdraw_button = ttk.Button(row, text='Withdraw review', command=self.withdraw)
        for b in (self.mark_button, self.withdraw_button):
            b.pack(side='left', padx=(0, 6))
        ttk.Button(row, text='Open the report', command=lambda: app.open_page('report.html')).pack(side='left', padx=(0, 6))
        ttk.Button(row, text='Close', command=self.close).pack(side='right')
        self.show_info = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text='Show info findings', variable=self.show_info, command=self.refresh).pack(side='left', padx=(12, 0))
        self.status = tk.StringVar()
        ttk.Label(frame, textvariable=self.status, font=('Segoe UI', 10, 'bold'), wraplength=820, justify='left').pack(anchor='w', pady=(8, 0))
        top.protocol('WM_DELETE_WINDOW', self.close)
        self.refresh()

    def close(self):
        self.app.windows.pop('reviews', None)
        self.top.destroy()

    def findings(self):
        """(number, finding) for each finding in the scan, with its review state applied."""
        report = remote.read_report(self.run_dir)
        remote.apply_reviews(report, remote.review_records_for(report, self.run_dir.parent))
        return [(number, finding) for number, finding in enumerate(report['findings'], 1) if isinstance(finding, dict)]

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        try:
            rows = self.findings()
        except (OSError, RuntimeError) as error:
            self.status.set('The scan could not be read: ' + str(error))
            return
        manage = remote.load_module('manage')
        for number, finding in rows:
            if finding.get('severity') == 'info' and not self.show_info.get():
                continue
            if finding.get('review'):
                state = 'Reviewed: ' + remote.clean(finding['review'].get('note', ''), 120)
            elif finding.get('review_changed'):
                state = 'Changed since your review: look again'
            elif not manage.reviewable(finding):
                state = 'Cannot be reviewed (no file hash)'
            else:
                state = 'Not reviewed'
            self.tree.insert('', 'end', iid=str(number), values=(number, remote.clean(finding.get('severity', ''), 20), remote.clean(finding.get('location', '')),
                                                                  remote.clean(finding.get('rule', ''), 80), state))
        self.refresh_buttons()

    def selected(self):
        """The chosen finding's number and the finding, or (None, None)."""
        chosen = self.tree.selection()
        if not chosen:
            return None, None
        number = int(chosen[0])
        return number, dict(self.findings())[number]

    def refresh_buttons(self):
        number, finding = self.selected()
        manage = remote.load_module('manage')
        can_mark = bool(finding) and manage.reviewable(finding) and not finding.get('review')
        self.mark_button.configure(state='normal' if can_mark else 'disabled')
        self.withdraw_button.configure(state='normal' if finding and finding.get('review') else 'disabled')

    def record(self, number, finding, decision, note):
        args = argparse.Namespace(run=self.run_dir, finding=number, sha256=finding['sha256'], note=note, decision=decision)
        try:
            # Its printed summary is not needed here.
            with contextlib.redirect_stdout(io.StringIO()):
                remote.record_review(args)
        except (OSError, ValueError, RuntimeError) as error:
            messagebox.showwarning('WP Sentinel', 'Nothing was recorded: ' + str(error), parent=self.top)
            return False
        return True

    def mark(self):
        number, finding = self.selected()
        if not finding:
            return
        note = simpledialog.askstring('Mark as reviewed', f'{remote.clean(finding.get("location", ""))}\n\nWhat did you check, and why is it harmless?\n'
                                      'For example: SiteGround Security folder protection, added by the plugin.', parent=self.top)
        if note is None:
            return
        if not note.strip():
            messagebox.showinfo('WP Sentinel', 'A short note is needed, so you know later why it was marked.', parent=self.top)
            return
        if self.record(number, finding, 'benign', note):
            self.status.set('Marked as reviewed. Open the report to see it counted apart.')
            self.refresh()

    def withdraw(self):
        number, finding = self.selected()
        if finding and self.record(number, finding, 'withdraw', 'Review withdrawn'):
            self.status.set('Review withdrawn. The finding counts again.')
            self.refresh()

def main():
    root = tk.Tk()
    app = App(root)
    if remote.elevated():
        app.status.set('Running as administrator: reports may open as blank pages. Use a normal PowerShell window.')
        root.withdraw()
        keep = messagebox.askyesno('WP Sentinel', 'This window was started as administrator.\n\n'
                                   'Scans made from here can only be opened from administrator windows, so your reports '
                                   'would show as blank pages in your browser.\n\n'
                                   'Close this, open PowerShell normally (not "Run as administrator"), and start WP Sentinel again.\n\n'
                                   'Carry on anyway?', default='no', icon='warning')
        if not keep:
            root.destroy()
            return
        root.deiconify()
    root.mainloop()

if __name__ == '__main__':
    main()
