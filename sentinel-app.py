#!/usr/bin/env python3
"""A window for running sentinel-remote.py scans without typing commands.

It fills in the same options you would type, runs sentinel-remote.py, shows its output and
opens the pages it makes. Everything still happens over SSH from this computer, and evidence
stays here. See documentation/APP.txt.
"""
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
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
        root.title('WP Sentinel')
        root.minsize(760, 640)
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
        b = ttk.Button(pages, text='Checklist', command=self.checklist)
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
        self.output.configure(state='normal')
        self.output.insert('end', text)
        self.output.see('end')
        self.output.configure(state='disabled')

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

    def run(self, argv, title, done=None):
        """Run a command in the background, showing its output here."""
        if self.process:
            return
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.status.set(title + '…')
        self.done = done
        for b in self.busy_buttons:
            b.configure(state='disabled')
        self.stop_button.configure(state='normal')
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
        for b in self.busy_buttons:
            b.configure(state='normal')
        self.stop_button.configure(state='disabled')
        done, self.done = self.done, None
        if done:
            done(code)
        else:
            self.status.set('Finished.' if code == 0 else 'Stopped with a problem (exit ' + str(code) + '). See the messages below.')

    def stop(self):
        if self.process and messagebox.askyesno('WP Sentinel', 'Stop now? A scan stopped part way can leave its temporary folder on the server. '
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
        page = run_dir / name
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

    def open_evidence(self):
        folder = self.evidence()
        if not folder.is_dir():
            messagebox.showinfo('WP Sentinel', 'The evidence folder does not exist yet. It is made by the first scan.')
        elif os.name == 'nt':
            os.startfile(folder)
        else:
            webbrowser.open(folder.as_uri())

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
