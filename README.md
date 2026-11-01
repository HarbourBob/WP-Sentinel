# WP Sentinel

> **Back up your site first, if at all possible.** Keep the backup away from the website.

WP Sentinel scans a WordPress site and its database over SSH for signs of compromise, and
helps you deal with what it finds. It produces a report you can read in a browser, and it
can move reviewed files into a private quarantine or swap them for verified clean copies.

Current release: **0.23.0-rc1**

## Status: new and largely untested, with no guarantees

This is new software, offered for testing under the [MIT licence](LICENSE), with no
warranty. It may not work on your host, it may miss malware, and it may flag innocent
files. It has been run on one real site. How much real malware the rules catch has not
been measured. Try it on a staging copy before relying on it.

A report with no findings does not mean there is no malware.

Testers and developers are welcome. See [Contributing](#contributing).

## What it does

- **Scans files** for malicious patterns and for PHP in places it should not be.
- **Compares core, plugins and themes** with their official copies, or with trusted ZIP
  files you supply.
- **Scans the database** for injected content, unexpected admin accounts and other
  changes, using PHP CLI.
- **Checks startup locations** such as must-use plugins, `.htaccess` and the account
  crontab.
- **Quarantines or replaces files** you have reviewed, and can undo either.
- **Runs from your own computer** if you prefer, leaving nothing on the host and keeping
  the evidence off it.
- **Covers a whole hosting account**, with scheduled checks and email or webhook alerts.

[FEATURES.md](FEATURES.md) has the full list, including what is not covered.

## How it stays safe to run

- It never loads WordPress and never runs site code.
- Scanning does not change website files or database records.
- Any change is a preview by default. Applying one needs `--apply` and the hash from the
  preview you reviewed.
- It uses only the Python standard library, and needs no `sudo`.

Private stores do not protect evidence from an attacker running as the hosting account.
Keep independent off-account backups, and keep the tool and its evidence outside every
public document root.

## Requirements

- SSH access to your host.
- Python 3.7 or later on the host.
- PHP CLI with mysqli on the host, for database checks.
- Python 3.8 or later and an ssh client on your own computer, if you run it from there.

## First scan

Download this repository, then upload the files to a `compat/wp-sentinel` folder beside
your `public_html`, never inside it. Use binary transfer, because converting line endings
makes the package check fail. The `tools` folder is not needed on the host.

Then connect over SSH and run these from that folder:

```bash
python3 -I -S verify-package.py
```

```bash
chmod 700 ..
```

```bash
python3 -I -S sentinelctl.py --profile ../site.json init --root ../../public_html --private-dir .. --core-version auto --locale en_US
```

```bash
python3 -I -S sentinelctl.py --profile ../site.json scan --core --plugins --themes
```

`../site.json` is the profile, a small settings file that the `init` line creates. Use
`en_US` unless this prints another locale:

```bash
grep wp_local_package ../../public_html/wp-includes/version.php
```

The scan prints the path of its report folder. Download `report.html` from there and open
it on your own computer. Findings are sorted by priority, and file findings include
ready-to-copy preview commands. [RULES.txt](documentation/RULES.txt) explains how to read
them.

[INSTALL.txt](documentation/INSTALL.txt) has the details.

## Running from your own computer

This uploads the scanner to a temporary folder, runs it, copies the evidence back and
removes the folder. Run it on your own computer, not on the server:

```bash
python sentinel-remote.py scan --host user@example.com --root /home/user/public_html --core --plugins --themes --persistence
```

[REMOTE.txt](documentation/REMOTE.txt) covers SSH ports, keys and database checks.

## Guides

All guides are in the [documentation](documentation) folder.

| Guide | What it covers |
| --- | --- |
| [INSTALL](documentation/INSTALL.txt) | Install on a host and run your first scan. |
| [REMOTE](documentation/REMOTE.txt) | Run from your own computer and keep evidence off the host. |
| [ACCOUNT](documentation/ACCOUNT.txt) | Find and scan every WordPress install on an account. |
| [MONITORING](documentation/MONITORING.txt) | Scheduled checks, email and webhook alerts, old report cleanup. |
| [RULES](documentation/RULES.txt) | What the scanner looks for and how to read findings. |
| [QUARANTINE](documentation/QUARANTINE.txt) | Move reviewed files aside, and restore them. |
| [BATCH-QUARANTINE](documentation/BATCH-QUARANTINE.txt) | Move hundreds of reviewed files from one checked plan, and undo it. |
| [CLEAN-REPLACEMENT](documentation/CLEAN-REPLACEMENT.txt) | Swap changed core, plugin and theme files for clean copies, and undo it. |
| [MANAGEMENT](documentation/MANAGEMENT.txt) | Report history, review notes and inventories. |
| [FILE-INVENTORY](documentation/FILE-INVENTORY.txt) | Compare file hashes between scans. |
| [PERSISTENCE](documentation/PERSISTENCE.txt) | Startup files and account crontab. |
| [DATABASE-CONTENT](documentation/DATABASE-CONTENT.txt) | Replace one post's content, with a guarded restore. |
| [DATABASE-INVENTORY](documentation/DATABASE-INVENTORY.txt) | Offline check of database backups. |
| [DATABASE-VERIFY](documentation/DATABASE-VERIFY.txt) | Check a recorded database operation against live data. |
| [PACKAGE-CHECK](documentation/PACKAGE-CHECK.txt) | Confirm an upload matches the release. |

Release notes are in [documentation/README.txt](documentation/README.txt).

## Contributing

Forks and improvements are welcome. The most useful things right now are:

- **Trying it on your own sites or staging copies**, and reporting what breaks or what it
  flags wrongly.
- **Testing the rules against real malware samples**, since detection has not been
  measured. Please do not add live malware to the repository.
- **Building something from the [not built yet](FEATURES.md#not-built-yet) list.**

A few things to know before you change anything:

- The automated test suite is not in this repository.
- After changing any packaged file, run this, or `verify-package.py` will report a
  mismatch:

  ```bash
  python -B tools/build_manifest.py
  ```

- Never commit reports, profiles or evidence, as they describe real sites. The
  `.gitignore` covers the usual names, but check before you commit.

## Support
rob@littlewebshack.com
https://littlewebshack.com

Buy me a coffee - https://buymeacoffee.com/robertpalmer/

-- Copyright © 2026 - Robert Palmer 