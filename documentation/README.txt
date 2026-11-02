WORDPRESS SENTINEL 0.24.0-rc1

BACK UP YOUR SITE FIRST, IF AT ALL POSSIBLE. Keep the backup away from the website.

STATUS: NEW AND LARGELY UNTESTED, WITH NO GUARANTEES

This is new software, offered for testing under the MIT licence, with no warranty. It
may not work on your host, it may miss malware, and it may flag innocent files. It
has been run on one real site. How much real malware the rules catch has not been
measured. Try it on a staging copy before relying on it. Improvements and forks are
welcome.

Sentinel scans a WordPress site and its database for signs of compromise over
SSH, and can move reviewed files into a private quarantine. It uses only the
Python standard library, plus PHP CLI for database checks. It never loads
WordPress and never runs site code.

Scanning does not change website files or database records. Changes require
explicit review and --apply; preview is the default.

This is a release candidate for triage, not proof that a site is clean. A report
with no findings does not mean no malware. Private stores do not isolate evidence
from an attacker running as the hosting account, so keep independent off-account
backups, and keep tools and evidence outside every public document root.

WHERE TO START

  INSTALL.txt             Install on a host and run your first scan.
  REMOTE.txt              Run from your own computer and keep evidence off the host.
  ACCOUNT.txt             Find and scan every WordPress install on an account.
  MONITORING.txt          Scheduled checks, email and webhook alerts, old report cleanup.
  RULES.txt               What the scanner looks for and how to read findings.
  QUARANTINE.txt          Move reviewed files aside, and restore them.
  BATCH-QUARANTINE.txt    Move hundreds of reviewed files from one checked plan, and undo it.
  CLEAN-REPLACEMENT.txt   Swap changed core, plugin and theme files for clean copies, and undo it.
  MANAGEMENT.txt          Report history, review notes and inventories.
  FILE-INVENTORY.txt      Compare file hashes between scans, and build a timeline.
  VULNERABILITIES.txt     Find the way in: check installed versions for known vulnerabilities.
  CHECKLIST.txt           Post-incident checklist: salts, passwords, sessions, caches, reinfection.
  PERSISTENCE.txt         Startup files and account crontab.
  DATABASE-CONTENT.txt    Replace one post's content, with a guarded restore.
  DATABASE-INVENTORY.txt  Offline check of database backups.
  DATABASE-VERIFY.txt     Check a recorded database operation against live data.
  PACKAGE-CHECK.txt       Confirm an upload matches the release.

WHAT IS NEW IN 0.24

- Find the way in: installed core, plugin and theme versions are checked against the
  Wordfence Intelligence vulnerability feed, with the version that fixes each one.
  Needs a free API key. Every report now lists the installed versions. See
  VULNERABILITIES.txt.
- Post-incident checklist, built from a scan: closing the way in, rotating salts and
  passwords, ending sessions, clearing caches and watching for reinfection. See
  CHECKLIST.txt.
- File inventories record permissions, owners and dates. A new timeline shows
  activity by day, bulk changes and unusual files, and file-changes lists permission
  and owner changes. See FILE-INVENTORY.txt.
- sentinel-remote.py on Linux and Mac stops after 30 seconds on a port that does
  not answer as SSH. On Windows, where that setting delays every connection, it is
  no longer used.

WHAT IS NEW IN 0.23

- A flagged file that matches its official copy now drops to info, marked "Verified
  official", when --core, --plugins or --themes runs.
- The rule for remote includes no longer fires on plain text in comments.
- MIT licence added. Self-test commands, which relied on programs not in this package,
  have been removed.

WHAT IS NEW IN 0.22

- replace-plan fetches verified clean copies of core, plugin and theme files named in a
  report. replace-apply swaps them in after backing up the originals, and replace-undo
  puts the originals back.
- --themes compares themes with their WordPress.org copies when scanning. It also works
  with sentinel-remote.py.
- Files named with unusual line separators no longer break a batch plan.

WHAT IS NEW IN 0.21

- batch-plan turns a report into a list of files to quarantine, which you can check
  and edit. Files WordPress needs are left out unless you ask for them.
- batch-quarantine applies that exact list, in stages if you like. If it is
  interrupted, running it again carries on.
- batch-restore undoes all of it, or only the files you choose.

WHAT IS NEW IN 0.20

- sentinel-remote.py discover lists every WordPress install on the account.
- sentinel-remote.py scan-all scans each one, with an account summary page and one
  combined alert. It also reports installs that appear or disappear.
- Nested installs are scanned once, as their own site.

WHAT IS NEW IN 0.19

- Alerts by email or webhook, only for new or changed findings, new coverage gaps and
  failed runs. A failed delivery is tried again on the next run.
- Database checks can run without a prompt: --db-from-wp-config or --db-credentials.
- --unattended for scheduled runs from your own computer.
- prune and --prune-keep remove older reports. Preview first; nothing is removed
  unless you ask.
- DB_HOST values with a port or socket now work, when prompted as well.

WHAT IS NEW IN 0.18

Detection
- Rules now live in rules.json, about eight times as many file rules as before.
- wp-config.php and .env files are now scanned in memory. Their contents are never
  saved. Files merely named like them are no longer skipped.
- New location checks: PHP in uploads whatever it contains, unknown PHP in the site
  root, double extensions, hidden PHP, and symlinks leaving the site.
- Oversized files are noted, and both ends are checked.
- Database checks now cover comments, commentmeta, termmeta and multisite subsites,
  plus site URLs, active plugins, cron hooks, admin accounts, triggers and events.

Reports
- report.html is sorted by priority and filterable, and shows finding numbers,
  hashes, database context and ready-to-copy preview commands.
- --fail-on makes a scan exit 4 when findings reach a chosen priority.
- --core-version auto reads the installed version.

Fixes
- A skipped folder now only affects comparisons inside that folder.
- A damaged report no longer stops "summary".
- "changes" no longer stops on repeated findings for one file.
- Plugin checksums with several accepted values are understood.
- file-restore now checks --sha256 when it is given.
- Reference folder names may contain dots.
- --db-row-limit, --db-value-limit, --max-files and --php work through sentinelctl.
- Database helpers retry with only mysqli loaded if php -n leaves it unavailable.

Finding numbers now follow priority order in new reports. Existing reports and
review notes keep working. An earlier inventory's excluded configuration files show
as "unknown" the first time they are compared with a new one.
