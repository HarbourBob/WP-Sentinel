# WP Sentinel 0.25.0-rc1: Feature List

> **Back up your site first, if at all possible.** Keep the backup away from the website.

WP Sentinel scans WordPress sites over SSH for signs of compromise, and helps you deal
with what it finds. It uses the Python standard library, plus PHP CLI for database checks.
It never loads WordPress or runs site code. Nothing on the site changes unless you
preview a change and then apply it.

This is new, largely untested software with no guarantees. See [Known limits](#known-limits).

## File scanning

- **Pattern rules:** 31 file rules in an editable `rules.json`. They look for decoded
  execution, obfuscated code, droppers, request-driven includes, and suspicious
  `.htaccess` handlers and redirects.
- **Location checks:** PHP in uploads, unknown PHP in the site root or directly in
  `wp-content`, double extensions, hidden PHP, stray config files, and symlinks leaving
  the site.
- **Secrets stay private:** `wp-config.php` and `.env` files are scanned in memory. Only
  rule names, line numbers and hashes are recorded.
- **Image checks:** images are checked for PHP markers. Short PHP-like bytes found only
  inside the compressed data of a structurally valid PNG or WebP drop to info. Image
  contents are not decoded.
- **Large files:** oversized files are noted, and both ends are still checked.

## Integrity checks

- **WordPress core:** compared with official checksums, and the installed version can be
  detected automatically.
- **Plugins:** compared with the checksums published by WordPress.org.
- **Themes:** compared with their WordPress.org copies.
- **Premium and custom code:** compared with trusted ZIP files you supply.
- **Verified official:** a flagged file that matches its official copy drops to info, so
  false alarms in genuine plugins stay out of the way.

## Database scanning

- **Content:** scripts, PHP, hidden iframes and links, and encoded execution in posts,
  options, metadata and comments, including multisite subsites.
- **Settings:** admin accounts, site URLs, active plugins and scheduled hooks.
- **Database objects:** triggers, events and routines.
- **Credentials:** prompted for, read from `wp-config.php` as text, or read from a private
  file. They are never saved in reports.

## Startup locations

- Must-use plugins, drop-ins, `.htaccess`, `.user.ini` and `php.ini`.
- The account crontab, where the host provides one.

## Reports

- **HTML:** one self-contained page, sorted by priority and filterable, with hashes,
  database context and ready-to-copy preview commands.
- **JSON:** the same results for other tools to read.
- **Exit codes:** separate codes for coverage gaps, `--fail-on` matches and failed alerts.

## Finding the way in

- **Known vulnerabilities:** installed core, plugin and theme versions are checked against
  the Wordfence Intelligence feed, with the version that fixes each one. Needs a free API
  key; the feed is cached for a day.

## Fixing problems

- **Post-incident checklist:** built from a scan. It covers closing the way in, rotating
  salts and passwords, ending sessions, clearing caches and watching for reinfection,
  and names what that scan found.

Every action below previews first and needs `--apply` to make a change.

- **Single-file quarantine:** hash-checked, backed up, verified and restorable.
- **Batch quarantine:** one editable plan for hundreds of files. It can run in stages,
  resumes if interrupted, and leaves out files WordPress needs unless you ask for them.
  Undo all of it or only the files you choose.
- **Clean replacement:** fetches verified clean copies of core, plugin and theme files,
  swaps them in atomically, puts back missing files, and can be undone.
- **Post content replacement:** experimental, with a guarded restore.
- **Database records:** offline checks of database backups, and checks of a recorded
  operation against live data.

## Running remotely

- **From your own computer:** `sentinel-remote.py` works over SSH, removes the program from
  the host after each run, and keeps the evidence off the host.
- **From a window (prototype):** `sentinel-app.py` runs the same scan without the command
  line: fill in the SSH details, test the connection, scan, and open the results.
- **Quarantine from your computer:** make a list from a saved scan, untick what to keep,
  check it, then move the files out and put them back, with nothing left installed on
  the host. From the command line or the app's Quarantine window.
- **Whole account:** `discover` finds every WordPress install. `scan-all` scans each one,
  with a summary page and one combined alert, and reports installs that appear or
  disappear.

## Monitoring

- **Routine checks:** run on your own schedule, unattended if you like.
- **Alerts:** by email or webhook, only for new or changed findings, new coverage gaps and
  failed runs. A failed delivery is tried again on the next run.
- **Report cleanup:** removes older reports, with a preview first. Quarantine stores and
  review notes are never touched.

## Review and history

- **Review notes:** tied to a file's hash, so a note stops applying if the file changes.
- **Comparisons:** see what changed between scans, including permission and owner changes.
- **Timeline:** file dates, permissions and owners from each inventory, with activity by
  day and flags for world-writable files, unexpected owners and dates that look set back.
- **Inventories:** summaries, report history and quarantine inventories.
- **Package check:** confirms an upload matches the release. It checks consistency and is
  not a digital signature.

## Known limits

- New and largely untested, with no guarantees. It has been run on one real site.
- How much real malware the rules catch has not been measured.
- A report with no findings is not proof that a site is clean.
- Quarantined files stay on the hosting account, where an attacker with access to that
  account can reach them.
- Not covered: running processes, server configuration, and scheduled jobs that exist only
  in a hosting panel.

## Not built yet

Ideas and forks are welcome. See [Contributing](README.md#contributing).
