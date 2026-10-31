<?php
// CLI-only helper. Never loads WordPress. Uses only read statements.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
ini_set('display_errors', '0');
ini_set('log_errors', '0');
$stage = 'input';
function site_host($url) {
    $host = strtolower((string)parse_url(trim((string)$url), PHP_URL_HOST));
    return strpos($host, 'www.') === 0 ? substr($host, 4) : $host;
}
function state_finding($table, $name, $rule, $severity, $reason, $hashed, $context) {
    return ['source' => 'database', 'location' => "$table:option_name=$name", 'severity' => $severity, 'rule' => $rule, 'reason' => $reason, 'line' => null,
            'sha256' => hash('sha256', $hashed), 'content_complete' => true, 'hash_scope' => 'Normalized value described by this finding', 'context' => $context];
}
try {
    if (!function_exists('mysqli_init')) { throw new Exception('missing extension'); }
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $cfg = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    if (!preg_match('/^[A-Za-z0-9_]+$/D', $cfg['prefix'])) { throw new Exception('prefix'); }
    $limit = (int)$cfg['limit'];
    $valueLimit = (int)($cfg['value_limit'] ?? 65536);
    if ($valueLimit < 65536 || $valueLimit > 4194304) { throw new Exception('value limit'); }
    if ($limit < 1 || $limit > 100000) { throw new Exception('limit'); }
    $rules = $cfg['rules'] ?? null;
    if (!is_array($rules) || !$rules) { throw new Exception('rules'); }
    foreach ($rules as $rule) {
        if (@preg_match($rule['pattern'], '') === false) { throw new Exception('rule pattern'); }
    }
    $stage = 'connect';
    $db = mysqli_init();
    $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10);
    $db->real_connect($cfg['host'], $cfg['user'], $cfg['password'], $cfg['database'], $cfg['port'] ?? null, $cfg['socket'] ?? null);
    unset($cfg['password']);
    $stage = 'charset';
    $db->set_charset('utf8mb4');
    $findings = []; $limitations = []; $counts = []; $partial = false; $regexErrors = 0; $sites = [];
    try {
        $db->query('SET SESSION TRANSACTION READ ONLY');
    } catch (Throwable $error) {
        $limitations[] = 'The database session could not be set to read-only; the helper still issues only read statements.';
    }
    $stage = 'queries';
    // Multisite subsites have their own tables: wp_2_posts, wp_3_options and so on.
    $prefix = $cfg['prefix'];
    $prefixes = [$prefix];
    try {
        $tables = $db->query("SHOW TABLES LIKE '" . $db->real_escape_string(addcslashes($prefix, '_%')) . "%'");
        while ($row = $tables->fetch_row()) {
            if (preg_match('/^' . preg_quote($prefix, '/') . '(\d+)_posts$/D', $row[0], $site)) { $prefixes[] = $prefix . $site[1] . '_'; }
        }
        $tables->free();
    } catch (Throwable $error) {
        $partial = true;
        $limitations[] = 'Could not list tables; multisite subsites were not discovered.';
    }
    if (count($prefixes) > 200) {
        $partial = true;
        $limitations[] = (count($prefixes) - 200) . ' multisite subsites were not inspected (limit 200).';
        $prefixes = array_slice($prefixes, 0, 200);
    }
    $definitions = [];
    foreach ($prefixes as $sitePrefix) {
        $definitions[$sitePrefix . 'posts'] = ['ID', 'post_content', ['post_type', 'post_status']];
        $definitions[$sitePrefix . 'options'] = ['option_id', 'option_value', ['option_name']];
        $definitions[$sitePrefix . 'postmeta'] = ['meta_id', 'meta_value', ['meta_key', 'post_id']];
        $definitions[$sitePrefix . 'comments'] = ['comment_ID', 'comment_content', ['comment_approved', 'comment_post_ID']];
        $definitions[$sitePrefix . 'commentmeta'] = ['meta_id', 'meta_value', ['meta_key']];
        $definitions[$sitePrefix . 'termmeta'] = ['meta_id', 'meta_value', ['meta_key']];
    }
    $definitions[$prefix . 'usermeta'] = ['umeta_id', 'meta_value', ['meta_key', 'user_id']];
    foreach ($definitions as $table => $columns) {
        [$id, $value, $contextColumns] = $columns;
        $isUsermeta = $table === $prefix . 'usermeta';
        $select = '';
        foreach ($contextColumns as $column) { $select .= ", `$column` AS `ctx_$column`"; }
        $count = 0; $last = 0; $truncated = 0;
        try {
            while ($count < $limit) {
                // Bound buffered data to roughly 4 MiB, allowing four-byte UTF-8.
                $batch = min(max(1, (int)(4194304 / ($valueLimit * 4))), $limit - $count);
                $rows = $db->query("SELECT `$id` AS rid, LEFT(`$value`, $valueLimit) AS val, CHAR_LENGTH(`$value`) AS size$select FROM `$table` WHERE `$id` > $last ORDER BY `$id` LIMIT $batch");
                if (!$rows->num_rows) { break; }
                while ($row = $rows->fetch_assoc()) {
                    $firstFinding = count($findings);
                    $last = (int)$row['rid']; $count++;
                    if ((int)$row['size'] > $valueLimit) {
                        $truncated++; $partial = true;
                        $limitations[] = "$table:$id=$last truncated: " . (int)$row['size'] . " characters; inspected first $valueLimit.";
                    }
                    $text = $row['val'] ?? '';
                    foreach ($rules as $spec) {
                        $matched = @preg_match($spec['pattern'], $text);
                        if ($matched === false) { $regexErrors++; $partial = true; continue; }
                        if ($matched) {
                            $findings[] = ['source' => 'database', 'location' => "$table:$id=$last", 'severity' => $spec['severity'], 'rule' => $spec['id'], 'reason' => $spec['reason'], 'line' => null];
                        }
                    }
                    if ($isUsermeta && preg_match('/s:13:"administrator";b:1;/', $text)) {
                        $findings[] = ['source' => 'database', 'location' => "$table:$id=$last", 'severity' => 'review', 'rule' => 'administrator-role-marker', 'reason' => 'Administrator capability marker. Verify the associated account is authorized; this is not a malware finding.', 'line' => null];
                    }
                    if ($firstFinding < count($findings)) {
                        $context = [];
                        foreach ($contextColumns as $column) { $context[$column] = substr((string)$row["ctx_$column"], 0, 191); }
                        if ($isUsermeta && isset($row['ctx_user_id'])) {
                            try {
                                $user = $db->query("SELECT user_login, user_registered FROM `{$prefix}users` WHERE ID = " . (int)$row['ctx_user_id'])->fetch_assoc();
                                $context['user_login'] = $user ? substr((string)$user['user_login'], 0, 60) : '(no matching user)';
                                $context['user_registered'] = $user ? (string)$user['user_registered'] : '';
                            } catch (Throwable $error) {
                                $context['user_login'] = '(could not read users table)';
                            }
                        }
                        for ($fi = $firstFinding; $fi < count($findings); $fi++) {
                            $findings[$fi]['sha256'] = hash('sha256', $text);
                            $findings[$fi]['content_complete'] = (int)$row['size'] <= $valueLimit;
                            $findings[$fi]['hash_scope'] = 'Selected column value as returned over the UTF-8 database connection';
                            $findings[$fi]['context'] = $context;
                        }
                    }
                }
                $rows->free();
            }
            if ($count === $limit) {
                $more = $db->query("SELECT `$id` FROM `$table` WHERE `$id` > $last LIMIT 1");
                if ($more->num_rows) { $partial = true; $limitations[] = "$table reached its row limit; later rows were not inspected."; }
                $more->free();
            }
            if ($truncated) { $limitations[] = "$table: $truncated values inspected only through the first $valueLimit characters."; }
            $counts[$table] = $count;
        } catch (Throwable $error) {
            $partial = true;
            $counts[$table] = $count;
            $code = (int)$error->getCode();
            $limitations[] = "$table inspection failed or was incomplete (database error code $code); check table existence and SELECT permission.";
        }
    }
    if ($regexErrors) { $limitations[] = "$regexErrors pattern checks could not finish on large or unusual values; those values were not fully checked."; }
    // Site state. Serialized values are read with patterns and never unserialized.
    $stage = 'state';
    foreach ($prefixes as $sitePrefix) {
        $table = $sitePrefix . 'options';
        $site = ['table' => $table, 'active_plugins' => []];
        try {
            $values = [];
            $rows = $db->query("SELECT option_name, LEFT(option_value, $valueLimit) AS val FROM `$table` WHERE option_name IN ('siteurl', 'home', 'active_plugins', 'cron')");
            while ($row = $rows->fetch_assoc()) { $values[$row['option_name']] = (string)$row['val']; }
            $rows->free();
            foreach (['siteurl', 'home'] as $name) {
                if (isset($values[$name])) {
                    $findings[] = state_finding($table, $name, 'wp-site-url', 'info', 'Recorded so a change between scans stands out.', trim($values[$name]), ['host' => substr(site_host($values[$name]), 0, 191)]);
                }
            }
            if (isset($values['siteurl'], $values['home']) && site_host($values['siteurl']) !== site_host($values['home'])) {
                $findings[] = state_finding($table, 'siteurl', 'site-url-host-mismatch', 'medium', 'siteurl and home point to different hosts. Attackers change these to redirect a site; some setups do this on purpose.', $values['siteurl'] . "\0" . $values['home'], ['siteurl_host' => substr(site_host($values['siteurl']), 0, 191), 'home_host' => substr(site_host($values['home']), 0, 191)]);
            }
            if (isset($values['active_plugins'])) {
                preg_match_all('/s:\d+:"([^"]*)"/', $values['active_plugins'], $found);
                $plugins = array_values(array_unique($found[1]));
                sort($plugins);
                $site['active_plugins'] = array_slice($plugins, 0, 1000);
                $findings[] = state_finding($table, 'active_plugins', 'wp-active-plugins', 'info', 'Active plugin list, recorded so a change between scans stands out.', json_encode($plugins, JSON_INVALID_UTF8_SUBSTITUTE), ['count' => count($plugins)]);
            }
            if (isset($values['cron'])) {
                preg_match_all('/s:\d+:"([^"]+)";a:\d+:\{s:32:"[a-f0-9]{32}";/', $values['cron'], $found);
                $hooks = array_values(array_unique($found[1]));
                sort($hooks);
                $findings[] = state_finding($table, 'cron', 'wp-cron-hooks', 'info', 'Scheduled WordPress hooks, recorded so a new hook between scans stands out.', json_encode($hooks, JSON_INVALID_UTF8_SUBSTITUTE), ['count' => count($hooks), 'hooks' => array_slice($hooks, 0, 200)]);
            }
        } catch (Throwable $error) {
            $partial = true;
            $limitations[] = "$table: site settings could not be read (database error code " . (int)$error->getCode() . ').';
        }
        $sites[] = $site;
    }
    // Code stored in the database itself. Bodies are hashed, not reported.
    $stage = 'stored-code';
    $storedCode = [
        'trigger' => "SELECT TRIGGER_NAME AS name, ACTION_STATEMENT AS body FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()",
        'event' => "SELECT EVENT_NAME AS name, EVENT_DEFINITION AS body FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE()",
        'routine' => "SELECT ROUTINE_NAME AS name, ROUTINE_DEFINITION AS body FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE()",
    ];
    foreach ($storedCode as $kind => $query) {
        try {
            $rows = $db->query($query);
            while ($row = $rows->fetch_assoc()) {
                $findings[] = ['source' => 'database', 'location' => 'database:' . $kind . '=' . substr((string)$row['name'], 0, 64), 'severity' => 'medium', 'rule' => 'db-stored-' . $kind,
                               'reason' => "Database $kind found. WordPress does not create these; a plugin may, and so can an attacker. Its body is not included in this report.", 'line' => null,
                               'sha256' => hash('sha256', (string)$row['body']), 'content_complete' => true, 'hash_scope' => 'Stored definition'];
            }
            $rows->free();
        } catch (Throwable $error) {
            $partial = true;
            $limitations[] = "Database {$kind}s could not be listed (database error code " . (int)$error->getCode() . ').';
        }
    }
    $limitations[] = 'Database checks cover selected content columns in posts, options, postmeta, comments, commentmeta, termmeta and usermeta for the supplied prefix and its numbered multisite subsites. Other custom tables, the sitemeta table and other prefixes are not inspected. Trigger, event and routine visibility depends on database privileges.';
    $limitations[] = 'Database values are not executed, unserialized, or included in the report. Checks are patterns only; malicious redirects, serialized payloads, and unauthorized accounts may escape detection.';
    $db->close();
    echo json_encode(['findings' => $findings, 'limitations' => $limitations, 'sites' => $sites, 'summary' => ['status' => $partial ? 'partial' : 'completed-within-stated-scope', 'value_character_limit' => $valueLimit, 'rows_inspected' => $counts]], JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
} catch (Throwable $error) {
    // Deliberately omit the raw exception message: it can expose account details.
    $code = (int)$error->getCode();
    $category = 'database-check-failed';
    if (!function_exists('mysqli_init')) { $category = 'mysqli-unavailable'; }
    elseif ($stage === 'input') { $category = 'invalid-input'; }
    elseif (in_array($code, [1044, 1045, 1698], true)) { $category = 'access-denied'; }
    elseif ($code === 1049) { $category = 'unknown-database'; }
    elseif (in_array($code, [2002, 2003, 2005], true)) { $category = 'connection-failed'; }
    echo json_encode(['error' => ['category' => $category, 'stage' => $stage, 'code' => $code]]);
    exit(1);
}
