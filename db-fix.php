<?php
// Removes chosen pieces of flagged code (script elements, hidden iframes, PHP blocks) from one
// database value, keeping the original for undo. Never boots WordPress. Preview unless apply is set.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
ini_set('display_errors', '0'); ini_set('log_errors', '0');
const KINDS = ['posts' => ['ID', 'post_content'], 'postmeta' => ['meta_id', 'meta_value'], 'options' => ['option_id', 'option_value'],
               'comments' => ['comment_ID', 'comment_content'], 'commentmeta' => ['meta_id', 'meta_value'], 'termmeta' => ['meta_id', 'meta_value']];
const MAX_VALUE = 4194304;
const SAFE = ['mysqli-unavailable', 'invalid-request', 'unsupported-entry', 'transactional-table-required', 'table-triggers-unsupported', 'unsupported-primary-key',
              'record-not-found', 'record-size-limit', 'entry-changed-since-list', 'nothing-to-remove', 'would-break-structure', 'serialized-value-unsupported',
              'serialized-objects-unsupported', 'reviewed-hash-mismatch', 'invalid-private-folder', 'invalid-backup', 'backup-identity-mismatch',
              'backup-integrity-failed', 'entry-changed-since-fix', 'post-write-row-mismatch', 'backup-path-already-exists', 'backup-write-failed',
              'backup-flush-failed', 'state-write-failed'];
$db = null; $transaction = false; $stage = 'input';
function fail_safe($message) { throw new RuntimeException($message); }
function snapshot($row) {
    $out = [];
    foreach ($row as $key => $value) { $out[$key] = $value === null ? null : base64_encode((string)$value); }
    ksort($out);
    return $out;
}
function fingerprint($row) { return hash('sha256', json_encode(snapshot($row), JSON_THROW_ON_ERROR)); }
function save_private($path, $bytes) {
    if (file_exists($path) || is_link($path)) { fail_safe('backup-path-already-exists'); }
    $f = fopen($path, 'xb');
    if (!$f) { fail_safe('backup-write-failed'); }
    try {
        if (fwrite($f, $bytes) !== strlen($bytes) || !fflush($f)) { fail_safe('backup-write-failed'); }
        if (function_exists('fsync') && !fsync($f)) { fail_safe('backup-flush-failed'); }
    } finally { fclose($f); }
    chmod($path, 0600);
}
function save_state($folder, $record) {
    $temporary = $folder . '/state-' . bin2hex(random_bytes(8)) . '.tmp';
    save_private($temporary, json_encode($record, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    if (!rename($temporary, $folder . '/record.json')) { fail_safe('state-write-failed'); }
}
function site_host($url) {
    $host = strtolower((string)parse_url(trim((string)$url), PHP_URL_HOST));
    return strpos($host, 'www.') === 0 ? substr($host, 4) : $host;
}
// "wp_postmeta:meta_id=165" as a table and row. Only the listed WordPress tables, by their own ID column.
function target($location, $prefix) {
    $tables = implode('|', array_keys(KINDS));
    if (!preg_match('/^(' . preg_quote($prefix, '/') . '(?:\d+_)?(' . $tables . ')):([A-Za-z_]+)=([1-9][0-9]{0,17})$/D', (string)$location, $m)) { fail_safe('unsupported-entry'); }
    [$idColumn, $valueColumn] = KINDS[$m[2]];
    if ($m[3] !== $idColumn || strlen($m[1]) > 64) { fail_safe('unsupported-entry'); }
    return ['table' => $m[1], 'id_column' => $idColumn, 'value_column' => $valueColumn, 'id' => $m[4]];
}
function get_row($db, $t, $lock) {
    $r = $db->query("SELECT * FROM `{$t['table']}` WHERE `{$t['id_column']}` = {$t['id']}" . ($lock ? ' FOR UPDATE' : ''));
    if ($r->num_rows !== 1) { fail_safe('record-not-found'); }
    return $r->fetch_assoc();
}
// The pieces this tool can remove, as [offset, length, kind], in order. Page builders keep HTML inside
// JSON, where quotes and slashes are escaped, so an optional backslash is allowed before them.
function find_fragments($text) {
    $patterns = ['script' => '~<script\b[^>]*>.*?<\\\\?/script\s*>~is',
                 'iframe' => '~<iframe\b[^>]*(?:\b(?:width|height)\s*=\s*\\\\?["\']?[01]\\\\?["\'\s>]|display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>(?:[^<]*<\\\\?/iframe\s*>)?~is',
                 'php' => '~<\?php\b.*?\?>~is'];
    $all = [];
    foreach ($patterns as $kind => $pattern) {
        if (preg_match_all($pattern, $text, $found, PREG_OFFSET_CAPTURE)) {
            foreach ($found[0] as [$match, $offset]) { $all[] = [$offset, strlen($match), $kind]; }
        }
    }
    usort($all, fn($a, $b) => $a[0] <=> $b[0]);
    $kept = []; $end = 0;
    foreach ($all as $item) {
        if ($item[0] >= $end) { $kept[] = $item; $end = $item[0] + $item[1]; }
    }
    return $kept;
}
// Whether a piece reaches outside the JSON string it sits in: removing it would then damage the structure.
function unescaped_quote($fragment) {
    for ($i = 0, $n = strlen($fragment); $i < $n; $i++) {
        if ($fragment[$i] === '\\') { $i++; } elseif ($fragment[$i] === '"') { return true; }
    }
    return false;
}
function is_json_text($text) {
    $start = ltrim($text);
    if ($start === '' || ($start[0] !== '[' && $start[0] !== '{')) { return false; }
    json_decode($text);
    return json_last_error() === JSON_ERROR_NONE;
}
// What one piece is: where a script loads from or which known service it belongs to, and how it starts.
// The labels match database.php's, so reports and lists describe scripts the same way.
function describe($fragment, $kind, $selfHosts) {
    $html = str_ireplace(['\\/', '\\"'], ['/', '"'], $fragment);
    $label = $kind; $warn = false;
    if ($kind === 'script' && preg_match('/^<script\b([^>]*)>(.*)$/is', $html, $tag)) {
        if (preg_match('/\bsrc\s*=\s*["\']?([^"\'\s>]+)/i', $tag[1], $src)) {
            $host = site_host(strpos($src[1], '//') === 0 ? 'https:' . $src[1] : $src[1]);
            $label = $host === '' ? 'src:(this site)' : (in_array($host, $selfHosts, true) ? 'self' : 'src:' . substr($host, 0, 100));
        } elseif (stripos($tag[1], 'ld+json') !== false) {
            $label = 'json-ld';
        } else {
            $known = ['gtag(' => 'gtag', 'googletagmanager.com/gtm' => 'gtm', 'datalayer' => 'datalayer', 'fbq(' => 'meta-pixel', 'hotjar' => 'hotjar',
                      'clarity.ms' => 'clarity', '_paq' => 'matomo', 'plausible' => 'plausible', 'adsbygoogle' => 'adsense', 'grecaptcha' => 'recaptcha',
                      'twttr' => 'twitter', 'elementorfrontendconfig' => 'elementor', 'wp.i18n' => 'wordpress', 'jquery(' => 'jquery'];
            $code = strtolower(substr($tag[2], 0, 20000));
            $label = 'inline';
            foreach ($known as $marker => $name) {
                if (strpos($code, $marker) !== false) { $label = 'inline:' . $name; break; }
            }
            $warn = (bool)preg_match('/\b(?:eval|atob|unescape)\s*\(|fromcharcode|document\.write\s*\(/', $code);
        }
    } elseif ($kind === 'iframe' && preg_match('/\bsrc\s*=\s*["\']?([^"\'\s>]+)/i', $html, $src)) {
        $host = site_host(strpos($src[1], '//') === 0 ? 'https:' . $src[1] : $src[1]);
        $label = 'iframe:' . ($host === '' ? '(this site)' : substr($host, 0, 100));
    }
    $excerpt = preg_replace('/[^\x20-\x7E]+/', ' ', substr($html, 0, 400));
    return ['label' => $label, 'warn' => $warn, 'excerpt' => substr(preg_replace('/\s+/', ' ', $excerpt), 0, 200), 'bytes' => strlen($fragment)];
}
// Text with the chosen pieces taken out. Every piece seen is noted in $found, chosen or not.
function clean_text($text, $remove, &$found, $selfHosts) {
    $json = is_json_text($text);
    $out = ''; $position = 0;
    foreach (find_fragments($text) as [$offset, $length, $kind]) {
        $fragment = substr($text, $offset, $length);
        $sha = hash('sha256', $fragment);
        $removable = !($json && unescaped_quote($fragment));
        if (!isset($found[$sha])) { $found[$sha] = ['sha256' => $sha, 'kind' => $kind, 'count' => 0, 'removable' => true] + describe($fragment, $kind, $selfHosts); }
        $found[$sha]['count']++;
        $found[$sha]['removable'] = $found[$sha]['removable'] && $removable;
        if ($removable && in_array($sha, $remove, true)) {
            $out .= substr($text, $position, $offset - $position);
            $position = $offset + $length;
        }
    }
    $out .= substr($text, $position);
    if ($json && $out !== $text && !is_json_text($out)) { fail_safe('would-break-structure'); }
    return $out;
}
// A stored value with the chosen pieces taken out. WordPress settings are often PHP-serialized, where every
// string carries its length, so those are unpacked, cleaned string by string and packed again. Values
// holding objects, or that do not pack back to exactly what was stored, are refused.
function clean_value($value, $remove, &$found, $selfHosts, $depth = 0) {
    if (!preg_match('/^(?:a:\d+:\{|O:\d+:"|C:\d+:"|s:\d+:")/', $value)) { return clean_text($value, $remove, $found, $selfHosts); }
    if ($depth > 4) { fail_safe('serialized-value-unsupported'); }
    $data = @unserialize($value, ['allowed_classes' => false, 'max_depth' => 64]);
    if ($data === false || serialize($data) !== $value) { fail_safe('serialized-value-unsupported'); }
    $walk = function ($item, $level = 0) use (&$walk, $remove, &$found, $selfHosts, $depth) {
        if ($level > 64) { fail_safe('serialized-value-unsupported'); }
        if (is_object($item)) { fail_safe('serialized-objects-unsupported'); }
        if (is_array($item)) {
            foreach ($item as $key => $inner) { $item[$key] = $walk($inner, $level + 1); }
            return $item;
        }
        return is_string($item) ? clean_value($item, $remove, $found, $selfHosts, $depth + 1) : $item;
    };
    return serialize($walk($data));
}
function value_format($value) {
    return preg_match('/^(?:a:\d+:\{|O:\d+:"|C:\d+:"|s:\d+:")/', $value) ? 'serialized' : (is_json_text($value) ? 'json' : 'text');
}
function validate_table($db, $t) {
    $stmt = $db->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?');
    $stmt->bind_param('s', $t['table']); $stmt->execute(); $stmt->bind_result($engine); $found = $stmt->fetch(); $stmt->close();
    if (!$found || strtoupper((string)$engine) !== 'INNODB') { fail_safe('transactional-table-required'); }
    // Reject triggers: an apparently single-column write must not invoke unknown side effects.
    $stmt = $db->prepare('SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = ?');
    $stmt->bind_param('s', $t['table']); $stmt->execute(); $stmt->bind_result($triggerCount); $stmt->fetch(); $stmt->close();
    if ($triggerCount) { fail_safe('table-triggers-unsupported'); }
    $keys = $db->query("SHOW KEYS FROM `{$t['table']}` WHERE Key_name = 'PRIMARY'");
    $key = $keys->fetch_assoc();
    if ($keys->num_rows !== 1 || $key['Column_name'] !== $t['id_column']) { fail_safe('unsupported-primary-key'); }
}
try {
    if (!function_exists('mysqli_init')) { fail_safe('mysqli-unavailable'); }
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $cfg = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    if (!in_array($cfg['action'] ?? '', ['inspect', 'fix', 'restore'], true) || !preg_match('/^[A-Za-z0-9_]+$/D', (string)($cfg['prefix'] ?? ''))) { fail_safe('invalid-request'); }
    $apply = ($cfg['apply'] ?? false) === true;
    $folder = $cfg['folder'] ?? null;
    $stage = 'connect';
    $db = mysqli_init(); $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10);
    $db->real_connect($cfg['host'], $cfg['user'], $cfg['password'], $cfg['database'], $cfg['port'] ?? null, $cfg['socket'] ?? null);
    unset($cfg['password']);
    $db->set_charset('utf8mb4');
    $db->query('SET SESSION innodb_lock_wait_timeout = 10');
    // The site's own addresses, so its own scripts are named as such.
    $selfHosts = [];
    try {
        $own = $db->query("SELECT option_value FROM `{$cfg['prefix']}options` WHERE option_name IN ('siteurl', 'home')");
        while ($row = $own->fetch_assoc()) { $selfHosts[] = site_host($row['option_value']); }
    } catch (Throwable $ignored) {
    }
    $selfHosts = array_values(array_filter(array_unique($selfHosts)));

    if ($cfg['action'] === 'inspect') {
        $stage = 'inspect';
        if (!is_array($cfg['targets'] ?? null) || count($cfg['targets']) > 500) { fail_safe('invalid-request'); }
        $db->query('START TRANSACTION READ ONLY'); $transaction = true;
        $entries = [];
        foreach ($cfg['targets'] as $location) {
            $entry = ['location' => (string)$location];
            try {
                $t = target($location, $cfg['prefix']);
                $row = get_row($db, $t, false);
                $value = (string)$row[$t['value_column']];
                if (strlen($value) > MAX_VALUE) { fail_safe('record-size-limit'); }
                $found = [];
                clean_value($value, [], $found, $selfHosts);
                $entry += ['value_sha256' => hash('sha256', $value), 'bytes' => strlen($value), 'format' => value_format($value), 'fragments' => array_values($found)];
            } catch (Throwable $error) {
                $entry['error'] = in_array($error->getMessage(), SAFE, true) ? $error->getMessage() : 'database-operation-failed';
            }
            $entries[] = $entry;
        }
        $db->rollback(); $transaction = false;
        echo json_encode(['action' => 'inspect', 'status' => 'inspected', 'entries' => $entries], JSON_THROW_ON_ERROR);
        $db->close(); exit;
    }

    $t = target($cfg['location'] ?? '', $cfg['prefix']);
    $stage = 'validate-table';
    validate_table($db, $t);
    $databaseIdentity = hash('sha256', $cfg['host'] . "\0" . $cfg['database'] . "\0" . $t['table']);
    $stage = 'read-record';
    $db->begin_transaction(); $transaction = true;
    $row = get_row($db, $t, $apply);
    $original = (string)$row[$t['value_column']];
    if (strlen($original) > MAX_VALUE) { fail_safe('record-size-limit'); }
    $currentHash = hash('sha256', $original);

    if ($cfg['action'] === 'fix') {
        if (!hash_equals((string)($cfg['expected_sha256'] ?? ''), $currentHash)) { fail_safe('entry-changed-since-list'); }
        $remove = array_values(array_filter((array)($cfg['remove'] ?? []), fn($h) => is_string($h) && preg_match('/^[a-f0-9]{64}$/D', $h)));
        $found = [];
        $replacement = clean_value($original, $remove, $found, $selfHosts);
        if ($replacement === $original) { fail_safe('nothing-to-remove'); }
        $record = null;
    } else {
        if (!is_string($folder) || !is_dir($folder) || is_link($folder) || is_link($folder . '/record.json') || is_link($folder . '/original.bin')) { fail_safe('invalid-backup'); }
        if (filesize($folder . '/record.json') > 1048576 || filesize($folder . '/original.bin') > MAX_VALUE) { fail_safe('invalid-backup'); }
        $record = json_decode(file_get_contents($folder . '/record.json'), true, 512, JSON_THROW_ON_ERROR);
        if (($record['format'] ?? '') !== 'sentinel-db-fix-1' || $record['database_identity'] !== $databaseIdentity || $record['table'] !== $t['table']
            || (string)$record['id'] !== (string)$t['id'] || $record['site_root'] !== ($cfg['site_root'] ?? null)) { fail_safe('backup-identity-mismatch'); }
        $replacement = file_get_contents($folder . '/original.bin');
        if (!hash_equals($record['original_sha256'], hash('sha256', $replacement))) { fail_safe('backup-integrity-failed'); }
        // Undo only what this tool wrote: if the value has been edited since, it is left alone.
        if (!hash_equals($record['replacement_sha256'], $currentHash)) { fail_safe('entry-changed-since-fix'); }
    }
    $replacementHash = hash('sha256', $replacement);
    $result = ['action' => $cfg['action'], 'status' => 'preview', 'location' => $cfg['location'], 'value_sha256' => $currentHash, 'new_sha256' => $replacementHash,
               'original_bytes' => strlen($original), 'new_bytes' => strlen($replacement)];
    if (!$apply) { $db->rollback(); $transaction = false; echo json_encode($result); $db->close(); exit; }
    if (!hash_equals((string)($cfg['expected_new_sha256'] ?? ''), $replacementHash)) { fail_safe('reviewed-hash-mismatch'); }
    if (!is_string($folder) || !is_dir($folder) || is_link($folder)) { fail_safe('invalid-private-folder'); }
    $stage = 'preserve-before-write';
    $predicted = $row; $predicted[$t['value_column']] = $replacement;
    if ($cfg['action'] === 'fix') {
        $record = ['format' => 'sentinel-db-fix-1', 'site_root' => $cfg['site_root'] ?? null, 'database_identity' => $databaseIdentity, 'table' => $t['table'],
                   'id_column' => $t['id_column'], 'id' => (string)$t['id'], 'value_column' => $t['value_column'], 'original_sha256' => $currentHash,
                   'replacement_sha256' => $replacementHash, 'removed' => $remove, 'state' => 'prepared', 'created_utc' => gmdate('c')];
        save_private($folder . '/original.bin', $original);
        if (!hash_equals($currentHash, hash_file('sha256', $folder . '/original.bin'))) { fail_safe('backup-integrity-failed'); }
        save_state($folder, $record);
    }
    $stage = 'write';
    $stmt = $db->prepare("UPDATE `{$t['table']}` SET `{$t['value_column']}` = ? WHERE `{$t['id_column']}` = ?");
    $stmt->bind_param('ss', $replacement, $t['id']); $stmt->execute(); $stmt->close();
    // Read it back inside the same transaction: nothing but that one value may differ.
    if (!hash_equals(fingerprint($predicted), fingerprint(get_row($db, $t, false)))) { fail_safe('post-write-row-mismatch'); }
    $db->commit(); $transaction = false;
    $stage = 'record-committed-state';
    $record['state'] = $cfg['action'] === 'fix' ? 'fixed' : 'restored';
    $record['last_operation_utc'] = gmdate('c'); save_state($folder, $record);
    $result['status'] = $record['state'];
    echo json_encode($result); $db->close();
} catch (Throwable $error) {
    if ($transaction && $db) { try { $db->rollback(); } catch (Throwable $ignored) {} }
    $category = in_array($error->getMessage(), SAFE, true) ? $error->getMessage() : 'database-operation-failed';
    echo json_encode(['status' => 'failed', 'stage' => $stage, 'category' => $category, 'code' => (int)$error->getCode(),
                      'note' => 'A failure during state recording can follow a successful database commit. Raw server error text is omitted.']);
    exit(1);
}
