<?php
// Explicit post_content replacement only. Never boots WordPress.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
ini_set('display_errors', '0'); ini_set('log_errors', '0');
$db = null; $transaction = false; $stage = 'input';
function fail_safe($message) { throw new RuntimeException($message); }
function snapshot($row) {
    $out = [];
    foreach ($row as $key => $value) { $out[$key] = $value === null ? null : base64_encode((string)$value); }
    ksort($out);
    return $out;
}
function fingerprint($row) { return hash('sha256', json_encode(snapshot($row), JSON_THROW_ON_ERROR)); }
function get_row($db, $table, $id, $lock) {
    $r = $db->query("SELECT * FROM `$table` WHERE ID = $id" . ($lock ? ' FOR UPDATE' : ''));
    if ($r->num_rows !== 1) { fail_safe('record-not-found'); }
    return $r->fetch_assoc();
}
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
try {
    if (!function_exists('mysqli_init')) { fail_safe('mysqli-unavailable'); }
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $cfg = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    if (!in_array($cfg['action'], ['replace', 'restore', 'verify'], true) || !preg_match('/^[A-Za-z0-9_]+$/D', $cfg['prefix'])) { fail_safe('invalid-request'); }
    $table = $cfg['prefix'] . 'posts';
    if (strlen($table) > 64 || !preg_match('/^[1-9][0-9]{0,17}$/D', (string)$cfg['post_id'])) { fail_safe('invalid-request'); }
    $id = $cfg['post_id'];
    $apply = $cfg['apply'] === true;
    if ($cfg['action'] === 'verify' && $apply) { fail_safe('invalid-request'); }
    $folder = $cfg['folder'] ?? null;
    $stage = 'connect';
    $db = mysqli_init(); $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10);
    $db->real_connect($cfg['host'], $cfg['user'], $cfg['password'], $cfg['database']);
    unset($cfg['password']);
    $db->set_charset('utf8mb4');
    $db->query('SET SESSION innodb_lock_wait_timeout = 10');
    $stage = 'validate-table';
    $stmt = $db->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?');
    $stmt->bind_param('s', $table); $stmt->execute(); $stmt->bind_result($engine); $found = $stmt->fetch(); $stmt->close();
    if (!$found || strtoupper($engine) !== 'INNODB') { fail_safe('transactional-table-required'); }
    // Reject triggers: an apparently single-column write must not invoke unknown side effects.
    $stmt = $db->prepare('SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = ?');
    $stmt->bind_param('s', $table); $stmt->execute(); $stmt->bind_result($triggerCount); $stmt->fetch(); $stmt->close();
    if ($triggerCount) { fail_safe('table-triggers-unsupported'); }
    $keys = $db->query("SHOW KEYS FROM `$table` WHERE Key_name = 'PRIMARY'");
    $key = $keys->fetch_assoc();
    if ($keys->num_rows !== 1 || $key['Column_name'] !== 'ID') { fail_safe('unsupported-primary-key'); }
    $stage = 'read-record';
    if ($cfg['action'] === 'verify') { $db->query('START TRANSACTION READ ONLY'); }
    else { $db->begin_transaction(); }
    $transaction = true;
    $row = get_row($db, $table, $id, $apply);
    foreach (['post_content', 'post_type', 'post_status', 'post_modified', 'post_modified_gmt'] as $column) {
        if (!array_key_exists($column, $row)) { fail_safe('unsupported-schema'); }
    }
    if ($cfg['action'] !== 'verify' && !in_array($row['post_type'], ['post', 'page'], true)) { fail_safe('unsupported-post-type'); }
    if ($cfg['action'] !== 'verify' && !in_array($row['post_status'], ['publish', 'draft', 'pending', 'private', 'future'], true)) { fail_safe('unsupported-post-status'); }
    $original = $row['post_content'];
    if (strlen($original) > 4194304 || strlen(json_encode(snapshot($row))) > 8388608) { fail_safe('record-size-limit'); }
    $currentHash = hash('sha256', $original); $rowHash = fingerprint($row);
    $databaseIdentity = hash('sha256', $cfg['host'] . "\0" . $cfg['database'] . "\0" . $table);
    $record = null;
    if ($cfg['action'] === 'replace') {
        $replacement = base64_decode($cfg['replacement_base64'], true);
        if ($replacement === false || strlen($replacement) > 4194304 || !preg_match('//u', $replacement)) { fail_safe('invalid-replacement'); }
        if ($replacement === $original) { fail_safe('replacement-is-unchanged'); }
        if (preg_match('/^(?:a:\d+:\{|O:\d+:|C:\d+:|s:\d+:|b:[01];|i:-?\d+;|N;)/', ltrim($original))) { fail_safe('serialized-content-unsupported'); }
        $replacementHash = hash('sha256', $replacement);
    } else {
        if (!is_dir($folder) || is_link($folder) || is_link($folder . '/record.json') || is_link($folder . '/original.bin')) { fail_safe('invalid-backup'); }
        if (filesize($folder . '/record.json') > 12582912 || filesize($folder . '/original.bin') > 4194304) { fail_safe('backup-size-limit'); }
        $record = json_decode(file_get_contents($folder . '/record.json'), true, 512, JSON_THROW_ON_ERROR);
        if ($record['format'] !== 'sentinel-db-content-1' || $record['database_identity'] !== $databaseIdentity || (string)$record['post_id'] !== (string)$id || $record['site_root'] !== $cfg['site_root']) { fail_safe('backup-identity-mismatch'); }
        $replacement = file_get_contents($folder . '/original.bin');
        if (!hash_equals($record['original_sha256'], hash('sha256', $replacement))) { fail_safe('backup-integrity-failed'); }
        if ($cfg['action'] === 'verify') {
            $matchesOriginal = hash_equals($record['original_sha256'], $currentHash) && hash_equals($record['original_row_sha256'], $rowHash);
            $matchesReplacement = hash_equals($record['replacement_sha256'], $currentHash) && hash_equals($record['expected_replaced_row_sha256'], $rowHash);
            $state = $matchesOriginal ? 'matches-original-row' : ($matchesReplacement ? 'matches-replacement-row' : 'differs-from-both-recorded-states');
            $db->rollback(); $transaction = false;
            echo json_encode(['action' => 'verify', 'status' => 'verified-read', 'live_state' => $state,
                              'post_id' => (string)$id, 'table' => $table, 'content_sha256' => $currentHash, 'row_sha256' => $rowHash,
                              'content_matches_original' => hash_equals($record['original_sha256'], $currentHash),
                              'content_matches_replacement' => hash_equals($record['replacement_sha256'], $currentHash),
                              'note' => 'Read-only database snapshot. No content changed and no cache operations performed. State can change after this read.']);
            $db->close(); exit;
        }
        if (!hash_equals($record['replacement_sha256'], $currentHash) || !hash_equals($record['expected_replaced_row_sha256'], $rowHash)) { fail_safe('record-changed-since-replacement'); }
        $replacementHash = hash('sha256', $replacement);
    }
    $preview = ['action' => $cfg['action'], 'status' => 'preview', 'post_id' => (string)$id, 'table' => $table,
                'content_sha256' => $currentHash, 'row_sha256' => $rowHash, 'replacement_sha256' => $replacementHash,
                'original_bytes' => strlen($original), 'replacement_bytes' => strlen($replacement),
                'note' => 'Selected post_content only. No rendering, cache purge, revision, or WordPress hooks.'];
    if (!$apply) { $db->rollback(); $transaction = false; echo json_encode($preview); $db->close(); exit; }
    if (!hash_equals($cfg['expected_sha256'] ?? '', $currentHash) || !hash_equals($cfg['expected_row_sha256'] ?? '', $rowHash) || !hash_equals($cfg['expected_replacement_sha256'] ?? '', $replacementHash)) { fail_safe('reviewed-hash-mismatch'); }
    if (!is_dir($folder) || is_link($folder)) { fail_safe('invalid-private-folder'); }
    $stage = 'preserve-before-write';
    if ($cfg['action'] === 'replace') {
        $predicted = $row; $predicted['post_content'] = $replacement;
        $record = ['format' => 'sentinel-db-content-1', 'site_root' => $cfg['site_root'], 'database_identity' => $databaseIdentity,
                   'table' => $table, 'post_id' => (string)$id, 'original_sha256' => $currentHash,
                   'replacement_sha256' => $replacementHash, 'original_row_sha256' => $rowHash,
                   'expected_replaced_row_sha256' => fingerprint($predicted), 'original_row_base64' => snapshot($row),
                   'state' => 'prepared', 'created_utc' => gmdate('c')];
        save_private($folder . '/original.bin', $original);
        if (!hash_equals($currentHash, hash_file('sha256', $folder . '/original.bin'))) { fail_safe('backup-integrity-failed'); }
        save_state($folder, $record);
    }
    $stage = 'write';
    $stmt = $db->prepare("UPDATE `$table` SET post_content = ? WHERE ID = ?");
    $stmt->bind_param('ss', $replacement, $id); $stmt->execute(); $stmt->close();
    $after = get_row($db, $table, $id, false);
    $expected = $cfg['action'] === 'replace' ? $record['expected_replaced_row_sha256'] : $record['original_row_sha256'];
    if (!hash_equals($expected, fingerprint($after))) { fail_safe('post-write-row-mismatch'); }
    $db->commit(); $transaction = false;
    $stage = 'record-committed-state';
    $record['state'] = $cfg['action'] === 'replace' ? 'content-replaced' : 'restored';
    $record['last_operation_utc'] = gmdate('c'); save_state($folder, $record);
    $preview['status'] = $record['state'];
    $preview['note'] = 'Database operation committed. Clear relevant WordPress/object/page/CDN caches through trusted controls before resuming traffic. Preserved backup remains.';
    echo json_encode($preview); $db->close();
} catch (Throwable $error) {
    if ($transaction && $db) { try { $db->rollback(); } catch (Throwable $ignored) {} }
    $safe = ['mysqli-unavailable','invalid-request','transactional-table-required','table-triggers-unsupported','unsupported-primary-key','record-not-found','unsupported-schema','unsupported-post-type','unsupported-post-status','record-size-limit','invalid-replacement','replacement-is-unchanged','serialized-content-unsupported','invalid-backup','backup-size-limit','backup-identity-mismatch','backup-integrity-failed','record-changed-since-replacement','reviewed-hash-mismatch','invalid-private-folder','post-write-row-mismatch','backup-path-already-exists','backup-write-failed','backup-flush-failed','state-write-failed'];
    $category = in_array($error->getMessage(), $safe, true) ? $error->getMessage() : 'database-operation-failed';
    echo json_encode(['status' => 'failed', 'stage' => $stage, 'category' => $category, 'code' => (int)$error->getCode(),
                      'note' => 'Inspect preserved evidence before retrying. A failure during state recording can follow a successful database commit. Raw server error text is omitted.']);
    exit(1);
}
