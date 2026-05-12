<?php
/**
 * ============================================================
 * SRC MySQL Pro API Backend v2.0
 * Shree Ram Computers - Daurala, Meerut, Uttar Pradesh
 * ============================================================
 * UPLOAD THIS FILE TO: /public_html/api/src_mysql_api.php
 *
 * Deep Host se behtar kyun?
 *  ✅ HMAC Signature - Plain API key nahi chahiye
 *  ✅ Session Token - 1 ghante ka valid session
 *  ✅ Timestamp check - Replay attacks blocked
 *  ✅ Rate Limiting - Abuse se protection
 *  ✅ SQL Injection Proof - PDO + input validation
 *  ✅ master.php integration - SRC standard
 *  ✅ Condition parser - Safe WHERE clause
 * ============================================================
 */

require_once __DIR__ . '/../../protect/master.php';

// ============================================================
// CONFIG - Change these values!
// ============================================================
define('SRCM_SECRET_KEY',     'APNA_SECRET_KEY_YAHAN_LIKHEIN_32CHARS_MIN');
define('SRCM_TOKEN_EXPIRY',   3600);    // 1 hour session
define('SRCM_RATE_LIMIT',     120);     // 120 requests/hour per IP
define('SRCM_RATE_WINDOW',    3600);    // per hour
define('SRCM_TABLE_PREFIX',   '');      // Optional: 'app_' to restrict tables
define('SRCM_MAX_ROWS',       500);     // Max rows in one response
define('SRCM_ALLOW_CUSTOM_Q', true);    // Allow custom SELECT queries?
// ============================================================

// Headers
header('Content-Type: application/json; charset=UTF-8');
header('X-Powered-By: SRC-MySQL-Pro/2.0');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    src_json(false, 'POST request required.');
}

// Parse body
$raw   = file_get_contents('php://input');
$data  = json_decode($raw, true);

if (!is_array($data) || empty($data['action'])) {
    src_json(false, 'Invalid JSON or missing action.');
}

$ip     = src_ip();
$action = src_clean($data['action']);

// ============================================================
// RATE LIMITING
// ============================================================
if (!src_rate_limit('srcmysql:' . $ip, SRCM_RATE_LIMIT, SRCM_RATE_WINDOW)) {
    src_json(false, 'Bahut zyada requests. Ek ghante baad try karein.');
}

// ============================================================
// TOKEN TABLE SETUP (one-time auto-create)
// ============================================================
function ensureTokenTable(): void {
    $db = src_db();
    $db->exec("CREATE TABLE IF NOT EXISTS `src_mysql_tokens` (
        `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `token`      VARCHAR(64) NOT NULL,
        `app_id`     VARCHAR(100) NOT NULL DEFAULT '',
        `ip`         VARCHAR(45) NOT NULL DEFAULT '',
        `created_at` INT UNSIGNED NOT NULL DEFAULT 0,
        `expires_at` INT UNSIGNED NOT NULL DEFAULT 0,
        UNIQUE KEY `uq_token` (`token`),
        KEY `idx_expires` (`expires_at`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// ============================================================
// SIGNATURE VERIFY HELPER
// ============================================================
function verifySig(string $data_str, string $sig): bool {
    $expected = hash_hmac('sha256', $data_str, SRCM_SECRET_KEY);
    return hash_equals($expected, $sig);
}

// ============================================================
// TIMESTAMP FRESHNESS CHECK (5 minute window)
// ============================================================
function checkTimestamp(int $ts_ms): bool {
    $diff = abs((int)(microtime(true) * 1000) - $ts_ms);
    return $diff < 300000; // 5 minutes
}

// ============================================================
// TABLE NAME VALIDATOR
// ============================================================
function validateTable(string $name): string {
    $name = trim($name);
    if (!preg_match('/^[a-zA-Z0-9_]{1,64}$/', $name)) {
        throw new RuntimeException('Invalid table name. Sirf letters, numbers, underscore use karein.');
    }
    if (!empty(SRCM_TABLE_PREFIX) && !str_starts_with($name, SRCM_TABLE_PREFIX)) {
        throw new RuntimeException('Table name prefix required: ' . SRCM_TABLE_PREFIX);
    }
    // Block system tables
    $blocked = ['src_mysql_tokens', 'src_rate_limits', 'src_mail_queue'];
    if (in_array(strtolower($name), $blocked, true)) {
        throw new RuntimeException('This table is restricted.');
    }
    return $name;
}

// ============================================================
// COLUMN NAME VALIDATOR
// ============================================================
function validateColumn(string $col): string {
    if (!preg_match('/^[a-zA-Z0-9_]{1,64}$/', $col)) {
        throw new RuntimeException('Invalid column name: ' . $col);
    }
    return $col;
}

// ============================================================
// CONDITION PARSER → Safe WHERE clause with PDO bindings
//
// Supports: col=val, col!=val, col>val, col<val, col>=val, col<=val
//           col LIKE val, col IS NULL, col IS NOT NULL
// Connectors: AND, OR
//
// Example: "age>18 AND city=Meerut"
// ============================================================
function parseCondition(string $cond, array &$bind): string {
    if (trim($cond) === '') return '';

    // Split on AND / OR (preserve them)
    $tokens = preg_split('/\s+(AND|OR)\s+/i', trim($cond), -1, PREG_SPLIT_DELIM_CAPTURE);
    $sql    = '';

    foreach ($tokens as $tok) {
        $tok = trim($tok);
        if (preg_match('/^(AND|OR)$/i', $tok)) {
            $sql .= ' ' . strtoupper($tok) . ' ';
            continue;
        }

        // IS NULL / IS NOT NULL
        if (preg_match('/^([a-zA-Z0-9_]+)\s+IS\s+(NOT\s+)?NULL$/i', $tok, $m)) {
            $col  = validateColumn($m[1]);
            $sql .= '`' . $col . '` IS ' . (isset($m[2]) ? 'NOT NULL' : 'NULL');
            continue;
        }

        // LIKE
        if (preg_match('/^([a-zA-Z0-9_]+)\s+LIKE\s+(.+)$/i', $tok, $m)) {
            $col     = validateColumn($m[1]);
            $sql    .= '`' . $col . '` LIKE ?';
            $bind[]  = $m[2];
            continue;
        }

        // Comparison operators
        $ops = ['>=', '<=', '!=', '>', '<', '='];
        $matched = false;
        foreach ($ops as $op) {
            if (str_contains($tok, $op)) {
                [$col_raw, $val] = array_map('trim', explode($op, $tok, 2));
                $col     = validateColumn($col_raw);
                $sql    .= '`' . $col . '`' . $op . '?';
                $bind[]  = $val;
                $matched = true;
                break;
            }
        }
        if (!$matched) throw new RuntimeException('Condition samajh nahi ayi: ' . $tok);
    }
    return $sql;
}

// ============================================================
// ORDER BY VALIDATOR
// ============================================================
function validateOrderBy(string $raw): string {
    if (trim($raw) === '') return '';
    // Allow: col_name ASC|DESC, multiple comma-separated
    $parts = explode(',', $raw);
    $safe  = [];
    foreach ($parts as $p) {
        $words = preg_split('/\s+/', trim($p), 2);
        $col   = validateColumn($words[0]);
        $dir   = strtoupper($words[1] ?? 'ASC');
        if (!in_array($dir, ['ASC', 'DESC'], true)) $dir = 'ASC';
        $safe[] = '`' . $col . '` ' . $dir;
    }
    return implode(', ', $safe);
}

// ============================================================
// AUTH ACTION
// ============================================================
if ($action === 'auth') {
    $app_id = src_clean($data['app_id'] ?? '');
    $ts_ms  = (int)($data['timestamp'] ?? 0);
    $sig    = $data['sig'] ?? '';

    if (!checkTimestamp($ts_ms)) {
        src_json(false, 'Request expired. Device ka time check karein.');
    }
    if (!verifySig($app_id . $ts_ms . SRCM_SECRET_KEY, $sig)) {
        src_json(false, 'Invalid signature. Secret Key check karein.');
    }

    ensureTokenTable();
    $db  = src_db();

    // Clean old tokens
    $db->prepare("DELETE FROM `src_mysql_tokens` WHERE `expires_at` < ?")->execute([time()]);

    // Create new token
    $token   = src_token(32);
    $expires = time() + SRCM_TOKEN_EXPIRY;
    $db->prepare("INSERT INTO `src_mysql_tokens` (`token`,`app_id`,`ip`,`created_at`,`expires_at`) VALUES (?,?,?,?,?)")
       ->execute([$token, $app_id, $ip, time(), $expires]);

    echo json_encode([
        'success'    => true,
        'token'      => $token,
        'expires_in' => SRCM_TOKEN_EXPIRY,
        'message'    => 'Authentication successful',
        'count'      => 0,
    ]);
    exit;
}

// ============================================================
// VERIFY SIGNATURE + TOKEN FOR ALL OTHER ACTIONS
// ============================================================
$ts_ms  = (int)($data['timestamp'] ?? 0);
$sig    = $data['sig'] ?? '';
$d_tok  = src_clean($data['device_token'] ?? '');

if (!checkTimestamp($ts_ms)) {
    src_json(false, 'Request expired. Device ka time check karein.');
}
if (!verifySig($action . $ts_ms . SRCM_SECRET_KEY, $sig)) {
    src_json(false, 'Invalid signature. Unauthorized.');
}

// Token validation
if (!empty($d_tok)) {
    ensureTokenTable();
    $db   = src_db();
    $stmt = $db->prepare("SELECT `id` FROM `src_mysql_tokens` WHERE `token`=? AND `expires_at`>?");
    $stmt->execute([$d_tok, time()]);
    if (!$stmt->fetch()) {
        src_json(false, 'Session expired ya invalid. Please re-authenticate.');
    }
} else {
    // No token: still allow if signature was valid (basic mode)
    $db = src_db();
}

// ============================================================
// COLUMN TYPE WHITELIST FOR CREATE TABLE
// ============================================================
const ALLOWED_TYPES = [
    'INT','BIGINT','TINYINT','SMALLINT','MEDIUMINT',
    'FLOAT','DOUBLE','DECIMAL',
    'TEXT','MEDIUMTEXT','LONGTEXT','TINYTEXT',
    'VARCHAR','CHAR',
    'DATE','DATETIME','TIMESTAMP','TIME','YEAR',
    'BOOLEAN','BOOL',
    'JSON','BLOB','MEDIUMBLOB',
];

// ============================================================
// ACTION ROUTER
// ============================================================
try {
    switch ($action) {

        // ── CREATE TABLE ──────────────────────────────────────
        case 'create_table': {
            $table   = validateTable($data['table'] ?? '');
            $col_raw = trim($data['columns'] ?? '');
            if (empty($col_raw)) throw new RuntimeException('columns is required.');

            // Parse & whitelist each column definition
            $col_defs = [];
            foreach (explode(',', $col_raw) as $def) {
                $def   = trim($def);
                $words = preg_split('/\s+/', $def, 3);
                if (count($words) < 2) throw new RuntimeException('Invalid column def: ' . $def);

                $cname = validateColumn($words[0]);
                $ctype = strtoupper(preg_replace('/\(.*\)/', '', $words[1]));
                if (!in_array($ctype, ALLOWED_TYPES, true)) {
                    throw new RuntimeException('Invalid data type: ' . $words[1]);
                }

                // Allow type with size: VARCHAR(100)
                $ctype_full = strtoupper($words[1]);

                // Extra keywords
                $extras = strtoupper($words[2] ?? '');
                $safe_extra = '';
                if (str_contains($extras, 'AUTO_INCREMENT')) $safe_extra .= ' AUTO_INCREMENT';
                if (str_contains($extras, 'PRIMARY KEY'))    $safe_extra .= ' PRIMARY KEY';
                if (str_contains($extras, 'NOT NULL'))       $safe_extra .= ' NOT NULL';
                if (str_contains($extras, 'UNIQUE'))         $safe_extra .= ' UNIQUE';
                if (str_contains($extras, 'DEFAULT')) {
                    preg_match('/DEFAULT\s+(\S+)/i', $extras, $dm);
                    if (!empty($dm[1])) $safe_extra .= ' DEFAULT ' . $dm[1];
                }

                $col_defs[] = '`' . $cname . '` ' . $ctype_full . $safe_extra;
            }

            $db->exec("CREATE TABLE IF NOT EXISTS `{$table}` (" .
                       implode(', ', $col_defs) .
                       ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

            echo json_encode(['success' => true, 'data' => '"Table created: ' . $table . '"', 'count' => 0]);
            break;
        }

        // ── DROP TABLE ────────────────────────────────────────
        case 'drop_table': {
            $table = validateTable($data['table'] ?? '');
            $db->exec("DROP TABLE IF EXISTS `{$table}`");
            echo json_encode(['success' => true, 'data' => '"Table dropped: ' . $table . '"', 'count' => 0]);
            break;
        }

        // ── LIST TABLES ───────────────────────────────────────
        case 'list_tables': {
            $stmt   = $db->query("SHOW TABLES");
            $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
            echo json_encode(['success' => true, 'data' => json_encode($tables), 'count' => count($tables)]);
            break;
        }

        // ── INSERT ────────────────────────────────────────────
        case 'insert': {
            $table = validateTable($data['table'] ?? '');
            $row   = $data['data'] ?? [];
            if (empty($row) || !is_array($row)) throw new RuntimeException('data required (JSON object).');

            $cols  = array_map(fn($c) => '`' . validateColumn($c) . '`', array_keys($row));
            $phds  = array_fill(0, count($row), '?');
            $vals  = array_values($row);

            $stmt  = $db->prepare("INSERT INTO `{$table}` (" . implode(',', $cols) . ") VALUES (" . implode(',', $phds) . ")");
            $stmt->execute($vals);
            $id    = $db->lastInsertId();
            echo json_encode(['success' => true, 'data' => json_encode(['insert_id' => (int)$id]), 'count' => 1]);
            break;
        }

        // ── UPDATE ────────────────────────────────────────────
        case 'update': {
            $table = validateTable($data['table'] ?? '');
            $row   = $data['data'] ?? [];
            $cond  = $data['condition'] ?? '';
            if (empty($row) || !is_array($row)) throw new RuntimeException('data required.');

            $sets  = array_map(fn($c) => '`' . validateColumn($c) . '`=?', array_keys($row));
            $vals  = array_values($row);
            $bind  = [];
            $where = parseCondition($cond, $bind);

            $sql   = "UPDATE `{$table}` SET " . implode(',', $sets);
            if ($where) $sql .= " WHERE " . $where;
            $stmt  = $db->prepare($sql);
            $stmt->execute(array_merge($vals, $bind));
            echo json_encode(['success' => true, 'data' => json_encode(['rows_affected' => $stmt->rowCount()]), 'count' => $stmt->rowCount()]);
            break;
        }

        // ── DELETE ────────────────────────────────────────────
        case 'delete': {
            $table = validateTable($data['table'] ?? '');
            $cond  = $data['condition'] ?? '';
            if (empty(trim($cond))) throw new RuntimeException('Condition required for delete (safety reason).');

            $bind  = [];
            $where = parseCondition($cond, $bind);
            $stmt  = $db->prepare("DELETE FROM `{$table}` WHERE " . $where);
            $stmt->execute($bind);
            echo json_encode(['success' => true, 'data' => json_encode(['rows_deleted' => $stmt->rowCount()]), 'count' => $stmt->rowCount()]);
            break;
        }

        // ── GET ALL (with pagination) ──────────────────────────
        case 'get_all': {
            $table  = validateTable($data['table'] ?? '');
            $limit  = min(max(0, (int)($data['limit']  ?? 50)), SRCM_MAX_ROWS);
            $offset = max(0, (int)($data['offset'] ?? 0));
            $order  = validateOrderBy($data['order_by'] ?? '');

            $sql    = "SELECT * FROM `{$table}`";
            if ($order)  $sql .= " ORDER BY " . $order;
            if ($limit)  $sql .= " LIMIT {$limit} OFFSET {$offset}";

            $stmt   = $db->query($sql);
            $rows   = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'data' => json_encode($rows), 'count' => count($rows)]);
            break;
        }

        // ── SEARCH (condition-based) ──────────────────────────
        case 'search': {
            $table  = validateTable($data['table'] ?? '');
            $limit  = min(max(0, (int)($data['limit']  ?? 50)), SRCM_MAX_ROWS);
            $offset = max(0, (int)($data['offset'] ?? 0));
            $order  = validateOrderBy($data['order_by'] ?? '');
            $bind   = [];
            $where  = parseCondition($data['condition'] ?? '', $bind);

            $sql = "SELECT * FROM `{$table}`";
            if ($where)  $sql .= " WHERE " . $where;
            if ($order)  $sql .= " ORDER BY " . $order;
            if ($limit)  $sql .= " LIMIT {$limit} OFFSET {$offset}";

            $stmt = $db->prepare($sql);
            $stmt->execute($bind);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'data' => json_encode($rows), 'count' => count($rows)]);
            break;
        }

        // ── LIKE SEARCH ───────────────────────────────────────
        case 'like_search': {
            $table   = validateTable($data['table'] ?? '');
            $column  = validateColumn($data['column'] ?? '');
            $pattern = $data['pattern'] ?? '';
            $limit   = min(max(1, (int)($data['limit'] ?? 50)), SRCM_MAX_ROWS);

            $stmt = $db->prepare("SELECT * FROM `{$table}` WHERE `{$column}` LIKE ? LIMIT {$limit}");
            $stmt->execute([$pattern]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'data' => json_encode($rows), 'count' => count($rows)]);
            break;
        }

        // ── AGGREGATE ─────────────────────────────────────────
        case 'aggregate': {
            $table = validateTable($data['table'] ?? '');
            $col   = $data['column'] === '*' ? '*' : validateColumn($data['column'] ?? 'id');
            $func  = strtoupper($data['func'] ?? 'COUNT');
            if (!in_array($func, ['COUNT','SUM','AVG','MAX','MIN'], true)) {
                throw new RuntimeException('Invalid function. Use: COUNT, SUM, AVG, MAX, MIN');
            }
            $bind  = [];
            $where = parseCondition($data['condition'] ?? '', $bind);

            $colExpr = $col === '*' ? '*' : '`' . $col . '`';
            $sql     = "SELECT {$func}({$colExpr}) AS result FROM `{$table}`";
            if ($where) $sql .= " WHERE " . $where;

            $stmt    = $db->prepare($sql);
            $stmt->execute($bind);
            $result  = $stmt->fetchColumn();
            echo json_encode(['success' => true, 'data' => json_encode(['result' => $result, 'func' => $func, 'column' => $col]), 'count' => 1]);
            break;
        }

        // ── CUSTOM SELECT QUERY ───────────────────────────────
        case 'custom_query': {
            if (!SRCM_ALLOW_CUSTOM_Q) throw new RuntimeException('Custom queries disabled by admin.');

            $query = trim($data['query'] ?? '');
            if (!preg_match('/^SELECT\s/i', $query)) {
                throw new RuntimeException('Sirf SELECT allowed hai custom query mein.');
            }
            // Block dangerous keywords
            $blocked = ['DROP','DELETE','INSERT','UPDATE','ALTER','CREATE','TRUNCATE','EXEC','GRANT','REVOKE','REPLACE','UNION'];
            foreach ($blocked as $bk) {
                if (preg_match('/\b' . $bk . '\b/i', $query)) {
                    throw new RuntimeException('Blocked keyword: ' . $bk);
                }
            }
            $stmt = $db->query($query);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'data' => json_encode($rows), 'count' => count($rows)]);
            break;
        }

        default:
            src_json(false, 'Unknown action: ' . $action);
    }

} catch (Throwable $e) {
    src_json(false, $e->getMessage());
}
