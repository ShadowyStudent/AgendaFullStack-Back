<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
require_once __DIR__ . '/_cors.php';
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/db.php';

function log_error($text, $raw = '') {
    $dir = __DIR__ . '/../../logs';
    if (!is_dir($dir)) {
        mkdir($dir, 0770, true);
    }
    $safeRaw = $raw;
    if (is_string($safeRaw)) {
        $safeRaw = preg_replace('/("password"\s*:\s*)"([^"]*)"/i', '$1"[FILTERED]"', $safeRaw);
        $safeRaw = preg_replace('/("password"\s*:\s*)([^,\}\]]+)/i', '$1"[FILTERED]"', $safeRaw);
        $safeRaw = substr($safeRaw, 0, 1000);
    } else {
        $safeRaw = '';
    }
    $entry = date('c') . " " . $text . ($safeRaw !== '' ? " RAW:" . $safeRaw : "") . PHP_EOL;
    file_put_contents($dir . '/error.log', $entry, FILE_APPEND);
}

try {
    if (!isset($pdo)) {
        throw new Exception('No se pudo inicializar la conexión PDO');
    }

    $raw = file_get_contents('php://input');
    $input = json_decode($raw, true);
    if (!$input || !is_array($input)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'JSON inválido'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $nombre_de_usuario = trim((string)($input['nombre_de_usuario'] ?? ''));
    $password = (string)($input['password'] ?? '');

    if ($nombre_de_usuario === '' || $password === '') {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing fields'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (strlen($password) < 6) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Password too short'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (!preg_match('/^[A-Za-z0-9_\-]{3,50}$/', $nombre_de_usuario)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid username format'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $pdo->beginTransaction();

    $stmt = $pdo->prepare('SELECT COUNT(*) AS cnt FROM usuarios WHERE nombre_de_usuario = ?');
    $stmt->execute([$nombre_de_usuario]);
    $row = $stmt->fetch();
    if ($row && (int)$row['cnt'] > 0) {
        $pdo->rollBack();
        http_response_code(409);
        echo json_encode(['success' => false, 'message' => 'Username exists'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('INSERT INTO usuarios (nombre_de_usuario, password) VALUES (?,?)');
    $stmt->execute([$nombre_de_usuario, $hash]);
    $id = $pdo->lastInsertId();

    $pdo->commit();

    echo json_encode(['success' => true, 'data' => ['id' => $id, 'nombre_de_usuario' => $nombre_de_usuario]], JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        try { $pdo->rollBack(); } catch (Throwable $_) {}
    }
    http_response_code(500);
    log_error('Registrar error: ' . $e->getMessage(), $raw ?? '');
    echo json_encode(['success' => false, 'message' => 'Internal server error'], JSON_UNESCAPED_UNICODE);
    exit;
}