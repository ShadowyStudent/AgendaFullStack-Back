<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/_cors.php';
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/db.php';

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
    echo json_encode(['success' => false, 'message' => 'Internal server error'], JSON_UNESCAPED_UNICODE);
    exit;
}