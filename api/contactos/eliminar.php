<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/../../config/jwt.php';

$headers = function_exists('getallheaders') ? getallheaders() : [];
$auth = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (empty($auth) && !empty($_COOKIE['agenda_token'])) {
    $auth = 'Bearer ' . trim($_COOKIE['agenda_token']);
}
if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $m)) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Token missing']);
    exit;
}
$token = $m[1];

$secret = getenv('JWT_SECRET') ?: '';
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server configuration error']);
    exit;
}

$payload = jwt_validate($token, $secret);
if (!$payload) {
    $stmt = $pdo->prepare('SELECT id FROM usuarios WHERE token = ? LIMIT 1');
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && !empty($user['id'])) {
        $payload = ['sub' => $user['id']];
    } else {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Invalid token']);
        exit;
    }
}

$usuario_id = isset($payload['sub']) ? (int)$payload['sub'] : 0;
if ($usuario_id <= 0) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Invalid token payload']);
    exit;
}

$input = $_POST;
if (empty($input['id'])) {
    $raw = file_get_contents('php://input');
    $json = json_decode($raw, true);
    if (is_array($json) && !empty($json['id'])) $input['id'] = $json['id'];
}
$id = intval($input['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'ID inválido']);
    exit;
}

try {
    $stmt = $pdo->prepare('SELECT foto FROM contactos WHERE id = ? AND usuario_id = ? LIMIT 1');
    $stmt->execute([$id, $usuario_id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Contacto no encontrado']);
        exit;
    }

    $foto = trim($row['foto'] ?? '');
    if ($foto !== '') {
        $uploadsRoot = realpath(__DIR__ . '/../../uploads') ?: (__DIR__ . '/../../uploads');
        $uploadsRootReal = realpath($uploadsRoot) ?: $uploadsRoot;
        $candidate = $uploadsRootReal . '/contactos/' . basename($foto);
        $candidate2 = $uploadsRootReal . '/' . basename($foto);

        $toDelete = null;
        if (is_file($candidate)) {
            $toDelete = realpath($candidate);
        } elseif (is_file($candidate2)) {
            $toDelete = realpath($candidate2);
        }

        if ($toDelete !== false && $toDelete !== null && strpos($toDelete, $uploadsRootReal) === 0) {
            unlink($toDelete);
        }
    }

    $stmt = $pdo->prepare('DELETE FROM contactos WHERE id = ? AND usuario_id = ?');
    $stmt->execute([$id, $usuario_id]);
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Contacto no encontrado o no autorizado']);
        exit;
    }

    echo json_encode(['success' => true]);
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
    exit;
}