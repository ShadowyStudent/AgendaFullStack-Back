<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$dbPath = __DIR__ . '/../../config/db.php';
$jwtPath = __DIR__ . '/../../config/jwt.php';
if (!file_exists($dbPath) || !file_exists($jwtPath)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Configuración no encontrada']);
    exit;
}
require_once $dbPath;
require_once $jwtPath;

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

$env = [];
$envFile = __DIR__ . '/../../.env';
if (file_exists($envFile)) $env = parse_ini_file($envFile) ?: [];
$secret = $env['JWT_SECRET'] ?? getenv('JWT_SECRET') ?? '';
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server configuration error']);
    exit;
}

$payload = jwt_validate($token, $secret);
if (!$payload) {
    try {
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
    } catch (Throwable $e) {
        error_log(date('c') . " eliminar.php token fallback error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
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
            $real = realpath($candidate);
            if ($real !== false && strpos($real, $uploadsRootReal) === 0) $toDelete = $real;
        } elseif (is_file($candidate2)) {
            $real = realpath($candidate2);
            if ($real !== false && strpos($real, $uploadsRootReal) === 0) $toDelete = $real;
        }

        if ($toDelete !== null) {
            try {
                unlink($toDelete);
            } catch (Throwable $e) {
                error_log(date('c') . " eliminar.php unlink error: " . $e->getMessage());
            }
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
    error_log(date('c') . " eliminar.php error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
    exit;
}