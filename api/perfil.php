<?php
require_once __DIR__ . '/_cors.php';
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../config/jwt.php';

$headers = function_exists('getallheaders') ? getallheaders() : [];
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/Bearer\s(\S+)/', (string)$authHeader, $m)) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Token missing']);
    exit;
}
$token = $m[1];

$env = parse_ini_file(__DIR__ . '/../.env') ?: [];
$secret = $env['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: '';
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server configuration error']);
    exit;
}

$payload = jwt_validate($token, $secret);
if (!$payload) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Invalid token']);
    exit;
}

$usuario_id = isset($payload['sub']) ? (int)$payload['sub'] : 0;
if ($usuario_id <= 0) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Invalid token payload']);
    exit;
}

$stmt = $pdo->prepare('SELECT id, nombre_de_usuario, nombre, email, avatar, foto, fecha_registro FROM usuarios WHERE id = ?');
$stmt->execute([$usuario_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$user) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'User not found']);
    exit;
}

$filename = $user['avatar'] ?: $user['foto'] ?: null;
$avatarUrl = null;
if ($filename) {
    $filename = basename($filename);
    $scheme = !empty($_SERVER['REQUEST_SCHEME']) ? $_SERVER['REQUEST_SCHEME'] : ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME'], 2), '/');
    $avatarUrl = $scheme . '://' . $host . $basePath . '/uploads/users/' . rawurlencode($filename);
}

echo json_encode(['success' => true, 'data' => [
    'id' => (int)($user['id'] ?? 0),
    'nombre_de_usuario' => $user['nombre_de_usuario'] ?? null,
    'nombre' => $user['nombre'] ?? $user['nombre_de_usuario'] ?? null,
    'email' => $user['email'] ?? null,
    'avatar' => $avatarUrl,
    'fecha_registro' => $user['fecha_registro'] ?? null
]], JSON_UNESCAPED_UNICODE);
exit;