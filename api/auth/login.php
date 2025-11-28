<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../../config/db.php';

function safe_log($text, $context = '') {
    $dir = __DIR__ . '/../../logs';
    if (!is_dir($dir)) mkdir($dir, 0770, true);
    $safeContext = is_string($context) ? preg_replace('/("password"\s*:\s*)"([^"]*)"/i', '$1"[FILTERED]"', $context) : '';
    $entry = date('c') . ' ' . $text . ($safeContext !== '' ? ' | ' . substr($safeContext, 0, 1000) : '') . PHP_EOL;
    file_put_contents($dir . '/error.log', $entry, FILE_APPEND);
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function jwt_sign(array $payload, string $secret, int $expiresIn = 3600) {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $now = time();
    $payload['iat'] = $now;
    $payload['exp'] = $now + $expiresIn;

    $headJson = json_encode($header);
    $bodyJson = json_encode($payload);
    if ($headJson === false || $bodyJson === false) {
        throw new RuntimeException('JSON encoding failed for JWT');
    }

    $headb64 = base64url_encode($headJson);
    $bodyb64 = base64url_encode($bodyJson);
    $sig = hash_hmac('sha256', $headb64 . '.' . $bodyb64, $secret, true);
    $sigb64 = rtrim(strtr(base64_encode($sig), '+/', '-_'), '=');
    return $headb64 . '.' . $bodyb64 . '.' . $sigb64;
}

try {
    if (!isset($pdo)) throw new Exception('No se pudo inicializar la conexión PDO');

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
        echo json_encode(['success' => false, 'message' => 'Usuario y contraseña son obligatorios'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (mb_strlen($nombre_de_usuario) > 100 || mb_strlen($password) > 256) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Campos demasiado largos'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $stmt = $pdo->prepare('SELECT id, nombre_de_usuario, password FROM usuarios WHERE nombre_de_usuario = ? LIMIT 1');
    $stmt->execute([$nombre_de_usuario]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !isset($user['password']) || !password_verify($password, $user['password'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Credenciales inválidas'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $envFile = __DIR__ . '/../../.env';
    $env = [];
    if (file_exists($envFile)) $env = parse_ini_file($envFile) ?: [];
    $secret = $env['JWT_SECRET'] ?? getenv('JWT_SECRET') ?? '';
    if ($secret === '') {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Server misconfiguration'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $token = jwt_sign(['sub' => (int)$user['id']], $secret, 3600);

    $upd = $pdo->prepare('UPDATE usuarios SET token = ? WHERE id = ?');
    $upd->execute([$token, $user['id']]);

    echo json_encode([
        'success' => true,
        'data' => [
            'id' => (int)$user['id'],
            'nombre_de_usuario' => $user['nombre_de_usuario'],
            'token' => $token
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    safe_log('login error', json_encode(['error' => $e->getMessage(), 'input' => substr($raw ?? '', 0, 1000)]));
    echo json_encode(['success' => false, 'message' => 'Error interno'], JSON_UNESCAPED_UNICODE);
    exit;
}