<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/../../config/jwt.php';

$headers = function_exists('getallheaders') ? getallheaders() : [];
$auth = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_X_AUTHORIZATION'] ?? $_SERVER['HTTP_X_AUTH_TOKEN'] ?? '';
if (empty($auth) && !empty($_COOKIE['agenda_token'])) {
    $auth = 'Bearer ' . trim($_COOKIE['agenda_token']);
}
if (empty($auth) && !empty($_GET['token'])) {
    $auth = 'Bearer ' . trim($_GET['token']);
}
if (empty($auth)) {
    $raw = file_get_contents('php://input');
    $json = json_decode($raw, true);
    if (is_array($json) && !empty($json['token'])) {
        $auth = 'Bearer ' . trim($json['token']);
    }
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

$envBase = rtrim(getenv('BASE_URL') ?: '', '/');
$scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$basePath = rtrim(dirname(dirname(dirname($_SERVER['SCRIPT_NAME']))), '/\\');
$uploadsPublicBase = $envBase !== '' ? rtrim($envBase, '/') . '/backend/uploads' : rtrim($scheme . '://' . $host . $basePath, '/') . '/uploads';
$uploadsRoot = realpath(__DIR__ . '/../../uploads') ?: (__DIR__ . '/../../uploads');
$uploadsContactosRoot = realpath(__DIR__ . '/../../uploads/contactos') ?: ($uploadsRoot . '/contactos');

$page = max(1, intval($_GET['page'] ?? 1));
$limit = intval($_GET['limit'] ?? 10);
$limit = max(1, min(100, $limit));
$offset = ($page - 1) * $limit;
$q = trim((string)($_GET['q'] ?? ''));

try {
    if ($q !== '') {
        $like = '%' . $q . '%';
        $stmt = $pdo->prepare('SELECT COUNT(*) as total FROM contactos WHERE usuario_id = ? AND (nombre LIKE ? OR apellido LIKE ?)');
        $stmt->execute([$usuario_id, $like, $like]);
        $total = intval($stmt->fetchColumn());
        $sql = 'SELECT id, usuario_id, nombre, apellido, telefono, email, direccion, notas, foto, fecha_creacion FROM contactos WHERE usuario_id = ? AND (nombre LIKE ? OR apellido LIKE ?) ORDER BY fecha_creacion DESC LIMIT ? OFFSET ?';
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(1, $usuario_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $like, PDO::PARAM_STR);
        $stmt->bindValue(3, $like, PDO::PARAM_STR);
        $stmt->bindValue(4, $limit, PDO::PARAM_INT);
        $stmt->bindValue(5, $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $stmt = $pdo->prepare('SELECT COUNT(*) as total FROM contactos WHERE usuario_id = ?');
        $stmt->execute([$usuario_id]);
        $total = intval($stmt->fetchColumn());
        $stmt = $pdo->prepare('SELECT id, usuario_id, nombre, apellido, telefono, email, direccion, notas, foto, fecha_creacion FROM contactos WHERE usuario_id = ? ORDER BY fecha_creacion DESC LIMIT ? OFFSET ?');
        $stmt->bindValue(1, $usuario_id, PDO::PARAM_INT);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->bindValue(3, $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    $result = [];
    $uploadsRootReal = realpath($uploadsRoot) ?: $uploadsRoot;
    $uploadsContactosReal = realpath($uploadsContactosRoot) ?: $uploadsContactosRoot;

    foreach ($rows as $r) {
        $foto = trim((string)($r['foto'] ?? ''));
        if ($foto === '') {
            $r['foto'] = null;
        } elseif (preg_match('#^https?://#i', $foto)) {
            $r['foto'] = $foto;
        } else {
            $safeBase = basename($foto);
            $name = rawurlencode($safeBase);
            $candidate = $uploadsContactosReal . '/' . $safeBase;
            $candidate2 = $uploadsRootReal . '/' . $safeBase;
            $resolved = null;
            if (is_file($candidate)) {
                $resolved = rtrim($uploadsPublicBase, '/') . '/contactos/' . $name;
            } elseif (is_file($candidate2)) {
                $resolved = rtrim($uploadsPublicBase, '/') . '/' . $name;
            }
            $r['foto'] = $resolved;
        }

        $id = intval($r['id']);
        $baseApi = rtrim($scheme . '://' . $host . $basePath, '/');
        $r['urls'] = [
            'read' => $baseApi . '/api/contactos/leer.php?id=' . $id,
            'update' => $baseApi . '/api/contactos/actualizar.php?id=' . $id,
            'delete' => $baseApi . '/api/contactos/eliminar.php?id=' . $id
        ];
        $r['permissions'] = ['can_read' => true, 'can_update' => true, 'can_delete' => true];
        $result[] = $r;
    }

    echo json_encode(['success' => true, 'data' => ['total' => $total, 'page' => $page, 'limit' => $limit, 'contacts' => $result]]);
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
    exit;
}