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

$secret = getenv('JWT_SECRET') ?: '';
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

$stmt = $pdo->prepare('SELECT id, nombre_de_usuario, password, avatar FROM usuarios WHERE id = ?');
$stmt->execute([$usuario_id]);
$current = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$current) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'User not found']);
    exit;
}

$contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$data = [];
if (stripos($contentType, 'application/json') !== false) {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true) ?? [];
}

$nombre = $data['nombre'] ?? $data['nombre_de_usuario'] ?? $_POST['nombre'] ?? $_POST['nombre_de_usuario'] ?? null;
$email = $data['email'] ?? $_POST['email'] ?? null;
$password_actual = $data['password_actual'] ?? $_POST['password_actual'] ?? null;
$password_nueva = $data['password_nueva'] ?? $_POST['password_nueva'] ?? null;
$removeAvatar = $data['remove_avatar'] ?? $_POST['remove_avatar'] ?? null;

$uploadDir = __DIR__ . '/../uploads/users';
if (!is_dir($uploadDir)) mkdir($uploadDir, 0770, true);

if ($removeAvatar) {
    $old = $current['avatar'] ?? null;
    if ($old) {
        $oldPath = $uploadDir . '/' . basename($old);
        if (is_file($oldPath)) unlink($oldPath);
    }
    $stmt = $pdo->prepare('UPDATE usuarios SET avatar = NULL WHERE id = ?');
    $stmt->execute([$usuario_id]);
    echo json_encode(['success' => true, 'deleted' => true]);
    exit;
}

$fields = [];
$params = [];

if ($nombre !== null) {
    $newUsername = trim((string)$nombre);
    if ($newUsername !== '' && $newUsername !== $current['nombre_de_usuario']) {
        if (!preg_match('/^[A-Za-z0-9_\-]{3,50}$/', $newUsername)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid username format']);
            exit;
        }
        $check = $pdo->prepare('SELECT id FROM usuarios WHERE nombre_de_usuario = ? AND id != ?');
        $check->execute([$newUsername, $usuario_id]);
        if ($check->fetch()) {
            http_response_code(409);
            echo json_encode(['success' => false, 'message' => 'Nombre de usuario ya existe']);
            exit;
        }
        $fields[] = 'nombre_de_usuario = ?';
        $params[] = $newUsername;
    }
}

if ($email !== null) {
    $email = trim((string)$email);
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid email']);
        exit;
    }
    $fields[] = 'email = ?';
    $params[] = $email;
}

if ($password_nueva !== null && $password_nueva !== '') {
    if (!$password_actual || !password_verify((string)$password_actual, $current['password'])) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Contraseña actual incorrecta']);
        exit;
    }
    if (strlen((string)$password_nueva) < 6) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'New password too short']);
        exit;
    }
    $fields[] = 'password = ?';
    $params[] = password_hash((string)$password_nueva, PASSWORD_DEFAULT);
}

if (!empty($_FILES['foto']) && isset($_FILES['foto']['error']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK) {
    $f = $_FILES['foto'];
    $tmp = $f['tmp_name'];
    $name = basename($f['name']);
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $allowedExt = ['jpg','jpeg','png','webp'];
    $allowedMime = ['image/jpeg','image/png','image/webp'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $tmp);
    finfo_close($finfo);
    if (in_array($ext, $allowedExt, true) && in_array($mime, $allowedMime, true) && $f['size'] <= 2 * 1024 * 1024) {
        try {
            $filename = bin2hex(random_bytes(16)) . '.' . $ext;
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Server error']);
            exit;
        }
        $dest = $uploadDir . '/' . $filename;
        if (move_uploaded_file($tmp, $dest)) {
            chmod($dest, 0640);
            $fields[] = 'avatar = ?';
            $params[] = $filename;
            $old = $current['avatar'] ?? null;
            if ($old) {
                $oldPath = $uploadDir . '/' . basename($old);
                if (is_file($oldPath)) unlink($oldPath);
            }
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error al mover archivo']);
            exit;
        }
    } else {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Archivo no permitido o demasiado grande']);
        exit;
    }
}

if (empty($fields)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No fields to update']);
    exit;
}

$params[] = $usuario_id;
$sql = 'UPDATE usuarios SET ' . implode(', ', $fields) . ' WHERE id = ?';
try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);
    exit;
}

echo json_encode(['success' => true]);
exit;