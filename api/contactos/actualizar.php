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
if (!$auth || !preg_match('/Bearer\s(\S+)/', (string)$auth, $m)) {
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
$id = intval($input['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'ID inválido']);
    exit;
}

$nombre    = trim((string)($input['nombre'] ?? ''));
$apellido  = trim((string)($input['apellido'] ?? ''));
$telefono  = trim((string)($input['telefono'] ?? ''));
$email     = trim((string)($input['email'] ?? ''));
$direccion = trim((string)($input['direccion'] ?? ''));
$notas     = trim((string)($input['notas'] ?? ''));

if ($nombre === '' || $telefono === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Nombre y teléfono son obligatorios']);
    exit;
}

$contactosDir = __DIR__ . '/../../uploads/contactos';
if (!is_dir($contactosDir)) {
    mkdir($contactosDir, 0755, true);
}
$contactosDirReal = realpath($contactosDir);

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare('SELECT foto FROM contactos WHERE id = ? AND usuario_id = ? LIMIT 1');
    $stmt->execute([$id, $usuario_id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        $pdo->rollBack();
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Contacto no encontrado']);
        exit;
    }

    $newFotoName = null;
    if (!empty($_FILES['foto']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK && is_uploaded_file($_FILES['foto']['tmp_name'])) {
        if ($_FILES['foto']['size'] > 2 * 1024 * 1024) {
            $pdo->rollBack();
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Imagen demasiado grande (máx 2MB)']);
            exit;
        }

        $ext = strtolower(pathinfo($_FILES['foto']['name'], PATHINFO_EXTENSION));
        $allowedExt = ['jpg','jpeg','png','webp','gif'];
        if (!in_array($ext, $allowedExt, true)) {
            $pdo->rollBack();
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Formato de imagen no permitido']);
            exit;
        }

        $newFotoName = 'c_' . bin2hex(random_bytes(8)) . '.' . $ext;
        $dest = $contactosDirReal . '/' . $newFotoName;

        if (!move_uploaded_file($_FILES['foto']['tmp_name'], $dest)) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen']);
            exit;
        }

        @chmod($dest, 0644);

        if (!empty($row['foto'])) {
            $oldPath = $contactosDirReal . '/' . basename($row['foto']);
            if (is_file($oldPath)) {
                unlink($oldPath);
            }
        }
    }

    $sql = 'UPDATE contactos SET nombre = ?, apellido = ?, telefono = ?, email = ?, direccion = ?, notas = ?';
    $params = [$nombre, $apellido ?: null, $telefono ?: null, $email ?: null, $direccion ?: null, $notas ?: null];
    if ($newFotoName !== null) {
        $sql .= ', foto = ?';
        $params[] = $newFotoName;
    }
    $sql .= ' WHERE id = ? AND usuario_id = ?';
    $params[] = $id;
    $params[] = $usuario_id;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $pdo->commit();

    echo json_encode([
        'success' => true,
        'data' => [
            'id' => $id,
            'nombre' => $nombre,
            'apellido' => $apellido,
            'telefono' => $telefono,
            'email' => $email,
            'direccion' => $direccion,
            'notas' => $notas,
            'foto' => $newFotoName !== null ? $newFotoName : $row['foto']
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor'], JSON_UNESCAPED_UNICODE);
    exit;
}