<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/../../config/jwt.php';

$authHeader = null;
if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
} elseif (!empty($_SERVER['Authorization'])) {
    $authHeader = $_SERVER['Authorization'];
} elseif (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
    $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
} elseif (!empty($_SERVER['HTTP_X_AUTHORIZATION'])) {
    $authHeader = $_SERVER['HTTP_X_AUTHORIZATION'];
} elseif (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) {
    $authHeader = $_SERVER['HTTP_X_AUTH_TOKEN'];
} elseif (!empty($_POST['token'])) {
    $authHeader = trim($_POST['token']);
} elseif (!empty($_GET['token'])) {
    $authHeader = trim($_GET['token']);
}

if ($authHeader) {
    if (stripos($authHeader, 'Bearer ') === 0) {
        $authHeader = trim(substr($authHeader, 7));
    } else {
        $authHeader = trim($authHeader);
    }
}

$userId = false;
$secret = getenv('JWT_SECRET') ?: '';
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server configuration error'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (!empty($authHeader)) {
    $payload = jwt_validate($authHeader, $secret);
    if ($payload && !empty($payload['sub'])) {
        $userId = (int)$payload['sub'];
    } else {
        $stmt = $pdo->prepare('SELECT id FROM usuarios WHERE token = ? LIMIT 1');
        $stmt->execute([$authHeader]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row && !empty($row['id'])) {
            $userId = (int)$row['id'];
        }
    }
}

if (!$userId || $userId <= 0) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'No autorizado'], JSON_UNESCAPED_UNICODE);
    exit;
}

$nombre = trim((string)($_POST['nombre'] ?? ''));
$apellido = trim((string)($_POST['apellido'] ?? ''));
$telefono = trim((string)($_POST['telefono'] ?? ''));
$email = trim((string)($_POST['email'] ?? ''));
$direccion = trim((string)($_POST['direccion'] ?? ''));
$notas = trim((string)($_POST['notas'] ?? ''));

if ($nombre === '' || $telefono === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Nombre y teléfono son obligatorios'], JSON_UNESCAPED_UNICODE);
    exit;
}
if (mb_strlen($nombre) > 100 || mb_strlen($apellido) > 100 || mb_strlen($telefono) > 20 || mb_strlen($email) > 120 || mb_strlen($direccion) > 255) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Campos demasiado largos'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Email inválido'], JSON_UNESCAPED_UNICODE);
    exit;
}

$fotoFilename = null;
if (!empty($_FILES['foto']) && isset($_FILES['foto']['error']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK) {
    $tmp = $_FILES['foto']['tmp_name'];
    $origName = $_FILES['foto']['name'] ?? '';
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
    $allowedExt = ['jpg','jpeg','png','webp','gif'];
    if (!in_array($ext, $allowedExt, true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Formato de imagen no permitido'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = $finfo ? finfo_file($finfo, $tmp) : ($_FILES['foto']['type'] ?? '');
    if ($finfo) finfo_close($finfo);
    $allowedMime = ['image/jpeg','image/png','image/webp','image/gif'];
    if ($mime && !in_array($mime, $allowedMime, true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Tipo de archivo no permitido'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($_FILES['foto']['size'] > 2 * 1024 * 1024) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Imagen demasiado grande (máx 2MB)'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $destDir = realpath(__DIR__ . '/../../uploads/contactos') ?: (__DIR__ . '/../../uploads/contactos');
    if (!is_dir($destDir)) {
        if (!mkdir($destDir, 0755, true)) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    try {
        $fotoFilename = 'c_' . bin2hex(random_bytes(8)) . '.' . $ext;
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $dest = $destDir . '/' . basename($fotoFilename);
    if (!move_uploaded_file($tmp, $dest)) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $realDest = realpath($dest);
    $realDestDir = realpath($destDir);
    if ($realDest === false || $realDestDir === false || strpos($realDest, $realDestDir) !== 0) {
        @unlink($dest);
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    @chmod($realDest, 0640);
}

try {
    $pdo->beginTransaction();
    $stmt = $pdo->prepare('INSERT INTO contactos (usuario_id, nombre, apellido, telefono, email, direccion, notas, foto) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([
        $userId,
        $nombre,
        $apellido !== '' ? $apellido : null,
        $telefono,
        $email !== '' ? $email : null,
        $direccion !== '' ? $direccion : null,
        $notas !== '' ? $notas : null,
        $fotoFilename !== null ? $fotoFilename : null
    ]);
    $contactId = (int)$pdo->lastInsertId();
    $pdo->commit();

    $fotoUrl = null;
    if ($fotoFilename !== null) {
        $base = rtrim(getenv('BASE_URL') ?: '', '/');
        $fotoUrl = $base . '/backend/uploads/contactos/' . rawurlencode(basename($fotoFilename));
    }

    echo json_encode(['success' => true, 'data' => ['id' => $contactId, 'nombre' => $nombre, 'foto' => $fotoUrl]], JSON_UNESCAPED_UNICODE);
    exit;
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        try { $pdo->rollBack(); } catch (Throwable $_) {}
    }
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno al crear contacto'], JSON_UNESCAPED_UNICODE);
    exit;
}